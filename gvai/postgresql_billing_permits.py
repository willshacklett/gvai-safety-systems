"""Offline permit verification and pure lifecycle decisions; no executor or signer."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


DOMAIN = b"gvai-disposable-postgresql-permit-v1\x00"
MAX_PERMIT_BYTES = 16384


class PermitDenied(RuntimeError):
    """Fixed diagnostic codes only; never include input or underlying exceptions."""


class ConsumptionUnavailable(RuntimeError):
    """Storage outage or ambiguous durable commit; never clean replay rejection."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise PermitDenied(code)


def _identifier(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", value) is not None


def _hex(value: object, size: int) -> bool:
    return type(value) is str and re.fullmatch("[0-9a-f]{%d}" % size, value) is not None


class Lifecycle(str, Enum):
    APPROVED = "APPROVED"
    CREATED = "CREATED"
    INITIALIZED = "INITIALIZED"
    STARTED = "STARTED"
    ATTESTED = "ATTESTED"
    MIGRATED = "MIGRATED"
    TESTED = "TESTED"
    STOPPED = "STOPPED"
    CLEANED = "CLEANED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    CLEANUP_INCOMPLETE = "CLEANUP_INCOMPLETE"


class PermitOperation(str, Enum):
    CREATE = "create"
    INITIALIZE = "initialize"
    START = "start"
    ATTEST = "attest"
    MIGRATE = "migrate"
    TEST = "test"
    STOP = "stop"
    CLEANUP = "cleanup"


class Outcome(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"
    CLEANUP_INCOMPLETE = "cleanup_incomplete"


def transition(state: Lifecycle, operation: PermitOperation) -> Lifecycle:
    _require(type(state) is Lifecycle and type(operation) is PermitOperation, "invalid_transition")
    forward = {
        (Lifecycle.APPROVED, PermitOperation.CREATE): Lifecycle.CREATED,
        (Lifecycle.CREATED, PermitOperation.INITIALIZE): Lifecycle.INITIALIZED,
        (Lifecycle.INITIALIZED, PermitOperation.START): Lifecycle.STARTED,
        (Lifecycle.STARTED, PermitOperation.ATTEST): Lifecycle.ATTESTED,
        (Lifecycle.ATTESTED, PermitOperation.MIGRATE): Lifecycle.MIGRATED,
        (Lifecycle.MIGRATED, PermitOperation.TEST): Lifecycle.TESTED,
        (Lifecycle.STOPPED, PermitOperation.CLEANUP): Lifecycle.CLEANED,
        (Lifecycle.CLEANUP_INCOMPLETE, PermitOperation.CLEANUP): Lifecycle.CLEANED,
    }
    if operation is PermitOperation.STOP and state in {
        Lifecycle.CREATED, Lifecycle.INITIALIZED, Lifecycle.STARTED, Lifecycle.ATTESTED,
        Lifecycle.MIGRATED, Lifecycle.TESTED, Lifecycle.FAILED, Lifecycle.UNKNOWN,
    }:
        return Lifecycle.STOPPED
    target = forward.get((state, operation))
    _require(target is not None, "invalid_transition")
    return target


def _artifacts(value: object) -> None:
    _require(type(value) is tuple and 1 <= len(value) <= 32, "invalid_artifacts")
    for pair in value:
        _require(
            type(pair) is tuple and len(pair) == 2
            and _identifier(pair[0]) and _hex(pair[1], 64),
            "invalid_artifacts",
        )
    names = tuple(pair[0] for pair in value)
    _require(names == tuple(sorted(set(names))), "invalid_artifacts")


@dataclass(frozen=True, repr=False)
class Permit:
    version: int
    run_id: str
    nonce: str
    operation_id: str
    issuer: str
    audience: str
    key_id: str
    issued_at: int
    expires_at: int
    operation: PermitOperation
    predecessor: Lifecycle
    generation: int
    identity_digest: str
    artifacts: tuple[tuple[str, str], ...]

    def validate(self) -> None:
        _require(type(self.version) is int and self.version == 1, "invalid_version")
        _require(
            _hex(self.run_id, 32) and self.run_id != "0" * 32
            and _hex(self.nonce, 64) and self.nonce != "0" * 64
            and _hex(self.operation_id, 32) and self.operation_id != "0" * 32,
            "invalid_identity",
        )
        _require(
            _identifier(self.issuer) and _identifier(self.audience) and _identifier(self.key_id),
            "invalid_trust_context",
        )
        _require(
            type(self.issued_at) is int and type(self.expires_at) is int
            and 0 <= self.issued_at < self.expires_at <= 2**63 - 1
            and self.expires_at - self.issued_at <= 300,
            "invalid_validity",
        )
        _require(type(self.generation) is int and 0 <= self.generation < 2**63, "invalid_generation")
        _require(_hex(self.identity_digest, 64), "invalid_identity_digest")
        _artifacts(self.artifacts)
        transition(self.predecessor, self.operation)

    def payload(self) -> dict:
        self.validate()
        return {
            "version": self.version, "run_id": self.run_id, "nonce": self.nonce,
            "operation_id": self.operation_id, "issuer": self.issuer,
            "audience": self.audience, "key_id": self.key_id,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "operation": self.operation.value, "predecessor": self.predecessor.value,
            "generation": self.generation, "identity_digest": self.identity_digest,
            "artifacts": dict(self.artifacts),
        }

    def canonical_bytes(self) -> bytes:
        return DOMAIN + _json(self.payload())


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate_json_field")
        result[key] = value
    return result


@dataclass(frozen=True, repr=False)
class SignedPermit:
    permit: Permit
    signature: bytes

    def wire_bytes(self) -> bytes:
        _require(type(self.permit) is Permit, "invalid_permit")
        _require(type(self.signature) is bytes and len(self.signature) == 64, "invalid_signature")
        wire = _json({"permit": self.permit.payload(), "signature": self.signature.hex()})
        _require(len(wire) <= MAX_PERMIT_BYTES, "invalid_wire_size")
        return wire


def parse_permit(wire: bytes) -> SignedPermit:
    _require(type(wire) is bytes and 0 < len(wire) <= MAX_PERMIT_BYTES, "invalid_wire_size")
    try:
        envelope = json.loads(wire.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, RecursionError):
        raise PermitDenied("invalid_json") from None
    _require(
        type(envelope) is dict and set(envelope) == {"permit", "signature"},
        "invalid_envelope",
    )
    body = envelope["permit"]
    _require(type(body) is dict and set(body) == set(Permit.__dataclass_fields__), "invalid_fields")
    _require(type(body["artifacts"]) is dict, "invalid_artifacts")
    _require(_hex(envelope["signature"], 128), "invalid_signature")
    try:
        operation = PermitOperation(body["operation"])
        predecessor = Lifecycle(body["predecessor"])
    except (ValueError, TypeError):
        raise PermitDenied("invalid_transition") from None
    values = dict(body)
    values["operation"] = operation
    values["predecessor"] = predecessor
    values["artifacts"] = tuple(sorted(body["artifacts"].items()))
    signed = SignedPermit(Permit(**values), bytes.fromhex(envelope["signature"]))
    _require(signed.wire_bytes() == wire, "noncanonical_wire")
    return signed


@dataclass(frozen=True, repr=False)
class ExpectedPermit:
    """Independently supplied expectation, not derived from untrusted permit fields."""

    run_id: str
    nonce: str
    issuer: str
    audience: str
    operation: PermitOperation
    predecessor: Lifecycle
    generation: int
    identity_digest: str
    artifacts: tuple[tuple[str, str], ...]

    def matches(self, permit: Permit) -> bool:
        return all(
            type(getattr(self, name)) is type(getattr(permit, name))
            and getattr(self, name) == getattr(permit, name)
            for name in self.__dataclass_fields__
        )


class PermitVerifier:
    """Verification only; issuer/key-ID pins are independent of the envelope."""

    __slots__ = ("_keys",)

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Permit trust configuration is immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Permit trust configuration is immutable.")

    def __init__(self, trusted_public_keys: Mapping[tuple[str, str], bytes]) -> None:
        _require(isinstance(trusted_public_keys, Mapping) and bool(trusted_public_keys), "trusted_keys_required")
        keys = {}
        for context, raw in trusted_public_keys.items():
            _require(
                type(context) is tuple and len(context) == 2
                and all(_identifier(part) for part in context)
                and type(raw) is bytes and len(raw) == 32,
                "invalid_trusted_key",
            )
            keys[context] = Ed25519PublicKey.from_public_bytes(raw)
        self._keys = MappingProxyType(keys)

    def verify(self, wire: bytes, expected: ExpectedPermit, *, now: int) -> Permit:
        _require(type(expected) is ExpectedPermit, "independent_expectation_required")
        _require(type(now) is int and 0 <= now < 2**63, "invalid_clock")
        signed = parse_permit(wire)
        permit = signed.permit
        _require(expected.matches(permit), "permit_context_mismatch")
        _require(permit.issued_at <= now < permit.expires_at, "permit_not_current")
        key = self._keys.get((permit.issuer, permit.key_id))
        _require(key is not None, "untrusted_signing_key")
        try:
            key.verify(signed.signature, permit.canonical_bytes())
        except InvalidSignature:
            raise PermitDenied("signature_rejected") from None
        return permit


@dataclass(frozen=True)
class LifecycleRecord:
    run_id: str
    state: Lifecycle
    generation: int
    identity_digest: str

    def validate(self) -> None:
        _require(_hex(self.run_id, 32) and self.run_id != "0" * 32, "invalid_record")
        _require(type(self.state) is Lifecycle, "invalid_record")
        _require(type(self.generation) is int and 0 <= self.generation < 2**63 - 1, "invalid_record")
        _require(_hex(self.identity_digest, 64), "invalid_record")


@dataclass(frozen=True)
class ConsumptionIntent:
    issuer: str
    operation_id: str
    permit_digest: str
    expected: LifecycleRecord
    operation: PermitOperation
    target: Lifecycle


class PermitConsumption(Protocol):
    """External authenticated durable CAS boundary, not implemented here.

    Atomically reject reused (issuer, operation_id), compare the complete current
    lifecycle record, and persist the pending intent before returning True.
    Concurrent intents for one record cannot both succeed. False means clean
    replay/CAS rejection only. Outages/unknown commits raise ConsumptionUnavailable.
    Pending intents must recover as UNKNOWN after interruption, never success.
    Completion must atomically finalize the intent and next record externally.
    A process-local fake is useful for tests but supplies no replay resistance.
    """

    def consume_once(self, intent: ConsumptionIntent) -> bool: ...


def authorize_intent(
    verifier: PermitVerifier, wire: bytes, expected: ExpectedPermit,
    record: LifecycleRecord, storage: PermitConsumption, *, now: int,
) -> ConsumptionIntent:
    _require(type(verifier) is PermitVerifier and type(record) is LifecycleRecord, "invalid_verification_context")
    record.validate()
    permit = verifier.verify(wire, expected, now=now)
    _require(
        (record.run_id, record.state, record.generation, record.identity_digest)
        == (permit.run_id, permit.predecessor, permit.generation, permit.identity_digest),
        "lifecycle_record_mismatch",
    )
    intent = ConsumptionIntent(
        permit.issuer, permit.operation_id, hashlib.sha256(wire).hexdigest(),
        record, permit.operation, transition(record.state, permit.operation),
    )
    try:
        consumed = storage.consume_once(intent)
    except ConsumptionUnavailable:
        raise PermitDenied("consumption_unavailable_or_ambiguous") from None
    _require(consumed is True, "consumption_rejected")
    return intent


def finish_intent(intent: ConsumptionIntent, outcome: Outcome) -> LifecycleRecord:
    """Pure candidate only: no durable completion, attestation, or operation proof."""
    _require(type(intent) is ConsumptionIntent and type(outcome) is Outcome, "invalid_completion")
    intent.expected.validate()
    _require(intent.expected.generation < 2**63 - 2, "generation_exhausted")
    _require(
        _identifier(intent.issuer) and _hex(intent.operation_id, 32)
        and _hex(intent.permit_digest, 64)
        and type(intent.target) is Lifecycle
        and intent.target is transition(intent.expected.state, intent.operation),
        "invalid_completion",
    )
    if outcome is Outcome.SUCCEEDED:
        state = intent.target
    elif outcome is Outcome.FAILED:
        state = Lifecycle.FAILED
    elif outcome is Outcome.UNKNOWN:
        state = Lifecycle.UNKNOWN
    else:
        _require(intent.target is Lifecycle.CLEANED, "invalid_cleanup_outcome")
        state = Lifecycle.CLEANUP_INCOMPLETE
    return LifecycleRecord(
        intent.expected.run_id, state, intent.expected.generation + 1,
        intent.expected.identity_digest,
    )
