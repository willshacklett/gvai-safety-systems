"""Experimental fail-closed STOP-latch verification; no signer, no reset, no wiring.

This module holds only Ed25519 *public* keys. Nothing here can create, sign,
clear or advance a latch record, and nothing in the production service imports
it. Enforcement here is an in-process check: a compromised commercial process
can skip it. See docs/stop_latch_verification_v1.md for the required external
supervisor/gateway boundary.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.commercial_service import (
    CommercialEvaluationService,
    CommercialServiceResponse,
    ServiceOutcome,
    ServiceReason,
)
from gvai.commercial_usage import UsageReason, UsageResult


LATCH_VERSION = 1
LATCH_PURPOSE = "stop_latch"
LATCH_ALGORITHM = "Ed25519"
LATCH_DOMAIN = b"gvai-stop-latch-record-v1\x00"
GENESIS_HASH = "0" * 64
MAX_SEQUENCE = 2**63 - 1
MAX_LEASE_SECONDS = 300
MAX_RECORD_BYTES = 4096
OPERATIONS = frozenset({"evaluate", "reserve"})

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_FIELDS = frozenset({
    "authority_epoch", "authority_id", "contract_version", "expires_at",
    "issued_at", "previous_hash", "purpose", "sequence", "signature",
    "signature_algorithm", "signing_key_id", "state", "trust_domain",
})


class LatchState(str, Enum):
    RUN = "run"
    STOPPED = "stopped"


class LatchReason(str, Enum):
    RUN_LEASE_VALID = "run_lease_valid"
    STOPPED = "stopped"
    MISSING = "missing"
    CORRUPT = "corrupt"
    UNTRUSTED_AUTHORITY = "untrusted_authority"
    UNTRUSTED_KEY = "untrusted_key"
    INVALID_SIGNATURE = "invalid_signature"
    ROLLED_BACK = "rolled_back"
    CONFLICT = "conflict"
    CHAIN_BREAK = "chain_break"
    SEQUENCE_GAP = "sequence_gap"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    CLOCK_ERROR = "clock_error"
    SOURCE_UNAVAILABLE = "source_unavailable"
    INVALID_OPERATION = "invalid_operation"
    INTERNAL_ERROR = "internal_error"


@dataclass(frozen=True)
class LatchDecision:
    reason: LatchReason

    @property
    def allowed(self) -> bool:
        return self.reason is LatchReason.RUN_LEASE_VALID

    def __bool__(self) -> bool:
        return self.allowed


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _int(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


@dataclass(frozen=True)
class StopLatchRecord:
    """One supervisor-signed, hash-chained latch statement."""

    authority: AuthorityIdentity
    sequence: int
    previous_hash: str
    state: LatchState
    issued_at: int
    expires_at: int
    signing_key_id: str
    signature: bytes
    version: int = LATCH_VERSION
    purpose: str = LATCH_PURPOSE
    signature_algorithm: str = LATCH_ALGORITHM

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("Invalid latch authority.")
        if not _int(self.sequence, 1, MAX_SEQUENCE):
            raise ValueError("Invalid latch sequence.")
        if type(self.previous_hash) is not str or _HASH.fullmatch(self.previous_hash) is None:
            raise ValueError("Invalid previous hash.")
        if type(self.state) is not LatchState:
            raise ValueError("Invalid latch state.")
        if not _int(self.issued_at, 0, MAX_SEQUENCE) or not _int(self.expires_at, 0, MAX_SEQUENCE):
            raise ValueError("Invalid latch times.")
        if not 0 < self.expires_at - self.issued_at <= MAX_LEASE_SECONDS:
            raise ValueError("Invalid latch lease interval.")
        if not _identifier(self.signing_key_id):
            raise ValueError("Invalid latch signing key ID.")
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise ValueError("Invalid latch signature.")
        if type(self.version) is not int or self.version != LATCH_VERSION:
            raise ValueError("Unsupported latch version.")
        if self.purpose != LATCH_PURPOSE or type(self.purpose) is not str:
            raise ValueError("Invalid latch purpose.")
        if self.signature_algorithm != LATCH_ALGORITHM or type(self.signature_algorithm) is not str:
            raise ValueError("Unsupported latch algorithm.")

    def _body(self) -> dict[str, object]:
        return {
            "authority_epoch": self.authority.epoch,
            "authority_id": self.authority.authority_id,
            "contract_version": self.version,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "previous_hash": self.previous_hash,
            "purpose": self.purpose,
            "sequence": self.sequence,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "state": self.state.value,
            "trust_domain": self.authority.trust_domain,
        }

    def canonical_bytes(self) -> bytes:
        return LATCH_DOMAIN + _dumps(self._body())

    def record_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_wire(self) -> bytes:
        return _dumps({**self._body(), "signature": self.signature.hex()})


def _dumps(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def decode_record(raw: object) -> StopLatchRecord:
    """Strict wire decoder: exact fields, no duplicates, no coercion."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_RECORD_BYTES:
        raise ValueError("Invalid latch record size.")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate field.")
            result[key] = value
        return result

    def reject(_value: str) -> None:
        raise ValueError("Non-finite number.")

    data = json.loads(
        raw.decode("ascii"), object_pairs_hook=unique, parse_constant=reject
    )
    if type(data) is not dict or set(data) != _FIELDS:
        raise ValueError("Invalid latch fields.")
    if type(data["signature"]) is not str or re.fullmatch(r"[0-9a-f]{128}", data["signature"]) is None:
        raise ValueError("Invalid signature encoding.")
    if type(data["state"]) is not str:
        raise ValueError("Invalid state.")
    record = StopLatchRecord(
        authority=AuthorityIdentity(
            data["authority_id"], data["authority_epoch"], data["trust_domain"]
        ),
        sequence=data["sequence"],
        previous_hash=data["previous_hash"],
        state=LatchState(data["state"]),
        issued_at=data["issued_at"],
        expires_at=data["expires_at"],
        signing_key_id=data["signing_key_id"],
        signature=bytes.fromhex(data["signature"]),
        version=data["contract_version"],
        purpose=data["purpose"],
        signature_algorithm=data["signature_algorithm"],
    )
    if record.to_wire() != raw:
        raise ValueError("Noncanonical latch record.")
    return record


@dataclass(frozen=True)
class LatchAnchor:
    """Independently provisioned lower bound; restart never goes below it."""

    sequence: int = 0
    record_hash: str = GENESIS_HASH

    def __post_init__(self) -> None:
        if not _int(self.sequence, 0, MAX_SEQUENCE):
            raise ValueError("Invalid anchor sequence.")
        if type(self.record_hash) is not str or _HASH.fullmatch(self.record_hash) is None:
            raise ValueError("Invalid anchor hash.")
        if (self.sequence == 0) != (self.record_hash == GENESIS_HASH):
            raise ValueError("Genesis hash and sequence zero must coincide.")


class StopLatchVerifier:
    """Pinned-public-key latch verification with sticky, one-way STOP.

    State (high water and STOP stickiness) lives in this object only. A restart
    resets it to the provisioned anchor, so the anchor must be kept current by
    the trusted provisioner; a durable independent store is not provided.
    A valid STOPPED record latches regardless of sequence or age: replaying a
    captured STOP can only deny service, never grant it. There is no reset.
    """

    __slots__ = (
        "_authority", "_keys", "_clock", "_skew", "_lock",
        "_high_sequence", "_high_hash", "_stopped", "_max_now",
    )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Latch verifier state is not externally assignable.")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Latch trust configuration is immutable.")

    def __init__(
        self,
        *,
        authority: AuthorityIdentity,
        trusted_public_keys: Mapping[str, bytes],
        other_purpose_key_ids: frozenset[str],
        other_purpose_public_keys: frozenset[bytes],
        anchor: LatchAnchor,
        clock: Callable[[], object],
        revoked_key_ids: frozenset[str] = frozenset(),
        max_clock_skew_seconds: int = 5,
    ) -> None:
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if type(anchor) is not LatchAnchor:
            raise ValueError("A provisioned latch anchor is required.")
        if not callable(clock):
            raise ValueError("An injected clock is required.")
        if not _int(max_clock_skew_seconds, 0, 60):
            raise ValueError("Invalid clock skew.")
        if not isinstance(trusted_public_keys, Mapping) or not 0 < len(trusted_public_keys) <= 16:
            raise ValueError("A bounded non-empty pinned public-key set is required.")
        for ids in (other_purpose_key_ids, revoked_key_ids):
            if type(ids) not in (set, frozenset) or not all(_identifier(i) for i in ids):
                raise ValueError("Invalid key ID set.")
        if type(other_purpose_public_keys) not in (set, frozenset) or any(
            type(k) is not bytes or len(k) != 32 for k in other_purpose_public_keys
        ):
            raise ValueError("Invalid other-purpose public keys.")

        keys: dict[str, Ed25519PublicKey] = {}
        seen: set[bytes] = set()
        for key_id, raw_key in trusted_public_keys.items():
            if not _identifier(key_id) or type(raw_key) is not bytes or len(raw_key) != 32:
                raise ValueError("Invalid pinned STOP public key.")
            if key_id in other_purpose_key_ids or raw_key in other_purpose_public_keys:
                raise ValueError("STOP keys must not be reused from another purpose.")
            if raw_key in seen:
                raise ValueError("Duplicate STOP public key.")
            seen.add(raw_key)
            if key_id not in revoked_key_ids:
                keys[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)
        object.__setattr__(self, "_authority", authority)
        object.__setattr__(self, "_keys", MappingProxyType(keys))
        object.__setattr__(self, "_clock", clock)
        object.__setattr__(self, "_skew", max_clock_skew_seconds)
        object.__setattr__(self, "_lock", threading.Lock())
        object.__setattr__(self, "_high_sequence", anchor.sequence)
        object.__setattr__(self, "_high_hash", anchor.record_hash)
        object.__setattr__(self, "_stopped", False)
        object.__setattr__(self, "_max_now", 0)

    @property
    def stopped(self) -> bool:
        return self._stopped

    def check(self, candidate: object) -> LatchDecision:
        """DENY unless an authentic, fresh, in-chain RUN lease is presented."""

        try:
            with self._lock:
                return LatchDecision(self._check_locked(candidate))
        except Exception:
            return LatchDecision(LatchReason.INTERNAL_ERROR)

    def _check_locked(self, candidate: object) -> LatchReason:
        if self._stopped:
            return LatchReason.STOPPED
        if candidate is None:
            return LatchReason.MISSING
        if type(candidate) is not StopLatchRecord:
            return LatchReason.CORRUPT
        try:
            # Rebuild to defeat object.__setattr__ edits on the frozen instance.
            record = StopLatchRecord(
                authority=AuthorityIdentity(
                    candidate.authority.authority_id,
                    candidate.authority.epoch,
                    candidate.authority.trust_domain,
                ),
                sequence=candidate.sequence,
                previous_hash=candidate.previous_hash,
                state=candidate.state,
                issued_at=candidate.issued_at,
                expires_at=candidate.expires_at,
                signing_key_id=candidate.signing_key_id,
                signature=candidate.signature,
                version=candidate.version,
                purpose=candidate.purpose,
                signature_algorithm=candidate.signature_algorithm,
            )
        except Exception:
            return LatchReason.CORRUPT
        if record.authority != self._authority:
            return LatchReason.UNTRUSTED_AUTHORITY
        key = self._keys.get(record.signing_key_id)
        if key is None:
            return LatchReason.UNTRUSTED_KEY
        try:
            key.verify(record.signature, record.canonical_bytes())
        except InvalidSignature:
            return LatchReason.INVALID_SIGNATURE

        if record.state is LatchState.STOPPED:
            object.__setattr__(self, "_stopped", True)
            return LatchReason.STOPPED

        now = self._now()
        if now is None:
            return LatchReason.CLOCK_ERROR
        if record.sequence < self._high_sequence:
            return LatchReason.ROLLED_BACK
        if record.sequence == self._high_sequence:
            if record.record_hash() != self._high_hash:
                return LatchReason.CONFLICT
        elif record.sequence == self._high_sequence + 1:
            if record.previous_hash != self._high_hash:
                return LatchReason.CHAIN_BREAK
        else:
            return LatchReason.SEQUENCE_GAP
        if record.issued_at > now + self._skew:
            return LatchReason.NOT_YET_VALID
        if record.expires_at <= now:
            return LatchReason.EXPIRED
        object.__setattr__(self, "_high_sequence", record.sequence)
        object.__setattr__(self, "_high_hash", record.record_hash())
        return LatchReason.RUN_LEASE_VALID

    def _now(self) -> int | None:
        value = self._clock()
        if type(value) is bool or not isinstance(value, (int, float)):
            return None
        if isinstance(value, float) and not math.isfinite(value):
            return None
        now = int(value)
        if now < 0 or now < self._max_now:
            return None
        object.__setattr__(self, "_max_now", now)
        return now


class StopLatchSource(Protocol):
    """Read-only supplier of the latest record; may return None if absent."""

    def read_latest(self) -> StopLatchRecord | None: ...


class FileStopLatchSource:
    """Reads one supervisor-owned record file; every anomaly raises or yields None.

    Missing file is None. Symlinks, non-regular files, multiple links, group/other
    writable files and oversized/noncanonical content are rejected. Ownership and
    directory protection are the deployer's obligation and are not verified here.
    """

    def __init__(self, path: str) -> None:
        if type(path) is not str or not path:
            raise ValueError("A record path is required.")
        self._path = path

    def read_latest(self) -> StopLatchRecord | None:
        try:
            fd = os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_mode & 0o022
                or info.st_size > MAX_RECORD_BYTES
            ):
                raise ValueError("Unsafe latch record file.")
            raw = os.read(fd, MAX_RECORD_BYTES + 1)
        finally:
            os.close(fd)
        return decode_record(raw)


class StopLatchGate:
    """Mandatory enforcement point: read, verify, and deny on any doubt."""

    def __init__(self, verifier: StopLatchVerifier, source: StopLatchSource) -> None:
        if type(verifier) is not StopLatchVerifier:
            raise ValueError("A StopLatchVerifier is required.")
        if not callable(getattr(source, "read_latest", None)):
            raise ValueError("A latch source is required.")
        self._verifier = verifier
        self._source = source

    def require_run(self, operation: str) -> LatchDecision:
        if type(operation) is not str or operation not in OPERATIONS:
            return LatchDecision(LatchReason.INVALID_OPERATION)
        try:
            record = self._source.read_latest()
        except Exception:
            # A previously latched STOP must still be reported as STOPPED.
            if self._verifier.stopped:
                return LatchDecision(LatchReason.STOPPED)
            return LatchDecision(LatchReason.SOURCE_UNAVAILABLE)
        return self._verifier.check(record)


class LatchEnforcedUsage:
    """Usage wrapper: reserve is denied unless the gate allows; inner untouched on deny."""

    def __init__(self, inner: object, gate: StopLatchGate) -> None:
        if type(gate) is not StopLatchGate:
            raise ValueError("A StopLatchGate is mandatory.")
        self._inner = inner
        self._gate = gate

    def reserve_evaluation(
        self, credential: object, resource_id: str, request_id: str, payload: bytes
    ) -> UsageResult:
        if not self._gate.require_run("reserve"):
            return UsageResult(UsageReason.UNAUTHORIZED)
        return self._inner.reserve_evaluation(credential, resource_id, request_id, payload)

    def complete(
        self, credential: object, resource_id: str, request_id: str, *, succeeded: bool
    ) -> UsageResult:
        # Completion only settles an already-reserved attempt; it grants nothing.
        return self._inner.complete(credential, resource_id, request_id, succeeded=succeeded)


class LatchEnforcedEvaluationService:
    """Evaluation wrapper enforcing the gate at evaluate as well as reserve."""

    def __init__(self, service: CommercialEvaluationService, gate: StopLatchGate) -> None:
        if type(gate) is not StopLatchGate:
            raise ValueError("A StopLatchGate is mandatory.")
        if type(service) is not CommercialEvaluationService:
            raise ValueError("A CommercialEvaluationService is required.")
        self._service = service
        self._gate = gate

    def evaluate(self, *args: object, **kwargs: object) -> CommercialServiceResponse:
        if not self._gate.require_run("evaluate"):
            return CommercialServiceResponse(
                ServiceOutcome.DENIED, ServiceReason.AUTHORIZATION_DENIED
            )
        return self._service.evaluate(*args, **kwargs)


def build_latch_enforced_service(
    usage: object, gate: StopLatchGate, **service_kwargs: object
) -> LatchEnforcedEvaluationService:
    """Compose both mandatory enforcement points; nothing registers or activates this."""

    return LatchEnforcedEvaluationService(
        CommercialEvaluationService(LatchEnforcedUsage(usage, gate), **service_kwargs), gate
    )
