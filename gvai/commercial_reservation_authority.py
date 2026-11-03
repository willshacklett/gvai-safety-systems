from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol


CONTRACT_VERSION = 1
MAX_IDENTIFIER_LENGTH = 128
MAX_POLICY_VERSION_LENGTH = 64
MAX_CREDENTIAL_LENGTH = 4096
MAX_EVALUATION_INPUT_BYTES = 1_048_576
MAX_EVALUATION_UNITS = (1 << 63) - 1
SUPPORTED_RESERVATION_RESOURCE_KINDS = frozenset({"evaluation"})
GENESIS_HASH = "0" * 64
EVIDENCE_VERSION = 1
RESERVATION_RECEIPT_PURPOSE = "reservation_decision"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PERIOD = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])\Z")
_REQUEST_DOMAIN = b"gvai-reservation-request-v1\x00"
_EVENT_DOMAIN = b"gvai-reservation-event-v1\x00"
_PAYLOAD_DOMAIN = b"gvai-bounded-evaluation-input-v1\x00"
_RECEIPT_DOMAIN = b"gvai-authority-receipt-envelope-v1\x00"


class ReservationStatus(str, Enum):
    RESERVED = "reserved"
    REPLAY = "replay"
    CONFLICT = "conflict"
    QUOTA_EXCEEDED = "quota_exceeded"
    UNAUTHORIZED = "unauthorized"
    AUTHORITY_UNAVAILABLE = "authority_unavailable"


class CommitState(str, Enum):
    NOT_COMMITTED = "not_committed"
    COMMITTED = "committed"
    UNKNOWN = "unknown"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    DISABLED = "disabled"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class EvidenceClass(str, Enum):
    TEST_ONLY = "test_only"
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"


def _validate_identifier(value: object, field_name: str) -> None:
    if type(value) is not str or len(value) > MAX_IDENTIFIER_LENGTH:
        raise ValueError("Invalid %s." % field_name)
    if _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("Invalid %s." % field_name)


def _validate_digest(value: object, field_name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError("Invalid %s." % field_name)


def payload_digest_for_bounded_input(payload: bytes) -> str:
    """Digest the exact immutable input that the trusted evaluator will consume."""
    if type(payload) is not bytes or len(payload) > MAX_EVALUATION_INPUT_BYTES:
        raise ValueError("Evaluation input must be bounded immutable bytes.")
    return hashlib.sha256(_PAYLOAD_DOMAIN + payload).hexdigest()


@dataclass(frozen=True)
class AuthorityIdentity:
    authority_id: str
    epoch: int
    trust_domain: str

    def __post_init__(self) -> None:
        _validate_identifier(self.authority_id, "authority ID")
        _validate_identifier(self.trust_domain, "trust domain")
        if type(self.epoch) is not int or not 1 <= self.epoch <= MAX_EVALUATION_UNITS:
            raise ValueError("Invalid authority epoch.")


@dataclass(frozen=True)
class CanonicalReservationRequest:
    """Client-controlled bounded fields; tenant, principal, policy, and authority are absent."""

    request_id: str
    resource_id: str
    payload_digest: str
    version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != CONTRACT_VERSION:
            raise ValueError("Unsupported reservation contract version.")
        _validate_identifier(self.request_id, "request ID")
        _validate_identifier(self.resource_id, "resource ID")
        _validate_digest(self.payload_digest, "payload digest")

    @classmethod
    def from_bounded_input(
        cls, request_id: str, resource_id: str, payload: bytes
    ) -> "CanonicalReservationRequest":
        return cls(
            request_id,
            resource_id,
            payload_digest_for_bounded_input(payload),
        )

    def canonical_bytes(self) -> bytes:
        record = {
            "payload_digest": self.payload_digest,
            "request_id": self.request_id,
            "resource_id": self.resource_id,
            "version": self.version,
        }
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

    @property
    def request_digest(self) -> str:
        return hashlib.sha256(_REQUEST_DOMAIN + self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class AuthorityCredentialRecord:
    """Authority-owned result of credential authentication, never request claims."""

    principal_id: str
    tenant_id: str
    status: CredentialStatus

    def __post_init__(self) -> None:
        _validate_identifier(self.principal_id, "principal ID")
        _validate_identifier(self.tenant_id, "tenant ID")
        if type(self.status) is not CredentialStatus:
            raise ValueError("Invalid credential status.")


@dataclass(frozen=True)
class ResourceOwnership:
    resource_id: str
    tenant_id: str
    resource_kind: str

    def __post_init__(self) -> None:
        _validate_identifier(self.resource_id, "resource ID")
        _validate_identifier(self.tenant_id, "tenant ID")
        _validate_identifier(self.resource_kind, "resource kind")


@dataclass(frozen=True)
class MonthlyQuotaPolicy:
    tenant_id: str
    policy_version: str
    monthly_allowance: int

    def __post_init__(self) -> None:
        _validate_identifier(self.tenant_id, "tenant ID")
        _validate_identifier(self.policy_version, "policy version")
        if len(self.policy_version) > MAX_POLICY_VERSION_LENGTH:
            raise ValueError("Policy version is too long.")
        if (
            type(self.monthly_allowance) is not int
            or not 0 <= self.monthly_allowance <= MAX_EVALUATION_UNITS
        ):
            raise ValueError("Invalid monthly allowance.")


@dataclass(frozen=True)
class ReservationEvent:
    authority: AuthorityIdentity
    sequence: int
    event_id: str
    previous_event_hash: str
    tenant_digest: str
    principal_digest: str
    resource_digest: str
    request_id_digest: str
    request_digest: str
    period: str
    policy_version: str
    units: int = 1
    version: int = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("Invalid event authority.")
        if type(self.sequence) is not int or not 1 <= self.sequence <= MAX_EVALUATION_UNITS:
            raise ValueError("Invalid event sequence.")
        _validate_identifier(self.event_id, "event ID")
        for field_name in (
            "previous_event_hash",
            "tenant_digest",
            "principal_digest",
            "resource_digest",
            "request_id_digest",
            "request_digest",
        ):
            _validate_digest(getattr(self, field_name), field_name)
        if type(self.period) is not str or _PERIOD.fullmatch(self.period) is None:
            raise ValueError("Invalid accounting period.")
        _validate_identifier(self.policy_version, "policy version")
        if len(self.policy_version) > MAX_POLICY_VERSION_LENGTH:
            raise ValueError("Policy version is too long.")
        if type(self.units) is not int or self.units != 1:
            raise ValueError("A reservation event must account for exactly one unit.")
        if type(self.version) is not int or self.version != CONTRACT_VERSION:
            raise ValueError("Unsupported reservation event version.")

    def canonical_bytes(self) -> bytes:
        record = {
            "authority_epoch": self.authority.epoch,
            "authority_id": self.authority.authority_id,
            "contract_version": self.version,
            "event_id": self.event_id,
            "period": self.period,
            "policy_version": self.policy_version,
            "previous_event_hash": self.previous_event_hash,
            "principal_digest": self.principal_digest,
            "request_digest": self.request_digest,
            "request_id_digest": self.request_id_digest,
            "resource_digest": self.resource_digest,
            "sequence": self.sequence,
            "tenant_digest": self.tenant_digest,
            "trust_domain": self.authority.trust_domain,
            "units": self.units,
        }
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")

    @property
    def event_hash(self) -> str:
        return hashlib.sha256(_EVENT_DOMAIN + self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class AuthorityReceipt:
    authority: AuthorityIdentity
    status: ReservationStatus
    event: ReservationEvent
    signing_key_id: str | None
    signature: bytes | None
    evidence_class: EvidenceClass
    evidence_version: int = EVIDENCE_VERSION
    purpose: str = RESERVATION_RECEIPT_PURPOSE

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("Invalid receipt authority.")
        if type(self.status) is not ReservationStatus or self.status not in (
            ReservationStatus.RESERVED,
            ReservationStatus.REPLAY,
        ):
            raise ValueError("A receipt must represent a reservation or replay.")
        if type(self.event) is not ReservationEvent or self.event.authority != self.authority:
            raise ValueError("Receipt event authority mismatch.")
        if self.signing_key_id is not None:
            if type(self.signing_key_id) is not str:
                raise ValueError("Invalid signing key ID.")
            _validate_identifier(self.signing_key_id, "signing key ID")
        if self.signature is not None and (
            type(self.signature) is not bytes or not 1 <= len(self.signature) <= 512
        ):
            raise ValueError("Invalid receipt signature.")
        if type(self.evidence_class) is not EvidenceClass:
            raise ValueError("Invalid evidence class.")
        if type(self.evidence_version) is not int or self.evidence_version != EVIDENCE_VERSION:
            raise ValueError("Unsupported receipt evidence version.")
        if type(self.purpose) is not str or self.purpose != RESERVATION_RECEIPT_PURPOSE:
            raise ValueError("Unsupported receipt purpose.")
        if self.evidence_class is EvidenceClass.AUTHENTICATED and (
            self.signing_key_id is None or self.signature is None
        ):
            raise ValueError("Authenticated receipts require a key ID and signature.")

    def canonical_envelope_bytes(self) -> bytes:
        """Return the deterministic bytes that a production signer must authenticate."""
        event = self.event
        envelope = {
            "authority": {
                "authority_id": self.authority.authority_id,
                "epoch": self.authority.epoch,
                "trust_domain": self.authority.trust_domain,
            },
            "evidence_version": self.evidence_version,
            "event": {
                "event_hash": event.event_hash,
                "event_id": event.event_id,
                "previous_event_hash": event.previous_event_hash,
                "request_digest": event.request_digest,
                "request_id_digest": event.request_id_digest,
                "resource_digest": event.resource_digest,
                "sequence": event.sequence,
                "tenant_digest": event.tenant_digest,
                "principal_digest": event.principal_digest,
                "period": event.period,
                "policy_version": event.policy_version,
                "units": event.units,
                "version": event.version,
            },
            "evidence_class": self.evidence_class.value,
            "receipt_purpose": self.purpose,
            "signing_key_id": self.signing_key_id,
            "status": self.status.value,
        }
        return _RECEIPT_DOMAIN + json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")


@dataclass(frozen=True)
class ExpectedReceiptContext:
    """Trusted, server-derived bindings; never construct from customer claims."""

    authority: AuthorityIdentity
    status: ReservationStatus
    tenant_digest: str
    principal_digest: str
    request_id_digest: str
    request_digest: str
    resource_digest: str
    policy_version: str
    signing_key_ids: frozenset[str]
    evidence_version: int = EVIDENCE_VERSION
    purpose: str = RESERVATION_RECEIPT_PURPOSE

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("Invalid expected authority.")
        if type(self.status) is not ReservationStatus or self.status not in (
            ReservationStatus.RESERVED,
            ReservationStatus.REPLAY,
        ):
            raise ValueError("Invalid expected receipt purpose/status.")
        for field_name in (
            "tenant_digest",
            "principal_digest",
            "request_id_digest",
            "request_digest",
            "resource_digest",
        ):
            _validate_digest(getattr(self, field_name), field_name)
        _validate_identifier(self.policy_version, "expected policy version")
        if len(self.policy_version) > MAX_POLICY_VERSION_LENGTH:
            raise ValueError("Expected policy version is too long.")
        if (
            type(self.signing_key_ids) is not frozenset
            or not self.signing_key_ids
            or len(self.signing_key_ids) > 16
        ):
            raise ValueError("Expected a bounded pinned signing-key set.")
        for key_id in self.signing_key_ids:
            _validate_identifier(key_id, "expected signing key ID")
        if type(self.evidence_version) is not int or self.evidence_version != EVIDENCE_VERSION:
            raise ValueError("Unsupported expected evidence version.")
        if type(self.purpose) is not str or self.purpose != RESERVATION_RECEIPT_PURPOSE:
            raise ValueError("Unsupported expected receipt purpose.")


@dataclass(frozen=True)
class ReservationResult:
    status: ReservationStatus
    commit_state: CommitState
    receipt: AuthorityReceipt | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not ReservationStatus:
            raise ValueError("Invalid reservation status.")
        if type(self.commit_state) is not CommitState:
            raise ValueError("Invalid commit state.")
        if self.status in (ReservationStatus.RESERVED, ReservationStatus.REPLAY):
            if (
                self.commit_state is not CommitState.COMMITTED
                or type(self.receipt) is not AuthorityReceipt
            ):
                raise ValueError("A reservation/replay result requires a committed receipt.")
            if self.receipt.status is not self.status:
                raise ValueError("Result and receipt statuses differ.")
        elif self.receipt is not None:
            raise ValueError("Non-reservation results cannot carry a receipt.")
        elif self.status is ReservationStatus.AUTHORITY_UNAVAILABLE:
            if self.commit_state not in (CommitState.NOT_COMMITTED, CommitState.UNKNOWN):
                raise ValueError("Unavailable authority results cannot claim a committed decision.")
        elif self.commit_state is not CommitState.NOT_COMMITTED:
            raise ValueError("A denied reservation result must be uncommitted.")


@dataclass(frozen=True)
class AuthenticatedAuthorityHead:
    authority: AuthorityIdentity
    sequence: int
    event_hash: str
    signing_key_id: str
    signature: bytes
    evidence_class: EvidenceClass

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("Invalid authority head identity.")
        if type(self.sequence) is not int or not 0 <= self.sequence <= MAX_EVALUATION_UNITS:
            raise ValueError("Invalid authority head sequence.")
        _validate_digest(self.event_hash, "authority head event hash")
        _validate_identifier(self.signing_key_id, "signing key ID")
        if type(self.signature) is not bytes or not 1 <= len(self.signature) <= 512:
            raise ValueError("Invalid authority head signature.")
        if type(self.evidence_class) is not EvidenceClass:
            raise ValueError("Invalid evidence class.")


class ReservationAuthority(Protocol):
    """Authority must atomically authenticate, authorize, meter, and persist."""

    def reserve(
        self,
        request: CanonicalReservationRequest,
        credential: str,
    ) -> ReservationResult: ...

    def read_authenticated_head(self) -> AuthenticatedAuthorityHead: ...



class AuthorityEvidenceVerifier(Protocol):
    """Production verifier pins authority identity and independently trusted keys."""

    def verify_receipt(
        self,
        canonical_envelope: bytes,
        signature: bytes,
        signing_key_id: str,
        expected_authority: AuthorityIdentity,
    ) -> bool: ...

    def verify_head(
        self,
        head: AuthenticatedAuthorityHead,
        expected_authority: AuthorityIdentity,
    ) -> bool: ...


def verify_authenticated_receipt(
    receipt: object,
    expected: ExpectedReceiptContext,
    verifier: AuthorityEvidenceVerifier,
) -> bool:
    """Check trusted request context before asking an injected verifier about bytes."""
    if (
        type(receipt) is not AuthorityReceipt
        or type(expected) is not ExpectedReceiptContext
        or receipt.evidence_class is not EvidenceClass.AUTHENTICATED
        or receipt.status is not expected.status
        or receipt.purpose != expected.purpose
        or receipt.authority != expected.authority
        or receipt.event.authority != expected.authority
        or receipt.event.tenant_digest != expected.tenant_digest
        or receipt.event.principal_digest != expected.principal_digest
        or receipt.event.request_id_digest != expected.request_id_digest
        or receipt.event.request_digest != expected.request_digest
        or receipt.event.resource_digest != expected.resource_digest
        or receipt.event.policy_version != expected.policy_version
        or receipt.evidence_version != expected.evidence_version
        or type(receipt.signature) is not bytes
        or not receipt.signature
        or receipt.signing_key_id not in expected.signing_key_ids
    ):
        return False
    try:
        verify_receipt = getattr(verifier, "verify_receipt", None)
        if not callable(verify_receipt):
            return False
        return verify_receipt(
            receipt.canonical_envelope_bytes(),
            receipt.signature,
            receipt.signing_key_id,
            expected.authority,
        ) is True
    except Exception:
        return False
