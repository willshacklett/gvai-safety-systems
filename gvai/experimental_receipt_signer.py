from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from typing import Protocol

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    AuthorityReceipt,
    AuthenticatedAuthorityHead,
    CommitState,
    EvidenceClass,
    ExpectedReceiptContext,
    ReservationEvent,
    ReservationResult,
    ReservationStatus,
    RESERVATION_RECEIPT_PURPOSE,
)


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SIGNATURE_LENGTH = 64
_MAX_TRUSTED_SIGNER_IDS = 16


class ReceiptSigningKey(Protocol):
    """Injected signing capability; key creation and custody are external."""

    def sign(self, data: bytes) -> bytes: ...


class ReadOnlyCommittedEvidenceProvider(Protocol):
    """Read-only provider for a fresh committed-event and authority-head read.

    Implementations must use a read-only database role, an independent
    post-commit read, a consistent snapshot, and enforce the supplied timeout.
    This protocol does not itself prove those properties.
    """

    def read_committed_evidence(
        self, event_id: str, *, timeout_seconds: float
    ) -> "CommittedReservationEvidence | None": ...


class AuthorityHeadVerifier(Protocol):
    """Verify a head with trust and freshness controls independent of this signer."""

    def verify_head(
        self, head: AuthenticatedAuthorityHead, expected_authority: AuthorityIdentity
    ) -> bool: ...


@dataclass(frozen=True)
class CommittedReservationEvidence:
    """Read-back of one event and the independently trusted current authority head."""

    event: ReservationEvent
    stored_event_hash: str
    commit_state: CommitState
    authority_head: AuthenticatedAuthorityHead | None


class ExperimentalTrustedReceiptSigner:
    """Test-only signing boundary; it cannot reserve, write quota, or execute work.

    Repeated signing of the same event, status, and expected context is
    deterministic and idempotent under Ed25519. No durable signing-attempt
    ledger or production signer is provided.
    """

    __slots__ = (
        "_authority",
        "_signing_key_id",
        "_trusted_signer_ids",
        "_revoked_signer_ids",
        "_signing_key",
        "_evidence_provider",
        "_head_verifier",
        "_evidence_timeout_seconds",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Signer trust configuration is immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Signer trust configuration is immutable.")

    def __init__(
        self,
        *,
        authority: AuthorityIdentity,
        signing_key_id: str,
        trusted_signer_ids: set[str] | frozenset[str],
        revoked_signer_ids: set[str] | frozenset[str],
        signing_key: ReceiptSigningKey,
        evidence_provider: ReadOnlyCommittedEvidenceProvider,
        head_verifier: AuthorityHeadVerifier,
        evidence_timeout_seconds: float = 2.0,
    ) -> None:
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if type(signing_key_id) is not str or _IDENTIFIER.fullmatch(signing_key_id) is None:
            raise ValueError("Invalid signing key ID.")
        trusted_ids = self._copy_key_ids(trusted_signer_ids, "trusted")
        revoked_ids = self._copy_key_ids(revoked_signer_ids, "revoked", allow_empty=True)
        if signing_key_id not in trusted_ids or signing_key_id in revoked_ids:
            raise ValueError("The configured signer identity is unknown or revoked.")
        if not callable(getattr(signing_key, "sign", None)):
            raise ValueError("An injected receipt signing capability is required.")
        if not callable(getattr(evidence_provider, "read_committed_evidence", None)):
            raise ValueError("A read-only committed-evidence provider is required.")
        if not callable(getattr(head_verifier, "verify_head", None)):
            raise ValueError("A trusted authority-head verifier is required.")
        if (
            type(evidence_timeout_seconds) not in (int, float)
            or not math.isfinite(evidence_timeout_seconds)
            or not 0 < evidence_timeout_seconds <= 30
        ):
            raise ValueError("Evidence timeout must be bounded and positive.")

        self._authority = authority
        self._signing_key_id = signing_key_id
        self._trusted_signer_ids = trusted_ids
        self._revoked_signer_ids = revoked_ids
        self._signing_key = signing_key
        self._evidence_provider = evidence_provider
        self._head_verifier = head_verifier
        self._evidence_timeout_seconds = float(evidence_timeout_seconds)

    @staticmethod
    def _copy_key_ids(
        key_ids: set[str] | frozenset[str], label: str, *, allow_empty: bool = False
    ) -> frozenset[str]:
        if type(key_ids) not in (set, frozenset):
            raise ValueError("%s signer IDs must be a set." % label.capitalize())
        copied = frozenset(key_ids)
        if (
            (not allow_empty and not copied)
            or len(copied) > _MAX_TRUSTED_SIGNER_IDS
            or any(type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None for key_id in copied)
        ):
            raise ValueError("Invalid %s signer IDs." % label)
        return copied

    def sign_committed_result(
        self, result: object, expected: object
    ) -> AuthorityReceipt | None:
        """Sign only a committed adapter result matching trusted context and read-back."""
        if (
            type(result) is not ReservationResult
            or type(expected) is not ExpectedReceiptContext
            or result.status not in (ReservationStatus.RESERVED, ReservationStatus.REPLAY)
            or result.commit_state is not CommitState.COMMITTED
            or result.status is not expected.status
            or expected.authority != self._authority
            or expected.purpose != RESERVATION_RECEIPT_PURPOSE
            or self._signing_key_id not in expected.signing_key_ids
            or self._signing_key_id not in self._trusted_signer_ids
            or self._signing_key_id in self._revoked_signer_ids
        ):
            return None

        unsigned_result = result.receipt
        if (
            type(unsigned_result) is not AuthorityReceipt
            or unsigned_result.evidence_class is not EvidenceClass.UNAUTHENTICATED
            or unsigned_result.signature is not None
            or unsigned_result.signing_key_id is not None
            or unsigned_result.authority != self._authority
            or unsigned_result.status is not result.status
            or unsigned_result.purpose != expected.purpose
            or unsigned_result.evidence_version != expected.evidence_version
        ):
            return None

        event = unsigned_result.event
        if not self._matches_expected_event(event, expected):
            return None

        try:
            evidence = self._evidence_provider.read_committed_evidence(
                event.event_id,
                timeout_seconds=self._evidence_timeout_seconds,
            )
        except Exception:
            return None
        if (
            type(evidence) is not CommittedReservationEvidence
            or type(evidence.event) is not ReservationEvent
            or evidence.commit_state is not CommitState.COMMITTED
            or evidence.event != event
            or evidence.stored_event_hash != event.event_hash
        ):
            return None

        head = evidence.authority_head
        if (
            type(head) is not AuthenticatedAuthorityHead
            or head.evidence_class is not EvidenceClass.AUTHENTICATED
            or head.authority != self._authority
            or head.sequence != event.sequence
            or head.event_hash != event.event_hash
        ):
            return None
        try:
            if self._head_verifier.verify_head(head, self._authority) is not True:
                return None
        except Exception:
            return None

        unsigned_receipt = replace(
            unsigned_result,
            signing_key_id=self._signing_key_id,
            signature=b"\x00" * _SIGNATURE_LENGTH,
            evidence_class=EvidenceClass.AUTHENTICATED,
        )
        try:
            signature = self._signing_key.sign(
                unsigned_receipt.canonical_envelope_bytes()
            )
        except Exception:
            return None
        if type(signature) is not bytes or len(signature) != _SIGNATURE_LENGTH:
            return None
        return replace(unsigned_receipt, signature=signature)

    def _matches_expected_event(
        self, event: ReservationEvent, expected: ExpectedReceiptContext
    ) -> bool:
        return (
            event.authority == self._authority
            and event.authority == expected.authority
            and event.tenant_digest == expected.tenant_digest
            and event.principal_digest == expected.principal_digest
            and event.request_id_digest == expected.request_id_digest
            and event.request_digest == expected.request_digest
            and event.resource_digest == expected.resource_digest
            and event.policy_version == expected.policy_version
        )
