from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Protocol

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    AuthorityReceipt,
    AuthenticatedAuthorityHead,
    CanonicalReservationRequest,
    CommitState,
    EvidenceClass,
    ReservationEvent,
    ReservationStatus,
)


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HEAD_DOMAIN = b"gvai-authority-head-checkpoint-v1\x00"


class ReceiptSigningError(RuntimeError):
    """Signing was refused because authoritative evidence could not be established."""


@dataclass(frozen=True)
class ReceiptSigningContext:
    request: CanonicalReservationRequest
    tenant_digest: str
    principal_digest: str

    def __post_init__(self) -> None:
        if type(self.request) is not CanonicalReservationRequest:
            raise ValueError("A canonical reservation request is required.")
        if (
            type(self.tenant_digest) is not str
            or _DIGEST.fullmatch(self.tenant_digest) is None
            or type(self.principal_digest) is not str
            or _DIGEST.fullmatch(self.principal_digest) is None
        ):
            raise ValueError("Valid tenant and principal digests are required.")


@dataclass(frozen=True)
class IdempotencyEvidence:
    tenant_digest: str
    request_id_digest: str
    request_digest: str
    resource_digest: str
    event_id: str


@dataclass(frozen=True)
class CommittedReservationEvidence:
    status: ReservationStatus
    commit_state: CommitState
    event: ReservationEvent
    stored_event_hash: str
    idempotency: IdempotencyEvidence


class ReceiptEvidenceProvider(Protocol):
    """Read-only source for committed reservation and independently trusted head evidence."""

    def read_committed_reservation(
        self, context: ReceiptSigningContext
    ) -> CommittedReservationEvidence | None: ...

    def read_trusted_head_checkpoint(self) -> AuthenticatedAuthorityHead: ...


class ReceiptSigningKey(Protocol):
    """Isolated signing operation; private key material is not part of this boundary."""

    @property
    def key_id(self) -> str: ...

    def sign(self, message: bytes) -> bytes: ...


class TrustedCheckpointVerifier(Protocol):
    """Must authenticate the checkpoint and enforce freshness from an independent trust source."""

    def verify_trusted_checkpoint(
        self,
        checkpoint: AuthenticatedAuthorityHead,
        expected_authority: AuthorityIdentity,
    ) -> bool: ...


def canonical_head_checkpoint_bytes(checkpoint: AuthenticatedAuthorityHead) -> bytes:
    """Canonical bytes for a trusted head-checkpoint signature."""
    record = {
        "authority": {
            "authority_id": checkpoint.authority.authority_id,
            "epoch": checkpoint.authority.epoch,
            "trust_domain": checkpoint.authority.trust_domain,
        },
        "event_hash": checkpoint.event_hash,
        "sequence": checkpoint.sequence,
        "signing_key_id": checkpoint.signing_key_id,
    }
    return _HEAD_DOMAIN + json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


class ExperimentalTrustedReceiptSigner:
    """Isolated signing boundary; receipts are evidence and never execution permission.

    The evidence provider and checkpoint verifier are trusted dependencies. No
    production provider or freshness verifier is supplied by this module.
    """

    def __init__(
        self,
        *,
        authority: AuthorityIdentity,
        evidence_provider: ReceiptEvidenceProvider,
        signing_key: ReceiptSigningKey,
        checkpoint_verifier: TrustedCheckpointVerifier,
        trusted_signing_key_ids: frozenset[str],
        revoked_signing_key_ids: frozenset[str] = frozenset(),
        allow_test_only_checkpoints: bool = False,
    ) -> None:
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if not callable(getattr(evidence_provider, "read_committed_reservation", None)):
            raise ValueError("A committed-evidence provider is required.")
        if not callable(getattr(evidence_provider, "read_trusted_head_checkpoint", None)):
            raise ValueError("A trusted checkpoint provider is required.")
        if not callable(getattr(signing_key, "sign", None)):
            raise ValueError("An isolated signing interface is required.")
        if not callable(getattr(checkpoint_verifier, "verify_trusted_checkpoint", None)):
            raise ValueError("A trusted checkpoint verifier is required.")
        if (
            type(trusted_signing_key_ids) is not frozenset
            or not trusted_signing_key_ids
            or any(
                type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None
                for key_id in trusted_signing_key_ids
            )
        ):
            raise ValueError("A non-empty pinned signing-key set is required.")
        if type(revoked_signing_key_ids) is not frozenset or any(
            type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None
            for key_id in revoked_signing_key_ids
        ):
            raise ValueError("Revoked signing key IDs must be a valid frozen set.")
        if type(allow_test_only_checkpoints) is not bool:
            raise ValueError("Test-only checkpoint mode must be an explicit boolean.")
        self._authority = authority
        self._evidence_provider = evidence_provider
        self._signing_key = signing_key
        self._checkpoint_verifier = checkpoint_verifier
        self._trusted_signing_key_ids = trusted_signing_key_ids
        self._revoked_signing_key_ids = revoked_signing_key_ids
        self._allow_test_only_checkpoints = allow_test_only_checkpoints

    def sign_reservation(self, context: ReceiptSigningContext) -> AuthorityReceipt:
        """Sign only a matching committed reservation independently read by the provider."""
        try:
            if type(context) is not ReceiptSigningContext:
                raise ReceiptSigningError("Invalid receipt signing context.")
            key_id = self._signing_key.key_id
            if (
                type(key_id) is not str
                or _IDENTIFIER.fullmatch(key_id) is None
                or key_id not in self._trusted_signing_key_ids
                or key_id in self._revoked_signing_key_ids
            ):
                raise ReceiptSigningError("The signing key is unknown or revoked.")

            evidence = self._evidence_provider.read_committed_reservation(context)
            if not self._matches_committed_evidence(context, evidence):
                raise ReceiptSigningError("Committed reservation evidence is missing or inconsistent.")

            checkpoint = self._evidence_provider.read_trusted_head_checkpoint()
            if (
                type(checkpoint) is not AuthenticatedAuthorityHead
                or checkpoint.authority != self._authority
                or checkpoint.sequence != evidence.event.sequence
                or checkpoint.event_hash != evidence.event.event_hash
                or checkpoint.evidence_class
                not in (EvidenceClass.AUTHENTICATED, EvidenceClass.TEST_ONLY)
                or (
                    checkpoint.evidence_class is EvidenceClass.TEST_ONLY
                    and not self._allow_test_only_checkpoints
                )
                or self._checkpoint_verifier.verify_trusted_checkpoint(
                    checkpoint, self._authority
                )
                is not True
            ):
                raise ReceiptSigningError("A fresh trusted authority-head checkpoint is required.")

            unsigned = AuthorityReceipt(
                authority=self._authority,
                status=evidence.status,
                event=evidence.event,
                signing_key_id=key_id,
                signature=b"\x00" * 64,
                evidence_class=EvidenceClass.AUTHENTICATED,
            )
            signature = self._signing_key.sign(unsigned.canonical_envelope_bytes())
            if type(signature) is not bytes or len(signature) != 64:
                raise ReceiptSigningError("The signing interface returned an invalid signature.")
            return AuthorityReceipt(
                authority=unsigned.authority,
                status=unsigned.status,
                event=unsigned.event,
                signing_key_id=key_id,
                signature=signature,
                evidence_class=EvidenceClass.AUTHENTICATED,
            )
        except ReceiptSigningError:
            raise
        except Exception as exc:
            raise ReceiptSigningError("Trusted receipt signing failed closed.") from exc

    def _matches_committed_evidence(
        self,
        context: ReceiptSigningContext,
        evidence: CommittedReservationEvidence | None,
    ) -> bool:
        if (
            type(evidence) is not CommittedReservationEvidence
            or type(evidence.status) is not ReservationStatus
            or evidence.status not in (ReservationStatus.RESERVED, ReservationStatus.REPLAY)
            or evidence.commit_state is not CommitState.COMMITTED
            or type(evidence.event) is not ReservationEvent
            or type(evidence.stored_event_hash) is not str
            or type(evidence.idempotency) is not IdempotencyEvidence
        ):
            return False
        event = evidence.event
        request = context.request
        idem = evidence.idempotency
        if any(
            type(value) is not str
            for value in (
                idem.tenant_digest,
                idem.request_id_digest,
                idem.request_digest,
                idem.resource_digest,
                idem.event_id,
            )
        ):
            return False
        return (
            event.authority == self._authority
            and event.event_hash == evidence.stored_event_hash
            and event.tenant_digest == context.tenant_digest
            and event.principal_digest == context.principal_digest
            and event.request_id_digest == self._digest(request.request_id)
            and event.request_digest == request.request_digest
            and event.resource_digest == self._digest(request.resource_id)
            and idem.tenant_digest == event.tenant_digest
            and idem.request_id_digest == event.request_id_digest
            and idem.request_digest == event.request_digest
            and idem.resource_digest == event.resource_digest
            and idem.event_id == event.event_id
        )

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("ascii")).hexdigest()
