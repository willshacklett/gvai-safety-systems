import hashlib
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    AuthorityReceipt,
    AuthenticatedAuthorityHead,
    CanonicalReservationRequest,
    CommitState,
    EvidenceClass,
    ExpectedReceiptContext,
    GENESIS_HASH,
    ReservationEvent,
    ReservationStatus,
    verify_authenticated_receipt,
)
from gvai.ed25519_receipt_verifier import Ed25519ReceiptVerifier
from gvai.experimental_receipt_signer import (
    CommittedReservationEvidence,
    ExperimentalTrustedReceiptSigner,
    IdempotencyEvidence,
    ReceiptSigningContext,
    ReceiptSigningError,
    canonical_head_checkpoint_bytes,
)


_AUTHORITY = AuthorityIdentity("signer-authority", 3, "test-domain")
_TENANT_DIGEST = hashlib.sha256(b"tenant-a").hexdigest()
_PRINCIPAL_DIGEST = hashlib.sha256(b"principal-a").hexdigest()


class _EphemeralKey:
    def __init__(self, key_id):
        self.key_id = key_id
        self._private_key = Ed25519PrivateKey.generate()

    @property
    def public_key_bytes(self):
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def sign(self, message):
        return self._private_key.sign(message)


class _Provider:
    def __init__(self, evidence, checkpoint):
        self.evidence = evidence
        self.checkpoint = checkpoint
        self.fail_evidence = False
        self.fail_checkpoint = False

    def read_committed_reservation(self, context):
        if self.fail_evidence:
            raise OSError("test provider failure")
        return self.evidence

    def read_trusted_head_checkpoint(self):
        if self.fail_checkpoint:
            raise OSError("test checkpoint provider failure")
        return self.checkpoint


class _TestCheckpointVerifier:
    def __init__(self, public_key, *, minimum_sequence=0, key_id="head-test-key"):
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
        self._minimum_sequence = minimum_sequence
        self._key_id = key_id

    def verify_trusted_checkpoint(self, checkpoint, expected_authority):
        if (
            type(checkpoint) is not AuthenticatedAuthorityHead
            or checkpoint.authority != expected_authority
            or checkpoint.signing_key_id != self._key_id
            or checkpoint.evidence_class is not EvidenceClass.TEST_ONLY
            or checkpoint.sequence < self._minimum_sequence
        ):
            return False
        try:
            self._public_key.verify(
                checkpoint.signature, canonical_head_checkpoint_bytes(checkpoint)
            )
            return True
        except Exception:
            return False


class ExperimentalTrustedReceiptSignerTests(unittest.TestCase):
    def setUp(self):
        self.request = CanonicalReservationRequest.from_bounded_input(
            "request-1", "resource-1", b"bounded evaluation input"
        )
        self.context = ReceiptSigningContext(
            self.request, _TENANT_DIGEST, _PRINCIPAL_DIGEST
        )
        self.event = ReservationEvent(
            authority=_AUTHORITY,
            sequence=1,
            event_id="reservation-event-1",
            previous_event_hash=GENESIS_HASH,
            tenant_digest=_TENANT_DIGEST,
            principal_digest=_PRINCIPAL_DIGEST,
            resource_digest=self._digest("resource-1"),
            request_id_digest=self._digest("request-1"),
            request_digest=self.request.request_digest,
            period="2026-10",
            policy_version="policy-1",
        )
        self.evidence = self._evidence(ReservationStatus.RESERVED)
        self.receipt_key = _EphemeralKey("receipt-test-key")
        self.head_key = _EphemeralKey("head-test-key")
        self.provider = _Provider(self.evidence, self._checkpoint())
        self.checkpoint_verifier = _TestCheckpointVerifier(
            self.head_key.public_key_bytes
        )
        self.signer = self._signer()

    def _signer(self, *, trusted=None, revoked=frozenset()):
        return ExperimentalTrustedReceiptSigner(
            authority=_AUTHORITY,
            evidence_provider=self.provider,
            signing_key=self.receipt_key,
            checkpoint_verifier=self.checkpoint_verifier,
            trusted_signing_key_ids=(
                frozenset({self.receipt_key.key_id}) if trusted is None else trusted
            ),
            revoked_signing_key_ids=revoked,
            allow_test_only_checkpoints=True,
        )

    def _evidence(self, status, *, event=None, commit_state=CommitState.COMMITTED):
        event = self.event if event is None else event
        return CommittedReservationEvidence(
            status=status,
            commit_state=commit_state,
            event=event,
            stored_event_hash=event.event_hash,
            idempotency=IdempotencyEvidence(
                tenant_digest=event.tenant_digest,
                request_id_digest=event.request_id_digest,
                request_digest=event.request_digest,
                resource_digest=event.resource_digest,
                event_id=event.event_id,
            ),
        )

    def _checkpoint(self, *, sequence=None, event_hash=None, evidence_class=None):
        unsigned = AuthenticatedAuthorityHead(
            authority=_AUTHORITY,
            sequence=self.event.sequence if sequence is None else sequence,
            event_hash=self.event.event_hash if event_hash is None else event_hash,
            signing_key_id=self.head_key.key_id,
            signature=b"\x00" * 64,
            evidence_class=(
                EvidenceClass.TEST_ONLY if evidence_class is None else evidence_class
            ),
        )
        return replace(
            unsigned,
            signature=self.head_key.sign(canonical_head_checkpoint_bytes(unsigned)),
        )

    @staticmethod
    def _digest(value):
        return hashlib.sha256(value.encode("ascii")).hexdigest()

    def _verified(self, receipt):
        verifier = Ed25519ReceiptVerifier(
            authority=_AUTHORITY,
            trusted_public_keys={self.receipt_key.key_id: self.receipt_key.public_key_bytes},
        )
        expected = ExpectedReceiptContext(
            authority=_AUTHORITY,
            status=receipt.status,
            tenant_digest=self.event.tenant_digest,
            principal_digest=self.event.principal_digest,
            request_id_digest=self.event.request_id_digest,
            request_digest=self.event.request_digest,
            resource_digest=self.event.resource_digest,
            policy_version=self.event.policy_version,
            signing_key_ids=frozenset({self.receipt_key.key_id}),
        )
        return verifier, expected

    def test_signs_only_provider_retrieved_committed_evidence_and_verifies(self):
        receipt = self.signer.sign_reservation(self.context)
        self.assertEqual(receipt.status, ReservationStatus.RESERVED)
        self.assertEqual(receipt.evidence_class, EvidenceClass.AUTHENTICATED)
        verifier, expected = self._verified(receipt)
        self.assertTrue(verify_authenticated_receipt(receipt, expected, verifier))

    def test_arbitrary_application_receipts_are_not_signer_inputs(self):
        receipt = AuthorityReceipt(
            authority=_AUTHORITY,
            status=ReservationStatus.RESERVED,
            event=self.event,
            signing_key_id=None,
            signature=None,
            evidence_class=EvidenceClass.UNAUTHENTICATED,
        )
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(receipt)

    def test_missing_evidence_and_provider_failures_fail_closed(self):
        self.provider.evidence = None
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_inconsistent_idempotency_evidence_fails_closed(self):
        mismatched_idempotency = replace(
            self.evidence.idempotency, request_digest="d" * 64
        )
        self.provider.evidence = replace(
            self.evidence, idempotency=mismatched_idempotency
        )
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.provider.evidence = self.evidence
        self.provider.fail_evidence = True
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.provider.fail_evidence = False
        self.provider.fail_checkpoint = True
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_stored_event_hash_mismatch_fails_closed(self):
        self.provider.evidence = replace(self.evidence, stored_event_hash="a" * 64)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_sequence_and_event_hash_must_match_trusted_checkpoint(self):
        self.provider.checkpoint = self._checkpoint(sequence=2)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)
        self.provider.checkpoint = self._checkpoint(event_hash="a" * 64)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_tenant_authority_and_request_bindings_are_enforced(self):
        mismatched_event = replace(self.event, tenant_digest="b" * 64)
        self.provider.evidence = self._evidence(ReservationStatus.RESERVED, event=mismatched_event)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.provider.evidence = self.evidence
        for request in (
            CanonicalReservationRequest.from_bounded_input(
                "different-request", "resource-1", b"bounded evaluation input"
            ),
            CanonicalReservationRequest.from_bounded_input(
                "request-1", "different-resource", b"bounded evaluation input"
            ),
        ):
            with self.subTest(request=request):
                with self.assertRaises(ReceiptSigningError):
                    self.signer.sign_reservation(
                        ReceiptSigningContext(request, _TENANT_DIGEST, _PRINCIPAL_DIGEST)
                    )

        mismatched_event = replace(
            self.event,
            authority=AuthorityIdentity("other-authority", 3, "test-domain"),
        )
        self.provider.evidence = self._evidence(ReservationStatus.RESERVED, event=mismatched_event)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        mismatched_event = replace(self.event, request_digest="c" * 64)
        self.provider.evidence = self._evidence(ReservationStatus.RESERVED, event=mismatched_event)
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_stale_and_unauthenticated_checkpoints_fail_closed(self):
        self.checkpoint_verifier = _TestCheckpointVerifier(
            self.head_key.public_key_bytes, minimum_sequence=2
        )
        self.signer = self._signer()
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.checkpoint_verifier = _TestCheckpointVerifier(
            self.head_key.public_key_bytes, minimum_sequence=0
        )
        self.signer = self._signer()
        self.provider.checkpoint = self._checkpoint(
            evidence_class=EvidenceClass.UNAUTHENTICATED
        )
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_test_only_checkpoint_mode_is_disabled_by_default(self):
        signer = ExperimentalTrustedReceiptSigner(
            authority=_AUTHORITY,
            evidence_provider=self.provider,
            signing_key=self.receipt_key,
            checkpoint_verifier=self.checkpoint_verifier,
            trusted_signing_key_ids=frozenset({self.receipt_key.key_id}),
        )
        with self.assertRaises(ReceiptSigningError):
            signer.sign_reservation(self.context)

    def test_ambiguous_commit_unknown_signer_and_revoked_signer_fail_closed(self):
        self.provider.evidence = self._evidence(
            ReservationStatus.RESERVED, commit_state=CommitState.UNKNOWN
        )
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.provider.evidence = self.evidence
        self.signer = self._signer(trusted=frozenset({"other-key"}))
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

        self.signer = self._signer(revoked=frozenset({self.receipt_key.key_id}))
        with self.assertRaises(ReceiptSigningError):
            self.signer.sign_reservation(self.context)

    def test_replay_is_signed_as_replay_and_never_substitutes_for_reserved(self):
        replay = self._evidence(ReservationStatus.REPLAY)
        self.provider.evidence = replay
        receipt = self.signer.sign_reservation(self.context)
        self.assertEqual(receipt.status, ReservationStatus.REPLAY)
        verifier, replay_context = self._verified(receipt)
        self.assertTrue(verify_authenticated_receipt(receipt, replay_context, verifier))

        substituted = replace(receipt, status=ReservationStatus.RESERVED)
        reserved_context = replace(
            replay_context, status=ReservationStatus.RESERVED
        )
        self.assertFalse(
            verify_authenticated_receipt(substituted, reserved_context, verifier)
        )


if __name__ == "__main__":
    unittest.main()
