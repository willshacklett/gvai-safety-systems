from dataclasses import replace
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    AuthorityReceipt,
    AuthenticatedAuthorityHead,
    CommitState,
    EvidenceClass,
    ExpectedReceiptContext,
    GENESIS_HASH,
    ReservationEvent,
    ReservationResult,
    ReservationStatus,
    verify_authenticated_receipt,
)
from gvai.ed25519_receipt_verifier import Ed25519ReceiptVerifier
from gvai.experimental_receipt_signer import (
    CommittedReservationEvidence,
    ExperimentalTrustedReceiptSigner,
)


def _digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


class _EphemeralTestSigningKey:
    def __init__(self):
        self._key = Ed25519PrivateKey.generate()

    def sign(self, data):
        return self._key.sign(data)

    @property
    def public_key_bytes(self):
        return self._key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )


class _ReadOnlyTestEvidenceProvider:
    def __init__(self, evidence):
        self.evidence = evidence
        self.failure = None
        self.calls = []

    def read_committed_evidence(self, event_id, *, timeout_seconds):
        self.calls.append((event_id, timeout_seconds))
        if self.failure is not None:
            raise self.failure
        return self.evidence


class _TestAuthorityHeadVerifier:
    def __init__(self, trusted_head):
        self.trusted_head = trusted_head
        self.failure = None

    def verify_head(self, head, expected_authority):
        if self.failure is not None:
            raise self.failure
        return (
            head == self.trusted_head
            and expected_authority == self.trusted_head.authority
            and head.signature == b"test-only-head-signature"
        )


class ExperimentalTrustedReceiptSignerTests(unittest.TestCase):
    def setUp(self):
        self.authority = AuthorityIdentity("authority-test", 1, "test-domain")
        self.event = ReservationEvent(
            authority=self.authority,
            sequence=1,
            event_id="committed-event-1",
            previous_event_hash=GENESIS_HASH,
            tenant_digest=_digest("tenant-a"),
            principal_digest=_digest("principal-a"),
            resource_digest=_digest("resource-a"),
            request_id_digest=_digest("request-a"),
            request_digest=_digest("request-digest-a"),
            period="2026-10",
            policy_version="policy-7",
        )
        self.head = AuthenticatedAuthorityHead(
            authority=self.authority,
            sequence=self.event.sequence,
            event_hash=self.event.event_hash,
            signing_key_id="head-key-v1",
            signature=b"test-only-head-signature",
            evidence_class=EvidenceClass.AUTHENTICATED,
        )
        self.evidence = CommittedReservationEvidence(
            event=self.event,
            stored_event_hash=self.event.event_hash,
            commit_state=CommitState.COMMITTED,
            authority_head=self.head,
        )
        self.provider = _ReadOnlyTestEvidenceProvider(self.evidence)
        self.head_verifier = _TestAuthorityHeadVerifier(self.head)
        self.signing_key = _EphemeralTestSigningKey()
        self.signing_key_id = "test-signer-v1"
        self.signer = self.make_signer()

    def make_signer(self, **changes):
        configuration = {
            "authority": self.authority,
            "signing_key_id": self.signing_key_id,
            "trusted_signer_ids": {self.signing_key_id},
            "revoked_signer_ids": set(),
            "signing_key": self.signing_key,
            "evidence_provider": self.provider,
            "head_verifier": self.head_verifier,
            "evidence_timeout_seconds": 1.0,
        }
        configuration.update(changes)
        return ExperimentalTrustedReceiptSigner(**configuration)

    def result(self, status=ReservationStatus.RESERVED, event=None):
        event = self.event if event is None else event
        unsigned = AuthorityReceipt(
            authority=event.authority,
            status=status,
            event=event,
            signing_key_id=None,
            signature=None,
            evidence_class=EvidenceClass.UNAUTHENTICATED,
        )
        return ReservationResult(status, CommitState.COMMITTED, unsigned)

    def expected(self, status=ReservationStatus.RESERVED, **changes):
        context = ExpectedReceiptContext(
            authority=self.authority,
            status=status,
            tenant_digest=self.event.tenant_digest,
            principal_digest=self.event.principal_digest,
            request_id_digest=self.event.request_id_digest,
            request_digest=self.event.request_digest,
            resource_digest=self.event.resource_digest,
            policy_version=self.event.policy_version,
            signing_key_ids=frozenset({self.signing_key_id}),
        )
        return replace(context, **changes) if changes else context

    def test_committed_event_signs_and_existing_verifier_accepts_exact_envelope(self):
        signed = self.signer.sign_committed_result(
            self.result(), self.expected()
        )
        self.assertIsNotNone(signed)
        self.assertEqual(signed.evidence_class, EvidenceClass.AUTHENTICATED)
        self.assertEqual(self.provider.calls, [(self.event.event_id, 1.0)])

        verifier = Ed25519ReceiptVerifier(
            authority=self.authority,
            trusted_public_keys={self.signing_key_id: self.signing_key.public_key_bytes},
        )
        self.assertTrue(
            verify_authenticated_receipt(signed, self.expected(), verifier)
        )

    def test_repeat_signing_is_deterministic_and_context_bound(self):
        result = self.result()
        expected = self.expected()
        first = self.signer.sign_committed_result(result, expected)
        second = self.signer.sign_committed_result(result, expected)
        self.assertEqual(first.canonical_envelope_bytes(), second.canonical_envelope_bytes())
        self.assertEqual(first.signature, second.signature)
        self.assertIsNone(
            self.signer.sign_committed_result(
                result, self.expected(request_digest="f" * 64)
            )
        )

    def test_replay_is_signed_as_replay_and_never_as_reserved(self):
        replay_result = self.result(ReservationStatus.REPLAY)
        replay_expected = self.expected(ReservationStatus.REPLAY)
        signed_replay = self.signer.sign_committed_result(
            replay_result, replay_expected
        )
        self.assertIsNotNone(signed_replay)
        self.assertIs(signed_replay.status, ReservationStatus.REPLAY)

        verifier = Ed25519ReceiptVerifier(
            authority=self.authority,
            trusted_public_keys={self.signing_key_id: self.signing_key.public_key_bytes},
        )
        self.assertTrue(
            verify_authenticated_receipt(signed_replay, replay_expected, verifier)
        )
        self.assertFalse(
            verify_authenticated_receipt(
                signed_replay, self.expected(ReservationStatus.RESERVED), verifier
            )
        )
        self.assertFalse(hasattr(self.signer, "reserve"))

    def test_arbitrary_uncommitted_and_ambiguous_results_are_rejected(self):
        self.assertIsNone(
            self.signer.sign_committed_result(self.result().receipt, self.expected())
        )
        self.assertIsNone(
            self.signer.sign_committed_result(object(), self.expected())
        )

        client_signed_receipt = replace(
            self.result().receipt,
            signing_key_id="client-key",
            signature=b"x" * 64,
            evidence_class=EvidenceClass.AUTHENTICATED,
        )
        client_signed_result = ReservationResult(
            ReservationStatus.RESERVED,
            CommitState.COMMITTED,
            client_signed_receipt,
        )
        self.assertIsNone(
            self.signer.sign_committed_result(client_signed_result, self.expected())
        )

        arbitrary_event = replace(self.event, event_id="client-invented-event")
        self.assertIsNone(
            self.signer.sign_committed_result(
                self.result(event=arbitrary_event), self.expected()
            )
        )

        self.provider.evidence = replace(
            self.evidence, commit_state=CommitState.NOT_COMMITTED
        )
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        self.provider.evidence = self.evidence
        ambiguous = ReservationResult(
            ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.UNKNOWN
        )
        self.assertIsNone(
            self.signer.sign_committed_result(ambiguous, self.expected())
        )

    def test_event_hash_sequence_and_authority_epoch_mismatches_reject(self):
        self.provider.evidence = replace(
            self.evidence, stored_event_hash="0" * 64
        )
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        wrong_sequence_event = replace(self.event, sequence=2)
        self.provider.evidence = replace(
            self.evidence,
            event=wrong_sequence_event,
            stored_event_hash=wrong_sequence_event.event_hash,
        )
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        wrong_authority_event = replace(
            self.event,
            authority=AuthorityIdentity("authority-test", 2, "test-domain"),
        )
        self.provider.evidence = replace(
            self.evidence,
            event=wrong_authority_event,
            stored_event_hash=wrong_authority_event.event_hash,
        )
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        self.provider.evidence = self.evidence
        self.assertIsNone(
            self.signer.sign_committed_result(
                self.result(),
                self.expected(
                    authority=AuthorityIdentity("authority-test", 2, "test-domain")
                ),
            )
        )

    def test_tenant_principal_request_resource_and_policy_mismatches_reject(self):
        for field in (
            "tenant_digest",
            "principal_digest",
            "request_id_digest",
            "request_digest",
            "resource_digest",
        ):
            with self.subTest(field=field):
                self.assertIsNone(
                    self.signer.sign_committed_result(
                        self.result(), self.expected(**{field: "f" * 64})
                    )
                )
        self.assertIsNone(
            self.signer.sign_committed_result(
                self.result(), self.expected(policy_version="policy-other")
            )
        )

    def test_missing_stale_invalid_or_untrusted_head_rejects(self):
        self.provider.evidence = replace(self.evidence, authority_head=None)
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        stale_head = replace(self.head, sequence=2)
        self.provider.evidence = replace(self.evidence, authority_head=stale_head)
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        test_only_head = replace(self.head, evidence_class=EvidenceClass.TEST_ONLY)
        self.provider.evidence = replace(
            self.evidence, authority_head=test_only_head
        )
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        self.provider.evidence = self.evidence
        self.head_verifier.failure = RuntimeError("head trust unavailable")
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

        class RejectingHeadVerifier:
            def verify_head(self, head, expected_authority):
                return False

        self.head_verifier.failure = None
        rejecting_signer = self.make_signer(
            head_verifier=RejectingHeadVerifier()
        )
        self.assertIsNone(
            rejecting_signer.sign_committed_result(self.result(), self.expected())
        )

    def test_provider_failure_timeout_and_missing_event_fail_closed(self):
        self.provider.failure = TimeoutError("provider deadline exceeded")
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )
        self.provider.failure = OSError("database unavailable")
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )
        self.provider.failure = None
        self.provider.evidence = None
        self.assertIsNone(
            self.signer.sign_committed_result(self.result(), self.expected())
        )

    def test_unknown_or_revoked_signer_identity_and_missing_purpose_reject(self):
        with self.assertRaises(ValueError):
            self.make_signer(trusted_signer_ids={"other-key"})
        with self.assertRaises(ValueError):
            self.make_signer(revoked_signer_ids={self.signing_key_id})
        with self.assertRaises(ValueError):
            replace(self.expected(), purpose="execution_grant")

        self.assertIsNone(
            self.signer.sign_committed_result(
                self.result(),
                self.expected(signing_key_ids=frozenset({"unknown-key"})),
            )
        )

    def test_signing_key_failure_or_malformed_signature_fails_closed(self):
        class RaisingSigningKey:
            def sign(self, data):
                raise RuntimeError("test signer failure")

        class MalformedSigningKey:
            def sign(self, data):
                return b"short"

        for signing_key in (RaisingSigningKey(), MalformedSigningKey()):
            with self.subTest(signing_key=type(signing_key).__name__):
                signer = self.make_signer(signing_key=signing_key)
                self.assertIsNone(
                    signer.sign_committed_result(self.result(), self.expected())
                )

    def test_signer_has_no_reservation_or_database_write_interface(self):
        self.assertFalse(hasattr(self.signer, "reserve"))
        self.assertFalse(hasattr(self.signer, "_apply"))
        self.assertFalse(hasattr(self.signer, "connection_factory"))


if __name__ == "__main__":
    unittest.main()
