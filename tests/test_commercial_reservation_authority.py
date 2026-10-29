import hashlib
import hmac
import threading
import unittest
from collections import Counter
from dataclasses import replace

from gvai.commercial_reservation_authority import (
    AuthorityCredentialRecord,
    AuthorityIdentity,
    AuthenticatedAuthorityHead,
    AuthorityReceipt,
    CanonicalReservationRequest,
    CommitState,
    CredentialStatus,
    EvidenceClass,
    ExpectedReceiptContext,
    GENESIS_HASH,
    MAX_EVALUATION_INPUT_BYTES,
    MonthlyQuotaPolicy,
    ReservationEvent,
    ReservationStatus,
    ResourceOwnership,
    ReservationResult,
    SUPPORTED_RESERVATION_RESOURCE_KINDS,
    payload_digest_for_bounded_input,
    verify_authenticated_receipt,
)
from gvai.effects import make_action
from gvai.external_control import GVExternalControlPlane


_TEST_SIGNING_KEY = b"test-only-reservation-receipt-key"


class _TestReceiptHmac:
    """Test-only signing fixture; not a production authority or key provider."""

    key_id = "test-hmac-v1"

    @classmethod
    def sign(cls, receipt):
        unsigned = replace(
            receipt,
            signing_key_id=cls.key_id,
            signature=b"placeholder",
            evidence_class=EvidenceClass.AUTHENTICATED,
        )
        signature = hmac.new(
            _TEST_SIGNING_KEY,
            unsigned.canonical_envelope_bytes(),
            hashlib.sha256,
        ).digest()
        return replace(unsigned, signature=signature)

    def verify_receipt(self, envelope, signature, signing_key_id, expected_authority):
        return (
            signing_key_id == self.key_id
            and hmac.compare_digest(
                signature,
                hmac.new(_TEST_SIGNING_KEY, envelope, hashlib.sha256).digest(),
            )
        )


class _FakeReservationAuthority:
    """Test-only atomic model. It has no production persistence or signature."""

    def __init__(self, *, identity, credentials, ownership, policies, clock):
        self.identity = identity
        self.credentials = credentials.copy()
        self.ownership = ownership.copy()
        self.policies = policies.copy()
        self.clock = clock
        self.events = []
        self._idempotency = {}
        self._lock = threading.Lock()
        self.unavailable = False
        self.lose_next_acknowledgement = False

    def reserve(self, request, credential):
        if self.unavailable:
            return self._result(
                ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.UNKNOWN
            )
        if (
            type(request) is not CanonicalReservationRequest
            or type(credential) is not str
            or not 1 <= len(credential) <= 4096
        ):
            return self._result(ReservationStatus.UNAUTHORIZED, CommitState.NOT_COMMITTED)

        with self._lock:
            if self.unavailable:
                return self._result(
                    ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.UNKNOWN
                )
            identity = self.credentials.get(credential)
            if (
                type(identity) is not AuthorityCredentialRecord
                or identity.status is not CredentialStatus.ACTIVE
            ):
                return self._result(ReservationStatus.UNAUTHORIZED, CommitState.NOT_COMMITTED)

            owner = self.ownership.get(request.resource_id)
            if (
                type(owner) is not ResourceOwnership
                or owner.resource_id != request.resource_id
                or owner.tenant_id != identity.tenant_id
                or owner.resource_kind not in SUPPORTED_RESERVATION_RESOURCE_KINDS
            ):
                return self._result(ReservationStatus.UNAUTHORIZED, CommitState.NOT_COMMITTED)

            policy = self.policies.get(identity.tenant_id)
            if (
                type(policy) is not MonthlyQuotaPolicy
                or policy.tenant_id != identity.tenant_id
            ):
                return self._result(ReservationStatus.UNAUTHORIZED, CommitState.NOT_COMMITTED)
            period = self.clock()
            if type(period) is not str or len(period) != 7:
                return self._result(ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.UNKNOWN)

            request_id_digest = self._digest(request.request_id)
            key = identity.tenant_id, request_id_digest
            existing = self._idempotency.get(key)
            if existing is not None:
                old_request_digest, event = existing
                if old_request_digest != request.request_digest:
                    return self._result(ReservationStatus.CONFLICT, CommitState.NOT_COMMITTED)
                receipt = self._receipt(ReservationStatus.REPLAY, event)
                return ReservationResult(
                    ReservationStatus.REPLAY, CommitState.COMMITTED, receipt
                )

            consumed = sum(
                event.period == period and event.tenant_digest == self._digest(identity.tenant_id)
                for event in self.events
            )
            if consumed >= policy.monthly_allowance:
                return self._result(ReservationStatus.QUOTA_EXCEEDED, CommitState.NOT_COMMITTED)

            previous_hash = self.events[-1].event_hash if self.events else GENESIS_HASH
            sequence = len(self.events) + 1
            event = ReservationEvent(
                authority=self.identity,
                sequence=sequence,
                event_id="test-event-%08d" % sequence,
                previous_event_hash=previous_hash,
                tenant_digest=self._digest(identity.tenant_id),
                principal_digest=self._digest(identity.principal_id),
                resource_digest=self._digest(request.resource_id),
                request_id_digest=request_id_digest,
                request_digest=request.request_digest,
                period=period,
                policy_version=policy.policy_version,
            )
            self.events.append(event)
            self._idempotency[key] = (request.request_digest, event)

            if self.lose_next_acknowledgement:
                self.lose_next_acknowledgement = False
                return self._result(
                    ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.UNKNOWN
                )
            receipt = self._receipt(ReservationStatus.RESERVED, event)
            return ReservationResult(ReservationStatus.RESERVED, CommitState.COMMITTED, receipt)

    def read_authenticated_head(self):
        if self.unavailable:
            raise OSError("test-only authority unavailable")
        sequence = self.events[-1].sequence if self.events else 0
        event_hash = self.events[-1].event_hash if self.events else GENESIS_HASH
        return AuthenticatedAuthorityHead(
            authority=self.identity,
            sequence=sequence,
            event_hash=event_hash,
            signing_key_id="test-key-v1",
            signature=b"test-only-not-a-signature",
            evidence_class=EvidenceClass.TEST_ONLY,
        )

    def _receipt(self, status, event):
        return AuthorityReceipt(
            authority=self.identity,
            status=status,
            event=event,
            signing_key_id=None,
            signature=None,
            evidence_class=EvidenceClass.TEST_ONLY,
        )

    @staticmethod
    def _result(status, commit_state):
        return ReservationResult(status, commit_state)

    @staticmethod
    def _digest(value):
        return hashlib.sha256(value.encode("ascii")).hexdigest()


class ReservationAuthorityContractTests(unittest.TestCase):
    def setUp(self):
        self.now = ["2026-10"]
        self.identity = AuthorityIdentity("authority-test", 1, "test-domain")
        self.credentials = {
            "credential-a": AuthorityCredentialRecord(
                "principal-a", "tenant-a", CredentialStatus.ACTIVE
            ),
            "credential-b": AuthorityCredentialRecord(
                "principal-b", "tenant-b", CredentialStatus.ACTIVE
            ),
        }
        self.ownership = {
            "resource-a": ResourceOwnership("resource-a", "tenant-a", "evaluation"),
            "resource-b": ResourceOwnership("resource-b", "tenant-b", "evaluation"),
        }
        self.policies = {
            "tenant-a": MonthlyQuotaPolicy("tenant-a", "policy-7", 2),
            "tenant-b": MonthlyQuotaPolicy("tenant-b", "policy-3", 1),
        }
        self.authority = _FakeReservationAuthority(
            identity=self.identity,
            credentials=self.credentials,
            ownership=self.ownership,
            policies=self.policies,
            clock=lambda: self.now[0],
        )

    def request(self, request_id="request-1", resource_id="resource-a", payload=None):
        bounded_input = b"exact bounded test evaluation input" if payload is None else payload
        return CanonicalReservationRequest.from_bounded_input(
            request_id, resource_id, bounded_input
        )

    def expected_receipt_context(self, receipt, status=None, **changes):
        event = receipt.event
        context = ExpectedReceiptContext(
            authority=self.identity,
            status=receipt.status if status is None else status,
            tenant_digest=event.tenant_digest,
            principal_digest=event.principal_digest,
            request_id_digest=event.request_id_digest,
            request_digest=event.request_digest,
            resource_digest=event.resource_digest,
            policy_version=event.policy_version,
            signing_key_ids=frozenset({"test-key-v1"}),
        )
        return replace(context, **changes) if changes else context

    def authenticated_receipt(self, result, *, status=None, signing_key_id="test-key-v1", signature=b"test-signature"):
        return AuthorityReceipt(
            self.identity,
            result.status if status is None else status,
            result.receipt.event,
            signing_key_id,
            signature,
            EvidenceClass.AUTHENTICATED,
        )

    def test_first_valid_reservation_uses_authority_owned_context(self):
        request = self.request()
        result = self.authority.reserve(request, "credential-a")
        self.assertEqual(result.status, ReservationStatus.RESERVED)
        self.assertEqual(result.commit_state, CommitState.COMMITTED)
        self.assertEqual(result.receipt.evidence_class, EvidenceClass.TEST_ONLY)
        event = result.receipt.event
        self.assertEqual(event.authority, self.identity)
        self.assertEqual(event.sequence, 1)
        self.assertEqual(event.previous_event_hash, GENESIS_HASH)
        self.assertEqual(event.policy_version, "policy-7")
        self.assertFalse(hasattr(request, "tenant_id"))
        self.assertNotIn(b"credential-a", event.canonical_bytes())

    def test_exact_request_replay_never_becomes_a_new_reservation(self):
        request = self.request()
        first = self.authority.reserve(request, "credential-a")
        replay = self.authority.reserve(request, "credential-a")
        self.assertEqual(first.status, ReservationStatus.RESERVED)
        self.assertEqual(replay.status, ReservationStatus.REPLAY)
        self.assertEqual(first.receipt.event.event_id, replay.receipt.event.event_id)
        self.assertEqual(len(self.authority.events), 1)

    def test_changed_contents_for_same_tenant_request_id_conflict(self):
        self.authority.reserve(self.request(), "credential-a")
        conflict = self.authority.reserve(
            self.request(payload=b"different bounded evaluation input"), "credential-a"
        )
        self.assertEqual(conflict.status, ReservationStatus.CONFLICT)
        self.assertEqual(len(self.authority.events), 1)

    def test_monthly_quota_exhaustion_and_period_transition(self):
        self.assertEqual(
            self.authority.reserve(self.request("one"), "credential-a").status,
            ReservationStatus.RESERVED,
        )
        self.assertEqual(
            self.authority.reserve(self.request("two"), "credential-a").status,
            ReservationStatus.RESERVED,
        )
        self.assertEqual(
            self.authority.reserve(self.request("three"), "credential-a").status,
            ReservationStatus.QUOTA_EXCEEDED,
        )
        self.now[0] = "2026-11"
        self.assertEqual(
            self.authority.reserve(self.request("november"), "credential-a").status,
            ReservationStatus.RESERVED,
        )

    def test_concurrent_same_id_commits_one_reservation(self):
        request = self.request()
        results = []
        result_lock = threading.Lock()

        def reserve_once():
            result = self.authority.reserve(request, "credential-a")
            with result_lock:
                results.append(result)

        threads = [threading.Thread(target=reserve_once) for _ in range(32)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(Counter(result.status for result in results), {
            ReservationStatus.RESERVED: 1,
            ReservationStatus.REPLAY: 31,
        })
        self.assertEqual(len(self.authority.events), 1)

    def test_concurrent_distinct_requests_cannot_exceed_quota(self):
        results = []
        result_lock = threading.Lock()

        def reserve_index(index):
            result = self.authority.reserve(
                self.request("request-%02d" % index), "credential-a"
            )
            with result_lock:
                results.append(result)

        threads = [threading.Thread(target=reserve_index, args=(index,)) for index in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(
            sum(result.status is ReservationStatus.RESERVED for result in results), 2
        )
        self.assertEqual(
            sum(result.status is ReservationStatus.QUOTA_EXCEEDED for result in results), 22
        )
        self.assertEqual(len(self.authority.events), 2)

    def test_cross_tenant_same_request_id_is_independent(self):
        self.assertEqual(
            self.authority.reserve(self.request("shared", "resource-a"), "credential-a").status,
            ReservationStatus.RESERVED,
        )
        self.assertEqual(
            self.authority.reserve(self.request("shared", "resource-b"), "credential-b").status,
            ReservationStatus.RESERVED,
        )
        self.assertNotEqual(
            self.authority.events[0].tenant_digest,
            self.authority.events[1].tenant_digest,
        )

    def test_revocation_and_ownership_reassignment_deny(self):
        self.authority.credentials["credential-a"] = AuthorityCredentialRecord(
            "principal-a", "tenant-a", CredentialStatus.REVOKED
        )
        self.assertEqual(
            self.authority.reserve(self.request(), "credential-a").status,
            ReservationStatus.UNAUTHORIZED,
        )
        self.authority.credentials["credential-a"] = AuthorityCredentialRecord(
            "principal-a", "tenant-a", CredentialStatus.ACTIVE
        )
        self.authority.ownership["resource-a"] = ResourceOwnership(
            "resource-a", "tenant-b", "evaluation"
        )
        self.assertEqual(
            self.authority.reserve(self.request("reassigned"), "credential-a").status,
            ReservationStatus.UNAUTHORIZED,
        )
        self.authority.ownership["resource-a"] = ResourceOwnership(
            "resource-a", "tenant-a", "admin"
        )
        self.assertEqual(
            self.authority.reserve(self.request("unsupported-kind"), "credential-a").status,
            ReservationStatus.UNAUTHORIZED,
        )
        self.authority.ownership["resource-a"] = ResourceOwnership(
            "resource-a", "tenant-a", "evaluation"
        )
        self.authority.policies["tenant-a"] = MonthlyQuotaPolicy(
            "tenant-b", "wrong-tenant-policy", 99
        )
        self.assertEqual(
            self.authority.reserve(self.request("wrong-policy-tenant"), "credential-a").status,
            ReservationStatus.UNAUTHORIZED,
        )

    def test_unavailable_authority_does_not_fall_back(self):
        self.authority.unavailable = True
        result = self.authority.reserve(self.request(), "credential-a")
        self.assertEqual(result.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        self.assertEqual(result.commit_state, CommitState.UNKNOWN)
        self.assertEqual(self.authority.events, [])

    def test_unknown_commit_and_lost_ack_retry_as_replay(self):
        self.authority.lose_next_acknowledgement = True
        first = self.authority.reserve(self.request(), "credential-a")
        self.assertEqual(first.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        self.assertEqual(first.commit_state, CommitState.UNKNOWN)
        self.assertEqual(len(self.authority.events), 1)
        retry = self.authority.reserve(self.request(), "credential-a")
        self.assertEqual(retry.status, ReservationStatus.REPLAY)
        self.assertEqual(retry.receipt.event.sequence, 1)
        self.assertEqual(len(self.authority.events), 1)

    def test_event_hash_chain_and_test_evidence_are_not_authenticated(self):
        first = self.authority.reserve(self.request("one"), "credential-a")
        second = self.authority.reserve(self.request("two"), "credential-a")
        self.assertEqual(second.receipt.event.previous_event_hash, first.receipt.event.event_hash)
        self.assertEqual(first.receipt.evidence_class, EvidenceClass.TEST_ONLY)
        self.assertIsNone(first.receipt.signature)
        head = self.authority.read_authenticated_head()
        self.assertEqual(head.evidence_class, EvidenceClass.TEST_ONLY)
        self.assertEqual(head.signature, b"test-only-not-a-signature")
        self.assertFalse(hasattr(self.authority, "verify_receipt"))

    def test_receipt_verifier_rejects_test_evidence_and_binds_expected_context(self):
        result = self.authority.reserve(self.request(), "credential-a")

        class PermissiveTestVerifier:
            def __init__(self):
                self.calls = []

            def verify_receipt(self, envelope, signature, signing_key_id, expected_authority):
                self.calls.append((envelope, signature, signing_key_id, expected_authority))
                return True

        verifier = PermissiveTestVerifier()
        expected = self.expected_receipt_context(result.receipt)
        self.assertFalse(
            verify_authenticated_receipt(
                result.receipt, expected, verifier
            )
        )
        self.assertEqual(verifier.calls, [])

        authenticated_receipt = self.authenticated_receipt(result)
        self.assertTrue(
            verify_authenticated_receipt(
                authenticated_receipt, expected, verifier
            )
        )
        self.assertEqual(len(verifier.calls), 1)
        self.assertEqual(
            verifier.calls[0][0], authenticated_receipt.canonical_envelope_bytes()
        )

    def test_receipt_context_mismatches_reject_before_permissive_verifier(self):
        result = self.authority.reserve(self.request(), "credential-a")
        receipt = self.authenticated_receipt(result)

        class CountingVerifier:
            def __init__(self):
                self.calls = 0

            def verify_receipt(self, envelope, signature, signing_key_id, expected_authority):
                self.calls += 1
                return True

        context = self.expected_receipt_context(receipt)
        mismatches = (
            replace(context, status=ReservationStatus.REPLAY),
            replace(context, authority=AuthorityIdentity("other-authority", 1, "test-domain")),
            replace(context, authority=AuthorityIdentity("authority-test", 2, "test-domain")),
            replace(context, tenant_digest="b" * 64),
            replace(context, principal_digest="b" * 64),
            replace(context, request_id_digest="b" * 64),
            replace(context, request_digest="b" * 64),
            replace(context, resource_digest="b" * 64),
            replace(context, policy_version="different-policy"),
            replace(context, signing_key_ids=frozenset({"different-key"})),
        )
        for mismatch in mismatches:
            with self.subTest(mismatch=mismatch):
                verifier = CountingVerifier()
                self.assertFalse(verify_authenticated_receipt(receipt, mismatch, verifier))
                self.assertEqual(verifier.calls, 0)

        substituted_key = replace(receipt, signing_key_id="other-key")
        verifier = CountingVerifier()
        self.assertFalse(verify_authenticated_receipt(substituted_key, context, verifier))
        self.assertEqual(verifier.calls, 0)
        with self.assertRaises(ValueError):
            replace(context, evidence_version=2)
        with self.assertRaises(ValueError):
            replace(context, purpose="head_read")

    def test_verifier_lookup_failure_fails_closed(self):
        result = self.authority.reserve(self.request(), "credential-a")
        receipt = self.authenticated_receipt(result)
        context = replace(
            self.expected_receipt_context(receipt),
            signing_key_ids=frozenset({"test-key-v1"}),
        )

        class RaisingVerifier:
            @property
            def verify_receipt(self):
                raise RuntimeError("test-only lookup failure")

        self.assertFalse(verify_authenticated_receipt(receipt, context, RaisingVerifier()))

    def test_replay_to_reserved_substitution_changes_envelope_and_is_rejected(self):
        request = self.request()
        reserved_result = self.authority.reserve(request, "credential-a")
        replay_result = self.authority.reserve(request, "credential-a")
        reserved = _TestReceiptHmac.sign(reserved_result.receipt)
        replay = _TestReceiptHmac.sign(replay_result.receipt)
        self.assertEqual(replay.status, ReservationStatus.REPLAY)
        self.assertEqual(reserved.event.event_id, replay.event.event_id)
        self.assertNotEqual(
            reserved.canonical_envelope_bytes(), replay.canonical_envelope_bytes()
        )

        expected_replay = replace(
            self.expected_receipt_context(replay),
            signing_key_ids=frozenset({_TestReceiptHmac.key_id}),
        )
        self.assertTrue(
            verify_authenticated_receipt(replay, expected_replay, _TestReceiptHmac())
        )
        substituted = replace(replay, status=ReservationStatus.RESERVED)
        expected_reserved = replace(expected_replay, status=ReservationStatus.RESERVED)
        self.assertFalse(
            verify_authenticated_receipt(
                substituted, expected_reserved, _TestReceiptHmac()
            )
        )

    def test_evidence_class_relabel_changes_canonical_envelope(self):
        result = self.authority.reserve(self.request(), "credential-a")
        test_receipt = result.receipt
        relabeled = replace(
            test_receipt,
            signing_key_id="test-key-v1",
            signature=b"test-signature",
            evidence_class=EvidenceClass.AUTHENTICATED,
        )
        self.assertNotEqual(
            test_receipt.canonical_envelope_bytes(),
            relabeled.canonical_envelope_bytes(),
        )

    def test_fabricated_receipt_and_missing_or_malformed_signature_reject(self):
        class ForgedReceipt:
            status = ReservationStatus.RESERVED

        with self.assertRaises(ValueError):
            ReservationResult(
                ReservationStatus.RESERVED, CommitState.COMMITTED, ForgedReceipt()
            )

        result = self.authority.reserve(self.request(), "credential-a")
        with self.assertRaises(ValueError):
            AuthorityReceipt(
                self.identity,
                ReservationStatus.RESERVED,
                result.receipt.event,
                "key-1",
                None,
                EvidenceClass.AUTHENTICATED,
            )
        with self.assertRaises(ValueError):
            self.authenticated_receipt(result, signature=b"x" * 513)
        with self.assertRaises(ValueError):
            AuthorityReceipt(
                self.identity,
                ReservationStatus.RESERVED,
                result.receipt.event,
                7,
                b"signature",
                EvidenceClass.AUTHENTICATED,
            )

    def test_payload_digest_is_derived_from_exact_bounded_input(self):
        payload = b"exact bytes consumed by a trusted evaluator"
        request = CanonicalReservationRequest.from_bounded_input(
            "payload-test", "resource-a", payload
        )
        self.assertEqual(
            request.payload_digest, payload_digest_for_bounded_input(payload)
        )
        self.assertNotEqual(
            request.payload_digest,
            payload_digest_for_bounded_input(payload + b" changed"),
        )
        with self.assertRaises(ValueError):
            payload_digest_for_bounded_input("customer supplied digest")
        with self.assertRaises(ValueError):
            payload_digest_for_bounded_input(b"x" * (MAX_EVALUATION_INPUT_BYTES + 1))

    def test_inconsistent_status_and_commit_shapes_are_rejected(self):
        for status, commit_state in (
            (ReservationStatus.RESERVED, CommitState.UNKNOWN),
            (ReservationStatus.CONFLICT, CommitState.UNKNOWN),
            (ReservationStatus.QUOTA_EXCEEDED, CommitState.COMMITTED),
            (ReservationStatus.AUTHORITY_UNAVAILABLE, CommitState.COMMITTED),
        ):
            with self.subTest(status=status, commit_state=commit_state):
                with self.assertRaises(ValueError):
                    ReservationResult(status, commit_state)

    def test_request_validation_and_no_service_registration(self):
        for args in (
            ("bad/id", "resource-a", "a" * 64),
            ("request", "resource-a", "not-a-digest"),
            ("x" * 129, "resource-a", "a" * 64),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                CanonicalReservationRequest(*args)
        request = self.request()
        self.assertNotIn("tenant_id", request.canonical_bytes().decode("ascii"))
        self.assertFalse(hasattr(self.authority, "_apply"))

    def test_supervisor_stop_independent_when_authority_unavailable(self):
        self.authority.unavailable = True
        result = self.authority.reserve(self.request(), "credential-a")
        self.assertEqual(result.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        action = make_action("test-only", {"low_impact"})
        self.assertTrue(GVExternalControlPlane().evaluate_internal_shutdown(action).halted)


if __name__ == "__main__":
    unittest.main()
