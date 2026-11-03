from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import threading
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    GENESIS_HASH,
    MAX_EVALUATION_UNITS,
    ReservationEvent,
)
from gvai.experimental_authority_head import (
    AuthorityHeadCheckpoint,
    AuthorityHeadState,
    CHECKPOINT_DOMAIN,
    ExperimentalAuthorityHeadVerifier,
)


class _InMemoryTestHighWater:
    """Process-local test fake, not durable independent rollback protection."""

    def __init__(self, initial):
        self.state = initial
        self.lock = threading.Lock()
        self.calls = []
        self.failure = None

    def check_and_advance(self, checkpoint, *, timeout_seconds):
        with self.lock:
            self.calls.append((checkpoint, timeout_seconds))
            if self.failure is not None:
                raise self.failure
            candidate = checkpoint.head
            if self.state is None or candidate.authority != self.state.authority:
                return None
            if candidate.sequence < self.state.sequence:
                return None
            if candidate.sequence == self.state.sequence and candidate.event_hash != self.state.event_hash:
                return None
            self.state = candidate
            return self.state


class ExperimentalAuthorityHeadTests(unittest.TestCase):
    def setUp(self):
        self.authority = AuthorityIdentity("authority-test", 1, "independent-test-domain")
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        digest = hashlib.sha256(b"test-only-event-context").hexdigest()
        self.event = ReservationEvent(
            authority=self.authority,
            sequence=7,
            event_id="test-event-7",
            previous_event_hash=digest,
            tenant_digest=digest,
            principal_digest=digest,
            resource_digest=digest,
            request_id_digest=digest,
            request_digest=digest,
            period="2026-11",
            policy_version="test-policy-1",
        )
        self.head = AuthorityHeadState(self.authority, 7, self.event.event_hash)
        self.provider = _InMemoryTestHighWater(self.head)
        self.verifier = self.make_verifier()
        self.checkpoint = self.sign(self.head)

    def make_verifier(self, **changes):
        configuration = {
            "authority": self.authority,
            "checkpoint_public_keys": {"checkpoint-test-key": self.public_key},
            "independent_high_water": self.provider,
            "other_purpose_key_ids": frozenset(),
            "other_purpose_public_keys": frozenset(),
        }
        configuration.update(changes)
        return ExperimentalAuthorityHeadVerifier(**configuration)

    def sign(self, head, key=None, key_id="checkpoint-test-key"):
        unsigned = AuthorityHeadCheckpoint(head, key_id, b"\x00" * 64)
        signing_key = self.key if key is None else key
        return replace(unsigned, signature=signing_key.sign(unsigned.canonical_bytes()))

    def test_valid_checkpoint(self):
        result = self.verifier.verify_checkpoint(self.checkpoint, self.head)
        self.assertTrue(result.signature_authentic)
        self.assertTrue(result.database_consistent)
        self.assertTrue(result.high_water_confirmed)
        self.assertTrue(result.accepted)
        self.assertEqual(self.provider.calls, [(self.checkpoint, 2.0)])

    def test_forged_checkpoint_never_reaches_provider(self):
        forged = self.sign(self.head, key=Ed25519PrivateKey.generate())
        self.assertFalse(self.verifier.verify_checkpoint(forged, self.head).accepted)
        self.assertEqual(self.provider.calls, [])

    def test_old_valid_snapshot_and_signature_are_not_fresh(self):
        old_head = replace(self.head, sequence=6, event_hash="b" * 64)
        old_checkpoint = self.sign(old_head)
        self.assertTrue(self.verifier.verify_signature(old_checkpoint))
        result = self.verifier.verify_checkpoint(old_checkpoint, old_head)
        self.assertTrue(result.signature_authentic)
        self.assertTrue(result.database_consistent)
        self.assertFalse(result.high_water_confirmed)
        self.assertFalse(result.accepted)
        self.assertEqual(self.provider.state, self.head)

    def test_missing_provider_fails_closed(self):
        verifier = self.make_verifier(independent_high_water=None)
        result = verifier.verify_checkpoint(self.checkpoint, self.head)
        self.assertTrue(result.signature_authentic)
        self.assertTrue(result.database_consistent)
        self.assertFalse(result.accepted)

    def test_missing_state_cannot_bootstrap_from_valid_checkpoint(self):
        self.provider.state = None
        self.assertFalse(self.verifier.verify_checkpoint(self.checkpoint, self.head).accepted)
        self.assertIsNone(self.provider.state)

    def test_equal_sequence_conflicting_signed_hash_rejects(self):
        conflicting = replace(self.head, event_hash="b" * 64)
        signed_conflict = self.sign(conflicting)
        self.assertTrue(self.verifier.verify_signature(signed_conflict))
        self.assertFalse(self.verifier.verify_checkpoint(signed_conflict, conflicting).accepted)
        self.assertEqual(self.provider.state, self.head)

    def test_monotonic_advance_then_old_checkpoint_rejects(self):
        newer = replace(self.head, sequence=8, event_hash="c" * 64)
        self.assertTrue(self.verifier.verify_checkpoint(self.sign(newer), newer).accepted)
        self.assertFalse(self.verifier.verify_checkpoint(self.checkpoint, self.head).accepted)
        self.assertEqual(self.provider.state, newer)

    def test_genesis_requires_explicit_trusted_state(self):
        genesis = AuthorityHeadState(self.authority, 0, GENESIS_HASH)
        self.provider.state = genesis
        self.assertTrue(self.verifier.verify_checkpoint(self.sign(genesis), genesis).accepted)
        self.provider.state = None
        self.assertFalse(self.verifier.verify_checkpoint(self.sign(genesis), genesis).accepted)

    def test_canonical_contract_exact_bytes_and_v1_hash_unchanged(self):
        expected = (
            b'{"authority_epoch":1,"authority_id":"authority-test","contract_version":1,'
            b'"event_head_hash":"' + self.event.event_hash.encode("ascii") +
            b'","purpose":"independent_authority_head","sequence":7,'
            b'"signature_algorithm":"Ed25519","signing_key_id":"checkpoint-test-key",'
            b'"trust_domain":"independent-test-domain"}'
        )
        self.assertEqual(self.checkpoint.canonical_bytes(), CHECKPOINT_DOMAIN + expected)
        self.assertEqual(
            self.head.event_hash,
            hashlib.sha256(b"gvai-reservation-event-v1\x00" + self.event.canonical_bytes()).hexdigest(),
        )
        self.assertEqual(
            json.loads(expected),
            json.loads(self.checkpoint.canonical_bytes()[len(CHECKPOINT_DOMAIN):]),
        )

    def test_wrong_key_unknown_key_and_revoked_key_reject(self):
        unknown = self.sign(self.head, key_id="unknown-checkpoint-key")
        revoked = self.make_verifier(revoked_key_ids={"checkpoint-test-key"})
        self.assertFalse(self.verifier.verify_signature(unknown))
        self.assertFalse(revoked.verify_signature(self.checkpoint))
        other_key = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        verifier = self.make_verifier(checkpoint_public_keys={"checkpoint-test-key": other_key})
        self.assertFalse(verifier.verify_signature(self.checkpoint))
        self.assertEqual(self.provider.calls, [])

    def test_wrong_authority_epoch_and_trust_domain_reject_even_if_signed(self):
        identities = (
            replace(self.authority, authority_id="other-authority"),
            replace(self.authority, epoch=2),
            replace(self.authority, trust_domain="other-domain"),
        )
        for authority in identities:
            with self.subTest(authority=authority):
                wrong = replace(self.head, authority=authority)
                self.assertFalse(self.verifier.verify_checkpoint(self.sign(wrong), wrong).accepted)
        self.assertEqual(self.provider.calls, [])

    def test_altered_sequence_hash_and_key_id_invalidate_signature(self):
        changes = (
            {"head": replace(self.head, sequence=8)},
            {"head": replace(self.head, event_hash="b" * 64)},
            {"signing_key_id": "unknown-checkpoint-key"},
        )
        for change in changes:
            with self.subTest(change=change):
                altered = replace(self.checkpoint, **change)
                self.assertFalse(self.verifier.verify_checkpoint(altered, altered.head).accepted)
        self.assertEqual(self.provider.calls, [])

    def test_old_checkpoint_cannot_match_current_database_head(self):
        old = self.sign(replace(self.head, sequence=6, event_hash="b" * 64))
        result = self.verifier.verify_checkpoint(old, self.head)
        self.assertTrue(result.signature_authentic)
        self.assertFalse(result.database_consistent)
        self.assertFalse(result.accepted)
        self.assertEqual(self.provider.calls, [])

    def test_current_checkpoint_cannot_match_old_or_conflicting_database(self):
        observations = (
            replace(self.head, sequence=6),
            replace(self.head, sequence=8),
            replace(self.head, event_hash="b" * 64),
            replace(self.head, authority=replace(self.authority, epoch=2)),
            None,
            True,
        )
        for observation in observations:
            with self.subTest(observation=observation):
                result = self.verifier.verify_checkpoint(self.checkpoint, observation)
                self.assertTrue(result.signature_authentic)
                self.assertFalse(result.database_consistent)
                self.assertFalse(result.accepted)
        self.assertEqual(self.provider.calls, [])

    def test_purpose_version_algorithm_substitution_reject_even_if_resigned(self):
        substitutions = (
            ("purpose", "reservation_decision"),
            ("purpose", "supervisor_command"),
            ("version", 2),
            ("version", True),
            ("signature_algorithm", "ed25519"),
            ("signature_algorithm", "RSA"),
        )
        for field, value in substitutions:
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    replace(self.checkpoint, **{field: value})
                altered = replace(self.checkpoint)
                object.__setattr__(altered, field, value)
                object.__setattr__(altered, "signature", self.key.sign(altered.canonical_bytes()))
                self.assertFalse(self.verifier.verify_checkpoint(altered, self.head).accepted)
        self.assertEqual(self.provider.calls, [])

    def test_other_domain_and_unsigned_json_signatures_reject(self):
        canonical_json = self.checkpoint.canonical_bytes()[len(CHECKPOINT_DOMAIN):]
        for envelope in (
            canonical_json,
            b"gvai-authority-receipt-envelope-v1\x00" + canonical_json,
        ):
            with self.subTest(envelope=envelope):
                wrong = replace(self.checkpoint, signature=self.key.sign(envelope))
                self.assertFalse(self.verifier.verify_signature(wrong))

    def test_malformed_hashes_sequences_and_signatures_reject(self):
        for event_hash in ("a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n", b"a" * 64, None):
            with self.subTest(event_hash=event_hash):
                with self.assertRaises(ValueError):
                    replace(self.head, event_hash=event_hash)
                malformed = replace(self.head)
                object.__setattr__(malformed, "event_hash", event_hash)
                self.assertFalse(self.verifier.verify_signature(replace(self.checkpoint, head=malformed)))
        for sequence in (-1, True, 7.0, MAX_EVALUATION_UNITS + 1):
            with self.subTest(sequence=sequence):
                with self.assertRaises(ValueError):
                    replace(self.head, sequence=sequence)
                malformed = replace(self.head)
                object.__setattr__(malformed, "sequence", sequence)
                self.assertFalse(self.verifier.verify_signature(replace(self.checkpoint, head=malformed)))
        for signature in (b"", b"a" * 63, b"a" * 65, "a" * 64, bytearray(64), None):
            with self.subTest(signature=signature):
                with self.assertRaises(ValueError):
                    replace(self.checkpoint, signature=signature)
                malformed = replace(self.checkpoint)
                object.__setattr__(malformed, "signature", signature)
                self.assertFalse(self.verifier.verify_signature(malformed))
        with self.assertRaises(ValueError):
            AuthorityHeadState(self.authority, 0, "a" * 64)
        self.assertEqual(self.provider.calls, [])

    def test_unavailable_provider_and_provider_errors_fail_closed(self):
        for failure in (TimeoutError("unavailable"), ConnectionError("offline"), RuntimeError("provider error")):
            with self.subTest(failure=failure):
                self.provider.failure = failure
                result = self.verifier.verify_checkpoint(self.checkpoint, self.head)
                self.assertTrue(result.signature_authentic)
                self.assertTrue(result.database_consistent)
                self.assertFalse(result.accepted)
                self.assertEqual(self.provider.state, self.head)

    def test_invalid_provider_responses_fail_closed(self):
        class ResponseProvider:
            def __init__(self, response):
                self.response = response

            def check_and_advance(self, checkpoint, *, timeout_seconds):
                return self.response

        malformed = replace(self.head)
        object.__setattr__(malformed, "event_hash", "invalid")
        responses = (
            None,
            True,
            self.checkpoint,
            replace(self.head, sequence=6),
            replace(self.head, sequence=8),
            replace(self.head, event_hash="b" * 64),
            replace(self.head, authority=replace(self.authority, epoch=2)),
            malformed,
        )
        for response in responses:
            with self.subTest(response=response):
                verifier = self.make_verifier(independent_high_water=ResponseProvider(response))
                self.assertFalse(verifier.verify_checkpoint(self.checkpoint, self.head).accepted)

    def test_provider_cannot_substitute_authenticated_checkpoint(self):
        substitutions = (
            ("sequence", 8),
            ("event_hash", "b" * 64),
            ("authority_id", "other-authority"),
            ("epoch", 2),
            ("trust_domain", "other-domain"),
            ("signature", b"\x00" * 64),
        )
        for mutation in ("replace_head", "mutate_nested"):
            for field, value in substitutions:
                with self.subTest(mutation=mutation, field=field):
                    calls = []

                    class SubstitutingProvider:
                        def check_and_advance(self, checkpoint, *, timeout_seconds):
                            calls.append(checkpoint)
                            if field == "signature":
                                object.__setattr__(checkpoint, field, value)
                            elif field in ("sequence", "event_hash"):
                                if mutation == "replace_head":
                                    object.__setattr__(checkpoint, "head", replace(checkpoint.head, **{field: value}))
                                else:
                                    object.__setattr__(checkpoint.head, field, value)
                            elif mutation == "replace_head":
                                authority = replace(checkpoint.head.authority, **{field: value})
                                object.__setattr__(checkpoint, "head", replace(checkpoint.head, authority=authority))
                            else:
                                object.__setattr__(checkpoint.head.authority, field, value)
                            return checkpoint.head

                    verifier = self.make_verifier(independent_high_water=SubstitutingProvider())
                    result = verifier.verify_checkpoint(self.checkpoint, self.head)
                    self.assertTrue(result.signature_authentic)
                    self.assertTrue(result.database_consistent)
                    self.assertFalse(result.high_water_confirmed)
                    self.assertFalse(result.accepted)
                    self.assertEqual(len(calls), 1)
                    self.assertIsNot(calls[0], self.checkpoint)
                    self.assertIsNot(calls[0].head, self.head)
                    self.assertIsNot(calls[0].head.authority, self.authority)
                    self.assertTrue(verifier.verify_signature(self.checkpoint))
                    self.assertEqual(self.checkpoint.head, self.head)
                    self.assertEqual(self.provider.state, self.head)

    def test_high_water_identity_cannot_be_replaced(self):
        for authority in (
            replace(self.authority, authority_id="other-authority"),
            replace(self.authority, epoch=2),
            replace(self.authority, trust_domain="other-domain"),
        ):
            with self.subTest(authority=authority):
                self.provider.state = replace(self.head, authority=authority)
                prior = self.provider.state
                self.assertFalse(self.verifier.verify_checkpoint(self.checkpoint, self.head).accepted)
                self.assertEqual(self.provider.state, prior)

    def test_cross_purpose_key_reuse_rejected_by_id_and_bytes(self):
        for exclusions in (
            {"other_purpose_key_ids": {"checkpoint-test-key"}},
            {"other_purpose_public_keys": {self.public_key}},
        ):
            with self.subTest(exclusions=exclusions):
                with self.assertRaises(ValueError):
                    self.make_verifier(**exclusions)

    def test_invalid_trust_configuration_rejects(self):
        configurations = (
            {"authority": None},
            {"checkpoint_public_keys": {}},
            {"checkpoint_public_keys": {"bad key": self.public_key}},
            {"checkpoint_public_keys": {"valid-key": b"x" * 31}},
            {"checkpoint_public_keys": {"valid-key": bytearray(32)}},
            {"checkpoint_public_keys": {"key-%s" % index: self.public_key for index in range(17)}},
            {"revoked_key_ids": {"bad key"}},
            {"revoked_key_ids": ["checkpoint-test-key"]},
            {"other_purpose_key_ids": None},
            {"other_purpose_public_keys": {b"x" * 31}},
            {"independent_high_water": object()},
            {"timeout_seconds": True},
            {"timeout_seconds": 0},
            {"timeout_seconds": 31},
            {"timeout_seconds": float("nan")},
            {"timeout_seconds": float("inf")},
        )
        for configuration in configurations:
            with self.subTest(configuration=configuration):
                with self.assertRaises(ValueError):
                    self.make_verifier(**configuration)

    def test_key_pins_and_revocations_are_copied_and_immutable(self):
        pins = {"checkpoint-test-key": self.public_key}
        revoked = set()
        verifier = self.make_verifier(checkpoint_public_keys=pins, revoked_key_ids=revoked)
        pins.clear()
        revoked.add("checkpoint-test-key")
        self.assertTrue(verifier.verify_signature(self.checkpoint))
        with self.assertRaises(AttributeError):
            verifier._provider = None
        with self.assertRaises(AttributeError):
            del verifier._authority
        with self.assertRaises(TypeError):
            verifier._public_keys["injected-key"] = self.key.public_key()

    def test_malformed_checkpoint_object_rejects(self):
        for checkpoint in (None, True, self.head, {}, b"checkpoint"):
            with self.subTest(checkpoint=checkpoint):
                self.assertFalse(self.verifier.verify_checkpoint(checkpoint, self.head).accepted)

    def test_concurrent_high_water_updates_never_regress(self):
        barrier = threading.Barrier(8)
        heads = [replace(self.head, sequence=sequence, event_hash="%064x" % sequence) for sequence in range(8, 16)]
        checkpoints = [self.sign(head) for head in heads]

        def verify(checkpoint):
            barrier.wait(timeout=5)
            return self.verifier.verify_checkpoint(checkpoint, checkpoint.head)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(verify, checkpoints))
        self.assertTrue(results[-1].accepted)
        self.assertEqual(self.provider.state, heads[-1])
        self.assertTrue(all(result.signature_authentic and result.database_consistent for result in results))
        for checkpoint in checkpoints[:-1]:
            self.assertFalse(self.verifier.verify_checkpoint(checkpoint, checkpoint.head).accepted)
        self.assertEqual(self.provider.state, heads[-1])

    def test_concurrent_equal_sequence_conflicts_have_one_winner(self):
        heads = [replace(self.head, sequence=8, event_hash=character * 64) for character in ("a", "b")]
        checkpoints = [self.sign(head) for head in heads]
        for attempt in range(20):
            with self.subTest(attempt=attempt):
                self.provider.state = self.head
                barrier = threading.Barrier(2)

                def verify(checkpoint):
                    barrier.wait(timeout=5)
                    return self.verifier.verify_checkpoint(checkpoint, checkpoint.head)

                with ThreadPoolExecutor(max_workers=2) as executor:
                    results = list(executor.map(verify, checkpoints))
                self.assertEqual(sum(result.accepted for result in results), 1)
                winner = next(head for head, result in zip(heads, results) if result.accepted)
                self.assertEqual(self.provider.state, winner)

    def test_concurrent_identical_checkpoints_are_idempotent(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(
                lambda unused: self.verifier.verify_checkpoint(self.checkpoint, self.head), range(32)
            ))
        self.assertTrue(all(result.accepted for result in results))
        self.assertEqual(self.provider.state, self.head)


if __name__ == "__main__":
    unittest.main()
