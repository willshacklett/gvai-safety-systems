from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.experimental_authority_head import (
    AuthorityHeadCheckpoint,
    AuthorityHeadState,
    CHECKPOINT_DOMAIN,
    ExperimentalAuthorityHeadVerifier,
)
from gvai.experimental_checkpoint_recovery import (
    CheckpointRecoveryState,
    CheckpointStorageError,
    ExperimentalCheckpointRecoveryFence,
    ExperimentalDurableHighWaterProvider,
)


class _SQLiteTestCheckpointStorage:
    """Temporary local persistence fake, NOT independently custodied storage."""

    def __init__(self, path):
        self.path = Path(path)

    @classmethod
    def provision_for_test(cls, path, checkpoint):
        with sqlite3.connect(path) as connection:
            connection.execute(
                "CREATE TABLE checkpoint (slot INTEGER PRIMARY KEY CHECK(slot=1), "
                "payload BLOB NOT NULL, signature BLOB NOT NULL)"
            )
            connection.execute(
                "INSERT INTO checkpoint VALUES (1, ?, ?)",
                (checkpoint.canonical_bytes(), checkpoint.signature),
            )
        return cls(path)

    def _connect(self, timeout_seconds):
        connection = sqlite3.connect(
            self.path.as_uri() + "?mode=rw", uri=True,
            timeout=timeout_seconds, isolation_level=None,
        )
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _decode(row):
        if row is None:
            return None
        payload, signature = row
        if type(payload) is not bytes or not payload.startswith(CHECKPOINT_DOMAIN) or len(payload) > 4096:
            raise CheckpointStorageError("test_storage_corrupt")
        try:
            fields = json.loads(payload[len(CHECKPOINT_DOMAIN):])
            checkpoint = AuthorityHeadCheckpoint(
                AuthorityHeadState(
                    AuthorityIdentity(fields["authority_id"], fields["authority_epoch"], fields["trust_domain"]),
                    fields["sequence"], fields["event_head_hash"],
                ),
                fields["signing_key_id"], signature,
                version=fields["contract_version"], purpose=fields["purpose"],
                signature_algorithm=fields["signature_algorithm"],
            )
            if checkpoint.canonical_bytes() != payload:
                raise CheckpointStorageError("test_storage_noncanonical")
            return checkpoint
        except (KeyError, TypeError, ValueError) as error:
            raise CheckpointStorageError("test_storage_corrupt") from error

    def read_checkpoint(self, authority, *, timeout_seconds):
        try:
            connection = self._connect(timeout_seconds)
            try:
                record = self._decode(connection.execute(
                    "SELECT payload, signature FROM checkpoint WHERE slot=1"
                ).fetchone())
                if record is not None and record.head.authority != authority:
                    raise CheckpointStorageError("test_storage_identity_mismatch")
                return record
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise CheckpointStorageError("test_storage_unavailable") from error

    def compare_and_swap(self, expected, candidate, *, timeout_seconds):
        try:
            connection = self._connect(timeout_seconds)
            try:
                connection.execute("BEGIN IMMEDIATE")
                current = self._decode(connection.execute(
                    "SELECT payload, signature FROM checkpoint WHERE slot=1"
                ).fetchone())
                if current is None:
                    raise CheckpointStorageError("missing_trust_state")
                if current != expected:
                    connection.rollback()
                    return False
                if (
                    candidate.head.authority != current.head.authority
                    or candidate.head.sequence < current.head.sequence
                    or (candidate.head.sequence == current.head.sequence
                        and candidate.head.event_hash != current.head.event_hash)
                ):
                    raise CheckpointStorageError("test_storage_nonmonotonic")
                connection.execute(
                    "UPDATE checkpoint SET payload=?, signature=? WHERE slot=1",
                    (candidate.canonical_bytes(), candidate.signature),
                )
                connection.commit()
                return True
            finally:
                connection.close()
        except sqlite3.Error as error:
            raise CheckpointStorageError("test_storage_write_unavailable_or_ambiguous") from error


class DurableCheckpointRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "checkpoint.sqlite"
        self.authority = AuthorityIdentity("recovery-test", 1, "offline-test-domain")
        self.key = Ed25519PrivateKey.generate()
        self.public_key = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.verifier = ExperimentalAuthorityHeadVerifier(
            authority=self.authority,
            checkpoint_public_keys={"checkpoint-test": self.public_key},
            independent_high_water=None,
            other_purpose_key_ids=frozenset(),
            other_purpose_public_keys=frozenset(),
        )
        self.anchor = self.sign(7)
        self.storage = _SQLiteTestCheckpointStorage.provision_for_test(self.path, self.anchor)
        self.provider = self.make_provider()
        self.fence = ExperimentalCheckpointRecoveryFence(self.provider)

    def sign(self, sequence, event_hash=None, authority=None, key=None):
        head = AuthorityHeadState(
            self.authority if authority is None else authority,
            sequence, "%064x" % sequence if event_hash is None else event_hash,
        )
        unsigned = AuthorityHeadCheckpoint(head, "checkpoint-test", b"\x00" * 64)
        return replace(unsigned, signature=(self.key if key is None else key).sign(unsigned.canonical_bytes()))

    def make_provider(self, storage=None, anchor=None):
        return ExperimentalDurableHighWaterProvider(
            storage=self.storage if storage is None else storage,
            signature_verifier=self.verifier,
            recovery_anchor=self.anchor if anchor is None else anchor,
        )

    def advance(self, checkpoint, provider=None):
        return (self.provider if provider is None else provider).check_and_advance(
            checkpoint, timeout_seconds=2.0
        )

    def stored(self):
        return self.storage.read_checkpoint(self.authority, timeout_seconds=2.0)

    def test_restart_retains_high_water_and_requires_reconciliation(self):
        newer = self.sign(8)
        self.assertEqual(self.advance(newer), newer.head)
        restarted = self.make_provider(storage=_SQLiteTestCheckpointStorage(self.path))
        self.assertIsNone(self.advance(self.anchor, restarted))
        fence = ExperimentalCheckpointRecoveryFence(restarted)
        self.assertEqual(fence.assessment.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(fence.reconcile(newer, newer.head).state, CheckpointRecoveryState.RECONCILED)
        self.assertFalse(fence.may_authorize_fresh_grant)

    def test_fresh_process_reads_committed_record(self):
        import subprocess
        import sys

        newer = self.sign(8)
        self.advance(newer)
        result = subprocess.run(
            [sys.executable, "-c",
             "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); "
             "p,s=c.execute('SELECT payload,signature FROM checkpoint').fetchone(); "
             "print(p.hex()); print(s.hex())", str(self.path)],
            check=True, capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.stdout.splitlines(), [newer.canonical_bytes().hex(), newer.signature.hex()])

    def test_stale_database_backup_stays_fenced(self):
        self.advance(self.sign(8))
        result = self.fence.reconcile(self.anchor, self.anchor.head)
        self.assertEqual(result.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(result.reason, "stored_head_mismatch_or_concurrent_change")
        self.assertEqual(self.stored().head.sequence, 8)

    def test_stale_storage_backup_below_external_anchor_stays_fenced(self):
        backup = Path(self.directory.name) / "stale-backup.sqlite"
        with sqlite3.connect(self.path) as source, sqlite3.connect(backup) as target:
            source.backup(target)
        newer = self.sign(8)
        self.advance(newer)
        provider = self.make_provider(anchor=newer)
        with sqlite3.connect(backup) as source, sqlite3.connect(self.path) as target:
            source.backup(target)
        fence = ExperimentalCheckpointRecoveryFence(provider)
        result = fence.reconcile(self.anchor, self.anchor.head)
        self.assertEqual(result.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(result.reason, "storage_below_recovery_anchor_or_conflicting")
        with self.assertRaises(CheckpointStorageError):
            self.advance(newer, provider)
        self.assertEqual(self.stored(), self.anchor)

    def test_resetting_both_store_and_anchor_is_not_detectable(self):
        backup = Path(self.directory.name) / "old-store.sqlite"
        with sqlite3.connect(self.path) as source, sqlite3.connect(backup) as target:
            source.backup(target)
        newer = self.sign(8)
        self.advance(newer)
        with sqlite3.connect(backup) as source, sqlite3.connect(self.path) as target:
            source.backup(target)
        restarted_fence = ExperimentalCheckpointRecoveryFence(self.make_provider(anchor=self.anchor))
        self.assertEqual(restarted_fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.RECONCILED)
        self.assertFalse(restarted_fence.may_authorize_fresh_grant)

    def test_regression_and_equal_sequence_conflict_reject(self):
        for candidate in (self.sign(6), self.sign(7, "b" * 64)):
            with self.subTest(candidate=candidate):
                self.assertIsNone(self.advance(candidate))
                self.assertEqual(self.stored(), self.anchor)
        self.assertEqual(self.advance(self.anchor), self.anchor.head)

    def test_storage_adapter_itself_rejects_nonmonotonic_writes(self):
        for candidate in (
            self.sign(6), self.sign(7, "b" * 64),
            self.sign(8, authority=replace(self.authority, epoch=2)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CheckpointStorageError):
                    self.storage.compare_and_swap(self.anchor, candidate, timeout_seconds=2.0)
                self.assertEqual(self.stored(), self.anchor)

    def test_atomic_concurrent_updates_across_adapter_instances(self):
        barrier = threading.Barrier(8)
        candidates = [self.sign(sequence) for sequence in range(8, 16)]

        def advance(candidate):
            provider = self.make_provider(storage=_SQLiteTestCheckpointStorage(self.path))
            barrier.wait(timeout=5)
            return self.advance(candidate, provider)

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(advance, candidates))
        self.assertEqual(results[-1], candidates[-1].head)
        self.assertEqual(self.stored(), candidates[-1])
        for candidate in candidates[:-1]:
            self.assertIsNone(self.advance(candidate))

    def test_concurrent_conflicts_have_one_winner(self):
        barrier = threading.Barrier(2)
        candidates = [self.sign(8, character * 64) for character in ("a", "b")]

        def advance(candidate):
            barrier.wait(timeout=5)
            return self.advance(candidate)

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(advance, candidates))
        self.assertEqual(sum(result is not None for result in results), 1)
        self.assertEqual(self.stored().head, next(result for result in results if result is not None))

    def test_missing_trust_row_never_bootstraps(self):
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM checkpoint")
        with self.assertRaisesRegex(CheckpointStorageError, "missing_trust_state"):
            self.advance(self.sign(8))
        self.assertEqual(self.fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)
        self.assertIsNone(self.stored())

    def test_missing_storage_file_never_created(self):
        missing = Path(self.directory.name) / "absent.sqlite"
        provider = self.make_provider(storage=_SQLiteTestCheckpointStorage(missing))
        with self.assertRaises(CheckpointStorageError):
            self.advance(self.anchor, provider)
        self.assertFalse(missing.exists())
        fence = ExperimentalCheckpointRecoveryFence(provider)
        self.assertEqual(fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)

    def test_corrupt_storage_and_invalid_signature_stay_fenced(self):
        for payload, signature in (
            (b"corrupt", self.anchor.signature),
            (self.anchor.canonical_bytes(), b"\x00" * 64),
            (self.sign(8).canonical_bytes(), self.anchor.signature),
            (self.anchor.canonical_bytes() + b" ", self.anchor.signature),
        ):
            with self.subTest(payload=payload):
                with sqlite3.connect(self.path) as connection:
                    connection.execute("UPDATE checkpoint SET payload=?,signature=?", (payload, signature))
                result = self.fence.reconcile(self.anchor, self.anchor.head)
                self.assertEqual(result.state, CheckpointRecoveryState.FENCED)
                with self.assertRaises(CheckpointStorageError):
                    self.advance(self.sign(9))

    def test_corrupt_database_file_stays_fenced(self):
        self.path.write_bytes(b"not a SQLite database")
        result = self.fence.reconcile(self.anchor, self.anchor.head)
        self.assertEqual(result.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(result.reason, "test_storage_unavailable")

    def test_forged_or_wrong_identity_candidate_never_writes(self):
        for candidate in (
            self.sign(8, key=Ed25519PrivateKey.generate()),
            self.sign(8, authority=replace(self.authority, epoch=2)),
            replace(self.anchor, head=replace(self.anchor.head, sequence=8)),
            replace(self.anchor, head=replace(self.anchor.head, event_hash="b" * 64)),
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises(CheckpointStorageError):
                    self.advance(candidate)
                self.assertEqual(self.stored(), self.anchor)

    def test_invalid_recovery_anchor_rejected(self):
        for anchor in (None, self.sign(7, key=Ed25519PrivateKey.generate()),
                       self.sign(7, authority=replace(self.authority, epoch=2))):
            with self.subTest(anchor=anchor):
                with self.assertRaises(ValueError):
                    self.make_provider(anchor=anchor if anchor is not None else True)

    def test_stored_identity_or_anchor_hash_conflict_stays_fenced(self):
        for record in (
            self.sign(7, authority=replace(self.authority, epoch=2)),
            self.sign(7, "b" * 64),
        ):
            with self.subTest(record=record):
                with sqlite3.connect(self.path) as connection:
                    connection.execute(
                        "UPDATE checkpoint SET payload=?,signature=?",
                        (record.canonical_bytes(), record.signature),
                    )
                self.assertEqual(self.fence.reconcile(record, record.head).state,
                                 CheckpointRecoveryState.FENCED)
                with self.assertRaises(CheckpointStorageError):
                    self.advance(self.sign(8))

    def test_revoked_stored_signer_is_not_trusted_on_restart(self):
        verifier = ExperimentalAuthorityHeadVerifier(
            authority=self.authority,
            checkpoint_public_keys={"checkpoint-test": self.public_key},
            independent_high_water=None,
            other_purpose_key_ids=frozenset(),
            other_purpose_public_keys=frozenset(),
            revoked_key_ids=frozenset({"checkpoint-test"}),
        )
        with self.assertRaisesRegex(ValueError, "Recovery anchor must authenticate"):
            ExperimentalDurableHighWaterProvider(
                storage=self.storage, signature_verifier=verifier, recovery_anchor=self.anchor
            )

    def test_assessment_does_not_reconcile_and_newer_database_does_not_advance(self):
        self.assertEqual(self.fence.assess(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.MATCHED)
        self.assertEqual(self.fence.check_reconciled(self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)
        newer = self.sign(8)
        self.assertEqual(self.fence.reconcile(newer, newer.head).state,
                         CheckpointRecoveryState.FENCED)
        self.assertEqual(self.stored(), self.anchor)

    def test_ambiguous_database_heads_stay_fenced(self):
        for head in (None, True, {}, replace(self.anchor.head, sequence=6),
                     replace(self.anchor.head, event_hash="b" * 64)):
            with self.subTest(head=head):
                self.assertEqual(self.fence.reconcile(self.anchor, head).state,
                                 CheckpointRecoveryState.FENCED)

    def test_advance_after_reconciliation_refences_and_requires_explicit_reconciliation(self):
        self.assertEqual(self.fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.RECONCILED)
        newer = self.sign(8)
        self.advance(newer)
        self.assertEqual(self.fence.check_reconciled(self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)
        self.assertEqual(self.fence.check_reconciled(newer.head).state,
                         CheckpointRecoveryState.FENCED)
        self.assertEqual(self.fence.reconcile(newer, newer.head).state,
                         CheckpointRecoveryState.RECONCILED)

    def test_storage_failures_and_ambiguous_writes_stay_fenced(self):
        for operation in ("read", "swap", "ambiguous_commit", "invalid_response"):
            with self.subTest(operation=operation):
                real = self.storage

                class FailingStorage:
                    def read_checkpoint(self, authority, *, timeout_seconds):
                        if operation == "read":
                            raise CheckpointStorageError("storage_offline")
                        return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

                    def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                        if operation == "invalid_response":
                            return "success"
                        if operation == "ambiguous_commit":
                            real.compare_and_swap(expected, candidate, timeout_seconds=timeout_seconds)
                        raise CheckpointStorageError("storage_write_ambiguous_or_offline")

                provider = self.make_provider(storage=FailingStorage())
                fence = ExperimentalCheckpointRecoveryFence(provider)
                self.assertEqual(fence.reconcile(self.anchor, self.anchor.head).state,
                                 CheckpointRecoveryState.FENCED)
                with self.assertRaises(CheckpointStorageError):
                    self.advance(self.anchor, provider)

    def test_ambiguous_committed_advance_requires_readback_and_explicit_reconciliation(self):
        real = self.storage
        newer = self.sign(8)

        class AmbiguousStorage:
            def read_checkpoint(self, authority, *, timeout_seconds):
                return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

            def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                real.compare_and_swap(expected, candidate, timeout_seconds=timeout_seconds)
                raise CheckpointStorageError("commit_acknowledgement_lost")

        provider = self.make_provider(storage=AmbiguousStorage())
        with self.assertRaisesRegex(CheckpointStorageError, "commit_acknowledgement_lost"):
            self.advance(newer, provider)
        self.assertEqual(self.stored(), newer)
        self.assertEqual(self.fence.check_reconciled(newer.head).state, CheckpointRecoveryState.FENCED)
        self.assertEqual(self.fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)
        self.assertEqual(self.fence.reconcile(newer, newer.head).state,
                         CheckpointRecoveryState.RECONCILED)

    def test_storage_substitution_cannot_change_authenticated_snapshot(self):
        real = self.storage
        for field, value in (("sequence", 8), ("event_hash", "b" * 64), ("epoch", 2)):
            with self.subTest(field=field):
                class SubstitutingStorage:
                    def read_checkpoint(self, authority, *, timeout_seconds):
                        return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

                    def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                        target = candidate.head.authority if field == "epoch" else candidate.head
                        object.__setattr__(target, field, value)
                        return True

                provider = self.make_provider(storage=SubstitutingStorage())
                with self.assertRaisesRegex(CheckpointStorageError, "storage_argument_substitution"):
                    self.advance(self.anchor, provider)
                self.assertTrue(self.verifier.verify_signature(self.anchor))
                self.assertEqual(self.stored(), self.anchor)
                fence = ExperimentalCheckpointRecoveryFence(provider)
                self.assertEqual(fence.reconcile(self.anchor, self.anchor.head).state,
                                 CheckpointRecoveryState.FENCED)

    def test_equal_comparing_but_malformed_callback_substitution_rejects(self):
        real = self.storage
        for field, value in (
            ("sequence", 7.0), ("epoch", True), ("signature", bytearray(self.anchor.signature)),
        ):
            with self.subTest(field=field):
                class SubstitutingStorage:
                    def read_checkpoint(self, authority, *, timeout_seconds):
                        return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

                    def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                        if field == "signature":
                            target = candidate
                        elif field == "epoch":
                            target = candidate.head.authority
                        else:
                            target = candidate.head
                        object.__setattr__(target, field, value)
                        return True

                provider = self.make_provider(storage=SubstitutingStorage())
                with self.assertRaises(CheckpointStorageError):
                    self.advance(self.anchor, provider)
                self.assertEqual(self.stored(), self.anchor)

    def test_cas_comparison_loss_never_claims_acceptance(self):
        real = self.storage

        class LosingStorage:
            def read_checkpoint(self, authority, *, timeout_seconds):
                return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

            def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                return False

        provider = self.make_provider(storage=LosingStorage())
        with self.assertRaisesRegex(CheckpointStorageError, "storage_contention"):
            self.advance(self.sign(8), provider)
        self.assertEqual(self.stored(), self.anchor)
        fence = ExperimentalCheckpointRecoveryFence(provider)
        self.assertEqual(fence.reconcile(self.anchor, self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)

    def test_concurrent_advance_between_read_and_swap_reauthenticates(self):
        real = self.storage
        competing = self.sign(9)
        calls = []

        class RacingStorage:
            def read_checkpoint(self, authority, *, timeout_seconds):
                return real.read_checkpoint(authority, timeout_seconds=timeout_seconds)

            def compare_and_swap(self, expected, candidate, *, timeout_seconds):
                calls.append(candidate)
                real.compare_and_swap(expected, competing, timeout_seconds=timeout_seconds)
                return real.compare_and_swap(expected, candidate, timeout_seconds=timeout_seconds)

        provider = self.make_provider(storage=RacingStorage())
        self.assertIsNone(self.advance(self.sign(8), provider))
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.stored(), competing)

    def test_expired_read_deadline_rejects(self):
        with patch("gvai.experimental_checkpoint_recovery.time.monotonic",
                   side_effect=(0.0, 0.0, 3.0)):
            with self.assertRaisesRegex(CheckpointStorageError, "storage_timeout"):
                self.advance(self.anchor)
        self.assertEqual(self.stored(), self.anchor)

    def test_expired_commit_response_refences_even_if_write_committed(self):
        with patch("gvai.experimental_checkpoint_recovery.time.monotonic",
                   side_effect=(0.0, 0.0, 0.0, 0.0, 3.0)):
            result = self.fence.reconcile(self.anchor, self.anchor.head)
        self.assertEqual(result.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(result.reason, "storage_timeout")

    def test_revalidation_error_clears_previous_reconciliation(self):
        self.fence.reconcile(self.anchor, self.anchor.head)
        with patch.object(_SQLiteTestCheckpointStorage, "read_checkpoint",
                          side_effect=RuntimeError("nonconforming adapter failure")):
            with self.assertRaisesRegex(RuntimeError, "nonconforming adapter failure"):
                self.fence.check_reconciled(self.anchor.head)
        self.assertEqual(self.fence.assessment.state, CheckpointRecoveryState.FENCED)
        self.assertEqual(self.fence.check_reconciled(self.anchor.head).state,
                         CheckpointRecoveryState.FENCED)

    def test_trust_configuration_is_detached_and_immutable(self):
        anchor = replace(self.anchor, head=replace(
            self.anchor.head, authority=replace(self.anchor.head.authority)
        ))
        provider = self.make_provider(anchor=anchor)
        object.__setattr__(anchor.head, "sequence", 99)
        self.assertEqual(self.advance(self.anchor, provider), self.anchor.head)
        with self.assertRaises(AttributeError):
            provider._anchor = self.sign(6)
        with self.assertRaises(AttributeError):
            del provider._storage

    def test_invalid_timeouts_reject(self):
        for timeout in (True, 0, -1, 31, float("nan"), float("inf")):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    self.provider.check_and_advance(self.anchor, timeout_seconds=timeout)
                with self.assertRaises(ValueError):
                    ExperimentalCheckpointRecoveryFence(self.provider, timeout_seconds=timeout)

    def test_existing_checkpoint_verifier_works_with_durable_provider(self):
        verifier = ExperimentalAuthorityHeadVerifier(
            authority=self.authority,
            checkpoint_public_keys={"checkpoint-test": self.public_key},
            independent_high_water=self.provider,
            other_purpose_key_ids=frozenset(),
            other_purpose_public_keys=frozenset(),
        )
        newer = self.sign(8)
        self.assertTrue(verifier.verify_checkpoint(newer, newer.head).accepted)
        self.assertFalse(verifier.verify_checkpoint(self.anchor, self.anchor.head).accepted)
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM checkpoint")
        result = verifier.verify_checkpoint(newer, newer.head)
        self.assertFalse(result.accepted)
        self.assertTrue(result.signature_authentic)
        self.assertTrue(result.database_consistent)


if __name__ == "__main__":
    unittest.main()
