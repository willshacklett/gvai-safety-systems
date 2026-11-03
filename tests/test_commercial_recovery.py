import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from gvai.commercial_recovery import (
    ProjectionHead,
    RecoveryState,
    SQLiteRecoveryGate,
    TrustedHead,
)
from gvai.commercial_usage import SQLiteUsageStore


class _TestTrustedHeadProvider:
    def __init__(self, head=None, error=None):
        self.head = head
        self.error = error

    def read_verified_head(self):
        if self.error is not None:
            raise self.error
        return self.head


class _TestProjectionReader:
    def __init__(self, projection=None, error=None):
        self.projection = projection
        self.error = error

    def read_projection_head(self, store):
        if self.error is not None:
            raise self.error
        return self.projection


class SQLiteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "usage.sqlite3"
        self.store = SQLiteUsageStore.initialize(
            self.database_path,
            {"tenant-a": 2},
            clock=lambda: datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp(),
        )
        self.digest_a = "a" * 64
        self.digest_b = "b" * 64

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def make_gate(self, *, provider=None, projection_reader=None, authority_id="test-authority"):
        return SQLiteRecoveryGate(
            self.store,
            expected_authority_id=authority_id,
            trusted_head_provider=provider,
            projection_reader=projection_reader,
        )

    def provider(self, sequence=0, digest=None, authority_id="test-authority", authenticated=True):
        return _TestTrustedHeadProvider(
            TrustedHead(
                authority_id,
                sequence,
                self.digest_a if digest is None else digest,
                authenticated,
            )
        )

    def reader(self, sequence=0, digest=None):
        return _TestProjectionReader(
            ProjectionHead(sequence, self.digest_a if digest is None else digest)
        )

    def test_default_is_unverified_and_missing_authority_denies(self):
        gate = self.make_gate()
        self.assertEqual(gate.state, RecoveryState.UNVERIFIED)
        self.assertEqual(gate.verify(), RecoveryState.DENIED)
        self.assertFalse(gate.may_authorize_fresh_grant)

    def test_unavailable_authority_denies(self):
        gate = self.make_gate(
            provider=_TestTrustedHeadProvider(error=OSError("test-only unavailable")),
            projection_reader=self.reader(),
        )
        self.assertEqual(gate.verify(), RecoveryState.DENIED)

    def test_corrupt_or_unauthenticated_head_is_quarantined(self):
        cases = (
            self.provider(authenticated=False),
            self.provider(digest="not-a-digest"),
            self.provider(authority_id="unexpected-authority"),
        )
        for provider in cases:
            with self.subTest(provider=provider.head):
                gate = self.make_gate(provider=provider, projection_reader=self.reader())
                self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)
                self.assertFalse(gate.may_authorize_fresh_grant)

    def test_existing_schema_without_projection_cursor_requires_rebuild(self):
        gate = self.make_gate(provider=self.provider())
        self.assertEqual(gate.verify(), RecoveryState.REBUILD_REQUIRED)
        self.assertFalse(gate.may_authorize_fresh_grant)

    def test_unavailable_projection_reader_denies(self):
        gate = self.make_gate(
            provider=self.provider(),
            projection_reader=_TestProjectionReader(error=OSError("test-only unavailable")),
        )
        self.assertEqual(gate.verify(), RecoveryState.DENIED)

    def test_malformed_projection_head_is_quarantined(self):
        gate = self.make_gate(
            provider=self.provider(),
            projection_reader=_TestProjectionReader(ProjectionHead(0, "bad-hash")),
        )
        self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)

    def test_projection_behind_authority_requires_rebuild(self):
        gate = self.make_gate(
            provider=self.provider(sequence=3),
            projection_reader=self.reader(sequence=2),
        )
        self.assertEqual(gate.verify(), RecoveryState.REBUILD_REQUIRED)

    def test_projection_ahead_of_authority_is_quarantined(self):
        gate = self.make_gate(
            provider=self.provider(sequence=2),
            projection_reader=self.reader(sequence=3),
        )
        self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)

    def test_matching_test_heads_are_diagnostic_only(self):
        gate = self.make_gate(
            provider=self.provider(sequence=4),
            projection_reader=self.reader(sequence=4),
        )
        self.assertEqual(gate.verify(), RecoveryState.READY)
        self.assertFalse(gate.may_authorize_fresh_grant)

    def test_matching_sequence_with_different_hash_is_quarantined(self):
        gate = self.make_gate(
            provider=self.provider(sequence=4, digest=self.digest_a),
            projection_reader=self.reader(sequence=4, digest=self.digest_b),
        )
        self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)

    def test_schema_or_integrity_failure_is_quarantined(self):
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute(
                "CREATE TRIGGER unexpected_trigger AFTER INSERT ON usage_reservations BEGIN SELECT 1; END"
            )
            connection.commit()
        finally:
            connection.close()
        gate = self.make_gate(provider=self.provider(), projection_reader=self.reader())
        self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)

    def test_stale_snapshot_is_not_ready_after_restore(self):
        snapshot = Path(self.temp_dir.name) / "before-reservation.sqlite3"
        shutil.copy2(self.database_path, snapshot)
        self.store._apply("tenant-a", "project", "request-id", "reserve")
        self.store.close()
        shutil.copy2(snapshot, self.database_path)
        self.store = SQLiteUsageStore(
            self.database_path,
            {"tenant-a": 2},
            clock=lambda: datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp(),
        )

        gate = self.make_gate(
            provider=self.provider(sequence=1),
            projection_reader=self.reader(sequence=0),
        )
        self.assertEqual(gate.verify(), RecoveryState.REBUILD_REQUIRED)
        self.assertFalse(gate.may_authorize_fresh_grant)

    def test_crash_between_authority_and_projection_persistence_rebuilds(self):
        gate = self.make_gate(
            provider=self.provider(sequence=8),
            projection_reader=self.reader(sequence=7),
        )
        self.assertEqual(gate.verify(), RecoveryState.REBUILD_REQUIRED)
        self.assertFalse(gate.may_authorize_fresh_grant)

    def test_closed_database_denies_without_affecting_supervisor_stop(self):
        from gvai.effects import make_action
        from gvai.external_control import GVExternalControlPlane

        self.store.close()
        gate = self.make_gate(provider=self.provider(), projection_reader=self.reader())
        self.assertEqual(gate.verify(), RecoveryState.QUARANTINED)
        self.assertFalse(gate.may_authorize_fresh_grant)
        action = make_action("test-only", {"low_impact"})
        self.assertTrue(GVExternalControlPlane().evaluate_internal_shutdown(action).halted)


if __name__ == "__main__":
    unittest.main()
