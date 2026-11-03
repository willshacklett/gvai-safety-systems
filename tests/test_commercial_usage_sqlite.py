import sqlite3
import os
import stat
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability,
    CommercialResourceKind,
    CommercialResourceOwnership,
    VerifiedCustomerIdentity,
)
from gvai.commercial_usage import (
    CommercialUsage,
    ReservationState,
    SQLiteUsageStore,
    UsageReason,
    UsageResult,
)


def timestamp(year, month):
    return datetime(year, month, 1, tzinfo=timezone.utc).timestamp()


class _SQLiteLedgerTestHarness:
    """Test-only adapter for exercising ledger persistence without service grants."""

    def __init__(self, authorizer, store):
        self._authorizer = authorizer
        self._store = store

    def reserve(self, credential, resource_id, request_id):
        return self._operate(credential, resource_id, request_id, "reserve")

    def complete(self, credential, resource_id, request_id, *, succeeded):
        if type(succeeded) is not bool:
            return UsageResult(UsageReason.INVALID_INPUT)
        operation = "completed" if succeeded else "failed"
        return self._operate(credential, resource_id, request_id, operation)

    def summary(self, credential, resource_id):
        return self._operate(credential, resource_id, None, "summary")

    def _operate(self, credential, resource_id, request_id, operation):
        capability = (
            CommercialCapability.READ_USAGE
            if operation == "summary"
            else CommercialCapability.EVALUATE
        )
        decision = self._authorizer.authorize(credential, capability, resource_id)
        if decision.allowed is not True:
            return UsageResult(UsageReason.UNAUTHORIZED)
        try:
            return self._store._apply(
                decision.tenant_id, resource_id, request_id, operation
            )
        except Exception:
            return UsageResult(UsageReason.ACCOUNTING_ERROR)


class SQLiteUsageTests(unittest.TestCase):
    def setUp(self):
        self.now = timestamp(2026, 10)
        self.identities = {
            tenant: VerifiedCustomerIdentity(
                "customer-" + tenant,
                tenant,
                frozenset(CommercialCapability),
                int(timestamp(2030, 1)),
            )
            for tenant in ("tenant-a", "tenant-b")
        }
        self.resources = {
            tenant + suffix: CommercialResourceOwnership(
                tenant + suffix, tenant, kind
            )
            for tenant in self.identities
            for suffix, kind in (
                ("-project", CommercialResourceKind.EVALUATION),
                ("-usage", CommercialResourceKind.USAGE),
            )
        }
        verifier = type("Verifier", (), {})()
        verifier.verify = self.identities.get
        ownership = type("OwnershipStore", (), {})()
        ownership.lookup = self.resources.get
        self.ownership = ownership
        self.authorizer = CommercialAuthorizer(
            verifier, ownership, clock=lambda: self.now
        )
        self.temp_dir = TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "usage.sqlite3"
        self.allowances = {"tenant-a": 2, "tenant-b": 1}
        self.store = SQLiteUsageStore.initialize(
            self.database_path, self.allowances, clock=lambda: self.now
        )
        self.usage = _SQLiteLedgerTestHarness(self.authorizer, self.store)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def restart(self):
        self.store.close()
        self.store = SQLiteUsageStore(
            self.database_path, self.allowances, clock=lambda: self.now
        )
        self.usage = _SQLiteLedgerTestHarness(self.authorizer, self.store)

    def reserve(self, request_id="request-1", tenant="tenant-a"):
        return self.usage.reserve(
            tenant, tenant + "-project", request_id
        )

    def summary(self, tenant="tenant-a"):
        return self.usage.summary(tenant, tenant + "-usage")

    def complete(self, succeeded=True, request_id="request-1"):
        return self.usage.complete(
            "tenant-a",
            "tenant-a-project",
            request_id,
            succeeded=succeeded,
        )

    def test_restart_preserves_quota_balance_and_lifetime_replay(self):
        self.assertTrue(self.reserve("first").may_evaluate)
        self.restart()

        replay = self.reserve("first")
        self.assertEqual(replay.reason, UsageReason.REPLAY)
        self.assertFalse(replay.may_evaluate)
        self.assertTrue(self.reserve("second").may_evaluate)
        self.assertEqual(self.reserve("third").reason, UsageReason.QUOTA_EXHAUSTED)
        self.assertEqual(self.summary().summary.consumed, 2)

    def test_crash_after_reservation_and_completion_after_restart(self):
        self.assertTrue(self.reserve().may_evaluate)
        self.restart()

        replay = self.reserve()
        self.assertEqual(replay.reason, UsageReason.REPLAY)
        self.assertEqual(replay.reservation.state, ReservationState.RESERVED)
        self.assertFalse(replay.may_evaluate)
        self.assertEqual(self.complete().reason, UsageReason.COMPLETED)
        self.restart()
        self.assertEqual(self.complete().reason, UsageReason.REPLAY)
        self.assertEqual(self.reserve().reservation.state, ReservationState.COMPLETED)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_concurrent_duplicate_ids_across_store_instances_reserve_once(self):
        stores = [
            SQLiteUsageStore(self.database_path, self.allowances, clock=lambda: self.now)
            for _ in range(8)
        ]
        usages = [_SQLiteLedgerTestHarness(self.authorizer, store) for store in stores]
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(
                    pool.map(
                        lambda index: usages[index % len(usages)].reserve(
                            "tenant-a", "tenant-a-project", "same-id"
                        ),
                        range(64),
                    )
                )
            self.assertEqual(sum(result.may_evaluate for result in results), 1)
            self.assertEqual(
                sum(result.reason is UsageReason.REPLAY for result in results), 63
            )
            self.assertEqual(self.summary().summary.consumed, 1)
        finally:
            for store in stores:
                store.close()

    def test_concurrent_distinct_ids_cannot_exceed_quota_across_instances(self):
        stores = [
            SQLiteUsageStore(self.database_path, self.allowances, clock=lambda: self.now)
            for _ in range(8)
        ]
        usages = [_SQLiteLedgerTestHarness(self.authorizer, store) for store in stores]
        try:
            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(
                    pool.map(
                        lambda index: usages[index % len(usages)].reserve(
                            "tenant-a",
                            "tenant-a-project",
                            "request-" + str(index),
                        ),
                        range(64),
                    )
                )
            self.assertEqual(sum(result.may_evaluate for result in results), 2)
            self.assertEqual(
                sum(
                    result.reason is UsageReason.QUOTA_EXHAUSTED
                    for result in results
                ),
                62,
            )
            self.assertEqual(self.summary().summary.consumed, 2)
        finally:
            for store in stores:
                store.close()

    def test_clock_rollback_watermark_survives_restart(self):
        self.reserve()
        self.now -= 1
        self.restart()
        self.assertEqual(self.summary().reason, UsageReason.CLOCK_ROLLBACK)
        self.assertEqual(self.reserve("new").reason, UsageReason.CLOCK_ROLLBACK)
        self.now += 1
        self.assertEqual(self.reserve().reason, UsageReason.REPLAY)

    def test_closed_or_missing_database_fails_closed_without_reinitializing(self):
        self.store.close()
        self.assertEqual(self.reserve("closed").reason, UsageReason.ACCOUNTING_ERROR)
        self.database_path.unlink()
        with self.assertRaises(FileNotFoundError):
            SQLiteUsageStore(self.database_path, self.allowances, clock=lambda: self.now)

    def test_corrupt_reservation_state_fails_closed(self):
        self.reserve()
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute("PRAGMA ignore_check_constraints = ON")
            connection.execute("UPDATE usage_reservations SET state = 'corrupt'")
            connection.commit()
        finally:
            connection.close()
        self.assertEqual(self.summary().reason, UsageReason.ACCOUNTING_ERROR)

    def test_trigger_suppressed_insert_never_grants_or_regrants(self):
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute(
                """CREATE TRIGGER ignore_usage_insert
                   BEFORE INSERT ON usage_reservations
                   BEGIN SELECT RAISE(IGNORE); END"""
            )
            connection.commit()
        finally:
            connection.close()

        first = self.reserve("triggered")
        self.assertEqual(first.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(first.may_evaluate)
        with patch.object(self.store, "_check_schema", return_value=None):
            second = self.reserve("triggered")
        self.assertEqual(second.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(second.may_evaluate)

        connection = sqlite3.connect(str(self.database_path))
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM usage_reservations").fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_policy_row_mutation_while_open_fails_closed(self):
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute(
                "UPDATE usage_policy SET allowance = 99 WHERE tenant_id = ?",
                ("tenant-a",),
            )
            connection.commit()
        finally:
            connection.close()

        for request_id in ("first", "retry"):
            result = self.reserve(request_id)
            self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
            self.assertFalse(result.may_evaluate)

    def test_unexpected_index_and_trigger_changes_fail_closed(self):
        for name, statement, cleanup in (
            (
                "extra_usage_index",
                "CREATE INDEX extra_usage_index ON usage_reservations (state)",
                "DROP INDEX extra_usage_index",
            ),
            (
                "extra_usage_trigger",
                "CREATE TRIGGER extra_usage_trigger AFTER INSERT ON usage_reservations BEGIN SELECT 1; END",
                "DROP TRIGGER extra_usage_trigger",
            ),
        ):
            with self.subTest(name=name):
                connection = sqlite3.connect(str(self.database_path))
                try:
                    connection.execute(statement)
                    connection.commit()
                finally:
                    connection.close()
                result = self.reserve(name)
                self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
                self.assertFalse(result.may_evaluate)
                connection = sqlite3.connect(str(self.database_path))
                try:
                    connection.execute(cleanup)
                    connection.commit()
                finally:
                    connection.close()

    def test_ignored_completion_update_fails_closed(self):
        self.assertTrue(self.reserve().may_evaluate)
        connection = sqlite3.connect(str(self.database_path))
        try:
            connection.execute(
                """CREATE TRIGGER ignore_usage_update
                   BEFORE UPDATE ON usage_reservations
                   BEGIN SELECT RAISE(IGNORE); END"""
            )
            connection.commit()
        finally:
            connection.close()

        with patch.object(self.store, "_check_schema", return_value=None):
            result = self.complete()
        self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(result.may_evaluate)

        connection = sqlite3.connect(str(self.database_path))
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT state FROM usage_reservations"
                ).fetchone()[0],
                ReservationState.RESERVED.value,
            )
        finally:
            connection.close()

    def test_unsafe_database_and_parent_modes_fail_closed(self):
        original_file_mode = stat.S_IMODE(self.database_path.stat().st_mode)
        original_parent_mode = stat.S_IMODE(Path(self.temp_dir.name).stat().st_mode)
        try:
            os.chmod(self.database_path, 0o644)
            self.assertEqual(self.reserve("unsafe-file").reason, UsageReason.ACCOUNTING_ERROR)
            os.chmod(self.database_path, original_file_mode)

            os.chmod(self.temp_dir.name, 0o755)
            self.assertEqual(self.reserve("unsafe-parent").reason, UsageReason.ACCOUNTING_ERROR)
        finally:
            os.chmod(self.database_path, original_file_mode)
            os.chmod(self.temp_dir.name, original_parent_mode)

    def test_symlink_replacement_fails_closed(self):
        target = Path(self.temp_dir.name) / "moved-ledger.sqlite3"
        self.database_path.rename(target)
        self.database_path.symlink_to(target.name)
        result = self.reserve("symlinked")
        self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(result.may_evaluate)

    def test_symlinked_parent_path_is_refused(self):
        actual_parent = Path(self.temp_dir.name) / "actual-parent"
        actual_parent.mkdir(mode=0o700)
        symlink_parent = Path(self.temp_dir.name) / "symlink-parent"
        symlink_parent.symlink_to(actual_parent, target_is_directory=True)
        with self.assertRaises(PermissionError):
            SQLiteUsageStore.initialize(
                symlink_parent / "other.sqlite3",
                self.allowances,
                clock=lambda: self.now,
            )

    def test_database_failure_does_not_affect_supervisor_stop(self):
        from gvai.effects import make_action
        from gvai.external_control import GVExternalControlPlane

        self.store.close()
        result = self.reserve("closed-store")
        self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(result.may_evaluate)
        action = make_action("test-only", {"low_impact"})
        self.assertTrue(GVExternalControlPlane().evaluate_internal_shutdown(action).halted)

    def test_authorizer_tenant_and_current_revocation_remain_required(self):
        keys = CustomerApiKeys(
            InMemoryApiKeyStore(),
            verifier_secret=b"sqlite-ledger-test-verifier-secret-0000",
            clock=lambda: self.now,
        )
        issued = keys.issue(
            principal_id="customer-a",
            tenant_id="tenant-a",
            capabilities=frozenset(CommercialCapability),
            expires_at=int(timestamp(2027, 1)),
        )
        credential = issued.take_secret()
        usage = CommercialUsage(
            CommercialAuthorizer(keys, self.ownership, clock=lambda: self.now),
            self.store,
        )

        self.assertEqual(
            usage.reserve(credential, "tenant-b-project", "cross-tenant").reason,
            UsageReason.UNAUTHORIZED,
        )
        self.assertEqual(
            usage.reserve({"tenant_id": "tenant-a"}, "tenant-a-project", "forged").reason,
            UsageReason.UNAUTHORIZED,
        )
        authorized = usage.reserve(credential, "tenant-a-project", "authorized")
        self.assertEqual(authorized.reason, UsageReason.ACCOUNTING_ERROR)
        self.assertFalse(authorized.may_evaluate)
        self.assertTrue(keys.revoke(issued.key_id))
        self.assertEqual(
            usage.reserve(credential, "tenant-a-project", "after-revoke").reason,
            UsageReason.UNAUTHORIZED,
        )
        self.assertEqual(self.summary().summary.consumed, 0)

    def test_commercial_usage_never_grants_from_local_sqlite(self):
        usage = CommercialUsage(self.authorizer, self.store)
        for _attempt in range(2):
            result = usage.reserve("tenant-a", "tenant-a-project", "same-request")
            self.assertEqual(result.reason, UsageReason.ACCOUNTING_ERROR)
            self.assertFalse(result.may_evaluate)
        connection = sqlite3.connect(str(self.database_path))
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM usage_reservations").fetchone()[0],
                0,
            )
        finally:
            connection.close()

    def test_ledger_persists_only_digests_not_raw_identifiers(self):
        self.reserve("opaque-request-id")
        connection = sqlite3.connect(str(self.database_path))
        try:
            row = connection.execute(
                "SELECT request_digest, resource_digest FROM usage_reservations"
            ).fetchone()
            self.assertEqual(len(row[0]), 64)
            self.assertEqual(len(row[1]), 64)
            self.assertNotIn("opaque-request-id", row)
            self.assertNotIn("tenant-a-project", row)
        finally:
            connection.close()

    def test_policy_mismatch_and_existing_file_initialization_are_refused(self):
        with self.assertRaises(ValueError):
            SQLiteUsageStore(
                self.database_path, {"tenant-a": 99}, clock=lambda: self.now
            )
        with self.assertRaises(FileExistsError):
            SQLiteUsageStore.initialize(
                self.database_path, self.allowances, clock=lambda: self.now
            )

    def test_schema_version_and_integrity(self):
        self.assertEqual(stat.S_IMODE(self.database_path.stat().st_mode), 0o600)
        connection = sqlite3.connect(str(self.database_path))
        try:
            self.assertEqual(
                connection.execute("PRAGMA user_version").fetchone()[0], 1
            )
            self.assertEqual(
                connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
            )
            columns = connection.execute(
                "PRAGMA table_info(usage_reservations)"
            ).fetchall()
            self.assertEqual(
                [column[1] for column in columns if column[5] > 0],
                ["tenant_id", "request_digest"],
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
