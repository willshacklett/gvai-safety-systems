import re
import unittest
from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "postgresql"
    / "002_restricted_reservation_routine_v1.sql"
)


def _migration_text():
    return MIGRATION.read_text(encoding="utf-8").lower()


def _function_body(sql, function_name):
    match = re.search(
        r"create\s+function\s+gvai_authority\."
        + re.escape(function_name)
        + r"\s*\(.*?\).*?as\s+\$function\$(.*?)\$function\$;",
        sql,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("Missing function: " + function_name)
    return match.group(1)


class PostgreSQLReservationRoutineStaticTests(unittest.TestCase):
    def test_migration_is_atomic_and_requires_a_non_superuser_schema_owner(self):
        sql = _migration_text()
        self.assertRegex(sql, r"^\s*begin\s*;")
        self.assertRegex(sql, r"commit\s*;\s*$")
        self.assertIn("migration_is_superuser is distinct from false", sql)
        self.assertIn("reservation routine migration must run as authority schema owner", sql)
        self.assertIn("create extension if not exists pgcrypto with schema gvai_authority", sql)

    def test_reservation_routine_is_security_definer_with_pinned_search_path(self):
        sql = _migration_text()
        routine = _function_body(sql, "reserve_v1")
        declaration = sql.split("create function gvai_authority.reserve_v1(", 1)[1]
        declaration = declaration.split("as $function$", 1)[0]
        self.assertIn("security definer", declaration)
        self.assertIn(
            "set search_path = pg_catalog, gvai_authority, pg_temp",
            declaration,
        )
        self.assertIn(
            "revoke all on function gvai_authority.reserve_v1(", sql
        )
        self.assertIn("from public", sql)
        self.assertNotIn("grant insert", sql)
        self.assertNotIn("grant update", sql)
        self.assertNotIn("grant delete", sql)
        self.assertIn(
            "constant_time_verifier_equal(",
            routine,
        )

    def test_verifier_comparison_uses_fixed_length_work(self):
        sql = _migration_text()
        helper = _function_body(sql, "constant_time_verifier_equal")
        self.assertIn("for byte_index in 0..31 loop", helper)
        self.assertIn("get_byte(stored_verifier, byte_index)", helper)
        self.assertIn("get_byte(candidate_verifier, byte_index)", helper)
        self.assertIn(
            "revoke all on function gvai_authority.constant_time_verifier_equal",
            sql,
        )

    def test_routine_checks_current_identity_ownership_and_policy(self):
        routine = _function_body(_migration_text(), "reserve_v1")
        for expected in (
            "credential_row.status <> 'active'",
            "credential_row.revoked_at is not null",
            "credential_row.expires_at <= pg_catalog.clock_timestamp()",
            "membership_row.status <> 'active'",
            "tenant_row.status <> 'active'",
            "ownership_row.tenant_ref <> credential_row.tenant_ref",
            "ownership_row.resource_kind <> 'evaluation'",
            "current_quota_policies",
            "authority_row.authority_id <> p_expected_authority_id",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, routine)

    def test_routine_replays_conflicts_and_serializes_quota_with_one_event(self):
        sql = _migration_text()
        routine = _function_body(sql, "reserve_v1")
        self.assertIn("from gvai_authority.authority_state as authority", routine)
        self.assertIn("for update", routine)
        self.assertIn("reservation_idempotency", routine)
        self.assertIn("outcome := 'replay'", routine)
        self.assertIn("outcome := 'conflict'", routine)
        self.assertIn("outcome := 'quota_exceeded'", routine)
        self.assertIn("insert into gvai_authority.reservation_events", routine)
        self.assertIn("insert into gvai_authority.reservation_idempotency", routine)
        self.assertIn("update gvai_authority.authority_state", routine)
        self.assertLess(
            routine.index("insert into gvai_authority.reservation_events"),
            routine.index("insert into gvai_authority.reservation_idempotency"),
        )
        self.assertLess(
            routine.index("insert into gvai_authority.reservation_idempotency"),
            routine.index("update gvai_authority.authority_state"),
        )

    def test_usage_bucket_conflict_target_uses_named_primary_key(self):
        schema = (
            MIGRATION.parent / "001_reservation_authority_v1.sql"
        ).read_text(encoding="utf-8").lower()
        bucket = re.search(
            r"create\s+table\s+gvai_authority\.monthly_usage_buckets\s*"
            r"\((.*?)\n\);",
            schema,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(bucket)
        self.assertRegex(bucket.group(1), r"primary key\s*\(\s*tenant_ref\s*,\s*period_start\s*\)")

        routine = _function_body(_migration_text(), "reserve_v1")
        self.assertIn(
            "on conflict on constraint monthly_usage_buckets_pkey do nothing",
            routine,
        )
        self.assertNotIn("on conflict (tenant_ref, period_start)", routine)

    def test_hash_helpers_use_contract_domains_and_canonical_event_fields(self):
        sql = _migration_text()
        helper = _function_body(sql, "reservation_event_hash_v1")
        routine = _function_body(sql, "reserve_v1")
        self.assertIn("gvai-reservation-event-v1", helper)
        self.assertIn("gvai-reservation-request-v1", routine)
        for field in (
            "authority_epoch",
            "authority_id",
            "contract_version",
            "event_id",
            "period",
            "policy_version",
            "previous_event_hash",
            "principal_digest",
            "request_digest",
            "request_id_digest",
            "resource_digest",
            "sequence",
            "tenant_digest",
            "trust_domain",
            "units",
        ):
            with self.subTest(field=field):
                self.assertIn('"' + field + '":', helper)

    def test_runtime_table_writes_are_not_granted(self):
        sql = _migration_text()
        self.assertNotRegex(sql, r"(?m)^\s*grant\s+(insert|update|delete|all)")
        self.assertIn("revoke all privileges on table gvai_authority.reservation_routine_installation from public", sql)


if __name__ == "__main__":
    unittest.main()
