import re
import unittest
from pathlib import Path


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "postgresql"
    / "001_reservation_authority_v1.sql"
)


def _migration_text():
    return MIGRATION.read_text(encoding="utf-8").lower()


def _table_body(sql, table_name):
    match = re.search(
        r"create\s+table\s+gvai_authority\."
        + re.escape(table_name)
        + r"\s*\((.*?)\n\);",
        sql,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError("Missing table: " + table_name)
    return match.group(1)


class PostgreSQLAuthoritySchemaStaticTests(unittest.TestCase):
    def test_migration_is_explicitly_atomic(self):
        sql = _migration_text()
        documentation = (
            MIGRATION.parents[2]
            / "docs"
            / "postgresql_reservation_authority_v1.md"
        ).read_text(encoding="utf-8").lower()
        documentation = re.sub(r"\s+", " ", documentation)
        self.assertRegex(sql, r"^\s*begin\s*;")
        self.assertRegex(sql, r"commit\s*;\s*$")
        self.assertIn("-v on_error_stop=1", documentation)
        self.assertIn("dedicated non-superuser migration owner", documentation)
        self.assertIn("do not run it as `postgres` or a superuser", documentation)
        self.assertLess(
            sql.index("begin;"),
            sql.index("insert into gvai_authority.schema_version"),
        )
        self.assertGreater(
            sql.rindex("commit;"),
            sql.index("insert into gvai_authority.schema_version"),
        )

    def test_required_tables_are_declared(self):
        sql = _migration_text()
        for table_name in (
            "schema_version",
            "tenants",
            "tenant_memberships",
            "customer_credentials",
            "resource_ownerships",
            "quota_policies",
            "current_quota_policies",
            "monthly_usage_buckets",
            "authority_state",
            "reservation_events",
            "reservation_idempotency",
        ):
            with self.subTest(table=table_name):
                _table_body(sql, table_name)

    def test_schema_version_is_singleton_and_pinned_to_v1(self):
        sql = _migration_text()
        version = _table_body(sql, "schema_version")
        self.assertIn("singleton_id smallint primary key check (singleton_id = 1)", version)
        self.assertIn("version integer not null check (version = 1)", version)
        self.assertIn("001_reservation_authority_v1", version)
        self.assertIn("values (1, 1, '001_reservation_authority_v1')", sql)

    def test_idempotency_is_unique_per_authority_tenant_and_request_digest(self):
        body = _table_body(_migration_text(), "reservation_idempotency")
        self.assertRegex(
            body,
            r"primary key\s*\(\s*authority_id\s*,\s*tenant_ref\s*,"
            r"\s*request_id_digest\s*\)",
        )
        self.assertIn("references gvai_authority.reservation_events", body)
        for column in ("request_digest", "resource_digest", "event_id"):
            self.assertRegex(body, r"\b" + column + r"\b")

    def test_tenant_resource_and_membership_relationships_are_composite(self):
        sql = _migration_text()
        resources = _table_body(sql, "resource_ownerships")
        self.assertIn("unique (tenant_ref, ownership_ref)", resources)
        self.assertIn("unique (resource_id, ownership_version)", resources)
        membership = _table_body(sql, "tenant_memberships")
        self.assertIn("unique (tenant_ref, membership_ref)", membership)
        credential = _table_body(sql, "customer_credentials")
        self.assertIn(
            "references gvai_authority.tenant_memberships (tenant_ref, membership_ref)",
            credential,
        )
        events = _table_body(sql, "reservation_events")
        self.assertIn(
            "references gvai_authority.resource_ownerships (tenant_ref, ownership_ref)",
            events,
        )
        self.assertIn(
            "references gvai_authority.tenant_memberships (tenant_ref, membership_ref)",
            events,
        )

    def test_resource_reassignment_preserves_historical_ownership_rows(self):
        sql = _migration_text()
        ownerships = _table_body(sql, "resource_ownerships")
        self.assertIn("status in ('active', 'disabled', 'reassigned')", ownerships)
        self.assertIn("ownership_version bigint not null check (ownership_version > 0)", ownerships)
        self.assertIn("where status = 'active'", sql)
        self.assertIn(
            "on gvai_authority.resource_ownerships (resource_id)",
            sql,
        )
        self.assertIn(
            "create trigger resource_ownership_history_append_only",
            sql,
        )
        self.assertIn(
            "create trigger resource_ownership_version_sequence",
            sql,
        )
        self.assertIn("new.ownership_version <> prior_version + 1", sql)

    def test_event_sequence_is_unique_for_each_authority(self):
        body = _table_body(_migration_text(), "reservation_events")
        self.assertIn("unique (authority_id, sequence)", body)
        self.assertIn("unique (authority_id, event_id)", body)
        self.assertIn("contract_version smallint not null check (contract_version = 1)", body)
        self.assertIn("trust_domain text not null", body)
        self.assertIn("sequence between 1 and 9223372036854775807", body)

    def test_reservation_events_are_append_only_for_runtime_roles(self):
        sql = _migration_text()
        self.assertIn("create trigger reservation_events_append_only", sql)
        self.assertIn(
            "before update or delete on gvai_authority.reservation_events",
            sql,
        )
        self.assertIn("reservation events are append-only", sql)
        self.assertIn(
            "revoke update, delete, truncate",
            sql,
        )
        self.assertIn(
            "on gvai_authority.reservation_events from public",
            sql,
        )

    def test_idempotency_records_are_append_only(self):
        sql = _migration_text()
        self.assertIn("create trigger reservation_idempotency_append_only", sql)
        self.assertIn(
            "before update or delete on gvai_authority.reservation_idempotency",
            sql,
        )
        self.assertIn(
            "revoke update, delete, truncate",
            sql,
        )
        self.assertIn(
            "on gvai_authority.reservation_idempotency from public",
            sql,
        )

    def test_deferred_event_commit_requires_matching_idempotency_and_head(self):
        sql = _migration_text()
        self.assertIn(
            "create constraint trigger reservation_events_complete_at_commit",
            sql,
        )
        self.assertIn("deferrable initially deferred", sql)
        checker = sql.split(
            "create function gvai_authority.verify_reservation_commit()",
            1,
        )[1].split("$function$;", 1)[0]
        for expected in (
            "idem.authority_id = new.authority_id",
            "idem.event_id = new.event_id",
            "idem.tenant_ref = new.tenant_ref",
            "idem.request_id_digest = new.request_id_digest",
            "idem.request_digest = new.request_digest",
            "idem.resource_digest = new.resource_digest",
            "authority.last_sequence = new.sequence",
            "authority.last_event_hash = new.event_hash",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, checker)
        self.assertIn("requires one matching idempotency record", checker)
        self.assertIn("requires a matching advanced authority head", checker)
        self.assertIn(
            "security definer\nset search_path = pg_catalog, gvai_authority",
            checker,
        )

    def test_deferred_quota_consistency_aborts_incomplete_reservations(self):
        sql = _migration_text()
        self.assertIn(
            "create constraint trigger monthly_usage_buckets_match_events_at_commit",
            sql,
        )
        checker = sql.split(
            "create function gvai_authority.verify_usage_bucket_commit()",
            1,
        )[1].split("$function$;", 1)[0]
        self.assertIn("bucket_consumed <> (", checker)
        self.assertIn("select consumed", checker)
        self.assertIn("select count(*)", checker)
        self.assertIn("monthly usage bucket must equal committed event count", checker)
        self.assertIn(
            "security definer\nset search_path = pg_catalog, gvai_authority",
            checker,
        )
        event_checker = sql.split(
            "create function gvai_authority.verify_reservation_commit()",
            1,
        )[1].split("$function$;", 1)[0]
        self.assertIn("reservation event and quota bucket are inconsistent", event_checker)

    def test_runtime_role_has_no_implicit_public_privileges_or_grants(self):
        sql = _migration_text()
        self.assertIn("revoke all privileges on schema gvai_authority from public", sql)
        self.assertIn("revoke all privileges on all tables in schema gvai_authority from public", sql)
        self.assertIn("revoke all privileges on all sequences in schema gvai_authority from public", sql)
        self.assertIn("revoke all privileges on all functions in schema gvai_authority from public", sql)
        self.assertNotRegex(sql, r"(?m)^\s*grant\s")

    def test_authority_head_advances_one_matching_chained_event(self):
        sql = _migration_text()
        self.assertIn("create function gvai_authority.enforce_authority_head_continuity()", sql)
        self.assertIn("new.last_sequence <> old.last_sequence + 1", sql)
        self.assertIn("event.sequence = new.last_sequence", sql)
        self.assertIn("event.previous_event_hash = old.last_event_hash", sql)
        self.assertIn("event.event_hash = new.last_event_hash", sql)
        event_insert_trigger = sql.split(
            "create function gvai_authority.enforce_event_sequence_continuity()",
            1,
        )[1].split("$function$;", 1)[0]
        self.assertLess(
            event_insert_trigger.index("from gvai_authority.authority_state"),
            event_insert_trigger.index("from gvai_authority.monthly_usage_buckets"),
        )
        self.assertIn("set consumed = bucket.consumed + new.units", event_insert_trigger)
        self.assertIn(
            "security definer\nset search_path = pg_catalog, gvai_authority",
            event_insert_trigger,
        )
        self.assertIn(
            "revoke update on gvai_authority.authority_state from public",
            sql,
        )

    def test_revoked_credentials_cannot_be_reactivated(self):
        sql = _migration_text()
        self.assertIn(
            "create trigger customer_credentials_revocation_monotonic",
            sql,
        )
        self.assertIn(
            "before update or delete on gvai_authority.customer_credentials",
            sql,
        )
        self.assertIn("old.status = 'revoked'", sql)
        self.assertIn("new.credential_verifier is distinct from old.credential_verifier", sql)
        self.assertIn("credential revocation is irreversible", sql)
        self.assertIn(
            "revoke delete, truncate",
            sql,
        )
        self.assertIn(
            "on gvai_authority.customer_credentials from public",
            sql,
        )

    def test_quota_bucket_only_advances_with_event_insert(self):
        sql = _migration_text()
        self.assertIn("create trigger monthly_usage_buckets_monotonic", sql)
        self.assertIn(
            "new.consumed <> old.consumed + 1",
            sql,
        )
        self.assertIn(
            "before update or delete on gvai_authority.monthly_usage_buckets",
            sql,
        )

    def test_status_period_and_quota_values_are_restricted(self):
        sql = _migration_text()
        for table_name, status_values in (
            ("tenants", "('active', 'disabled')"),
            ("tenant_memberships", "('active', 'disabled')"),
            ("customer_credentials", "('active', 'revoked', 'disabled')"),
            ("resource_ownerships", "('active', 'disabled', 'reassigned')"),
        ):
            with self.subTest(table=table_name):
                self.assertIn(
                    "check (status in " + status_values + ")",
                    _table_body(sql, table_name),
                )
        self.assertIn(
            "monthly_allowance between 0 and 9223372036854775807",
            _table_body(sql, "quota_policies"),
        )
        self.assertIn(
            "foreign key (tenant_ref, policy_version, allowance)",
            _table_body(sql, "monthly_usage_buckets"),
        )
        self.assertIn(
            "foreign key (tenant_ref, period_start, policy_version)",
            _table_body(sql, "reservation_events"),
        )
        bucket = _table_body(sql, "monthly_usage_buckets")
        self.assertIn("allowance between 0 and 9223372036854775807", bucket)
        self.assertIn("consumed between 0 and 9223372036854775807", bucket)
        self.assertIn("consumed <= allowance", bucket)
        self.assertIn("units smallint not null default 1 check (units = 1)", _table_body(sql, "reservation_events"))

    def test_credentials_store_only_fixed_length_verifier_and_revocation_state(self):
        body = _table_body(_migration_text(), "customer_credentials")
        self.assertRegex(
            body,
            r"credential_verifier bytea not null\s+"
            r"check \(octet_length\(credential_verifier\) = 32\)",
        )
        self.assertIn("status in ('active', 'revoked', 'disabled')", body)
        self.assertIn("revoked_at", body)
        self.assertIn("expires_at > created_at", body)
        forbidden_columns = {
            "credential",
            "raw_credential",
            "plaintext_credential",
            "credential_secret",
            "secret",
            "evaluation_body",
            "payload_body",
            "evaluation_result",
        }
        declared_columns = {
            line.strip().split()[0].rstrip(",")
            for line in body.splitlines()
            if line.strip() and not line.lstrip().startswith(("check ", "foreign ", "primary ", "unique "))
        }
        self.assertFalse(forbidden_columns & declared_columns)

    def test_events_store_digests_and_internal_references_not_raw_identifiers(self):
        body = _table_body(_migration_text(), "reservation_events")
        for column in ("tenant_digest", "principal_digest", "resource_digest"):
            self.assertRegex(body, r"\b" + column + r"\b")
        self.assertNotRegex(
            body,
            r"(?m)^\s*(tenant_id|principal_id|resource_id|request_id)\s",
        )

    def test_schema_has_no_supervisor_stop_dependency(self):
        sql = _migration_text()
        self.assertNotIn("supervisor", sql)
        self.assertNotIn("stop", sql)
        self.assertNotIn("gvai_external_control", sql)


if __name__ == "__main__":
    unittest.main()
