"""Offline source contracts, not PostgreSQL privilege or transaction evidence."""

import hashlib
import re
from pathlib import Path

import pytest

from gvai.subscription_entitlement import StripeEventType, SubscriptionStatus


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations/postgresql"
MIGRATION = MIGRATIONS / "004_subscription_billing_v1.sql"
SCOPE = "stripe_account_id, environment"
SUBSCRIPTION = SCOPE + ", tenant_ref, subscription_id"
TABLE_COLUMNS = {
    "billing_prices": (
        "stripe_account_id", "environment", "price_id", "product_id", "currency",
        "unit_amount", "interval_unit", "interval_count", "quantity", "approved",
    ),
    "billing_customers": (
        "stripe_account_id", "environment", "tenant_ref", "customer_id", "membership_ref",
    ),
    "billing_subscriptions": (
        "stripe_account_id", "environment", "tenant_ref", "customer_id",
        "subscription_id", "price_id", "status", "cancel_at", "terminal_canceled",
        "revision", "uncertain", "observed_at", "lease_generation", "lease_expires_at",
        "admitted",
    ),
    "billing_invoices": (
        "stripe_account_id", "environment", "tenant_ref", "subscription_id",
        "invoice_id", "status", "currency", "amount_paid", "verified", "revision",
    ),
    "billing_paid_intervals": (
        "stripe_account_id", "environment", "tenant_ref", "subscription_id",
        "invoice_id", "invoice_line_id", "price_id", "period_start", "period_end",
        "revision",
    ),
    "billing_event_inbox": (
        "stripe_account_id", "environment", "event_id", "event_type", "api_version",
        "payload", "payload_digest", "received_at", "state", "attempts",
        "lease_generation", "lease_expires_at", "error_code",
    ),
    "billing_reconciliations": (
        "stripe_account_id", "environment", "tenant_ref", "subscription_id",
        "revision", "reconciliation_id", "source_event_id", "observed_at",
        "lease_generation", "evidence_digest", "certain", "outcome",
    ),
    "billing_entitlements": (
        "stripe_account_id", "environment", "tenant_ref", "subscription_id",
        "revision", "eligibility", "uncertain", "coverage_start", "coverage_end",
        "fresh_until", "cancel_at",
    ),
    "billing_advisory_attempts": (
        "event_id", "stripe_account_id", "environment", "tenant_ref",
        "subscription_id", "revision", "state",
    ),
    "billing_installation": ("migration_id", "contract_version", "installed_at"),
}
KEYS = {
    "billing_prices": ("primary key", SCOPE + ", price_id"),
    "billing_customers": ("primary key", SCOPE + ", customer_id"),
    "billing_subscriptions": ("primary key", SCOPE + ", subscription_id"),
    "billing_invoices": ("primary key", SCOPE + ", invoice_id"),
    "billing_paid_intervals": ("primary key", SCOPE + ", invoice_id, invoice_line_id"),
    "billing_event_inbox": ("primary key", SCOPE + ", event_id"),
    "billing_reconciliations": ("primary key", SUBSCRIPTION + ", revision"),
    "billing_entitlements": ("primary key", SUBSCRIPTION),
}
FOREIGN_KEYS = (
    ("billing_customers", "tenant_ref, membership_ref", "tenant_memberships",
     "tenant_ref, membership_ref"),
    ("billing_subscriptions", SCOPE + ", tenant_ref, customer_id", "billing_customers",
     SCOPE + ", tenant_ref, customer_id"),
    ("billing_subscriptions", SCOPE + ", price_id", "billing_prices", SCOPE + ", price_id"),
    ("billing_invoices", SUBSCRIPTION, "billing_subscriptions", SUBSCRIPTION),
    ("billing_invoices", SUBSCRIPTION + ", revision", "billing_reconciliations",
     SUBSCRIPTION + ", revision"),
    ("billing_paid_intervals", SUBSCRIPTION + ", invoice_id", "billing_invoices",
     SUBSCRIPTION + ", invoice_id"),
    ("billing_paid_intervals", SUBSCRIPTION + ", price_id", "billing_subscriptions",
     SUBSCRIPTION + ", price_id"),
    ("billing_paid_intervals", SUBSCRIPTION + ", revision", "billing_reconciliations",
     SUBSCRIPTION + ", revision"),
    ("billing_reconciliations", SUBSCRIPTION, "billing_subscriptions", SUBSCRIPTION),
    ("billing_reconciliations", SCOPE + ", source_event_id", "billing_event_inbox",
     SCOPE + ", event_id"),
    ("billing_entitlements", SUBSCRIPTION + ", revision", "billing_reconciliations",
     SUBSCRIPTION + ", revision"),
    ("billing_advisory_attempts", SUBSCRIPTION + ", revision", "billing_reconciliations",
     SUBSCRIPTION + ", revision"),
)
ENTRY_FUNCTIONS = (
    "enqueue_billing_event_v1",
    "claim_billing_events_v1",
    "begin_billing_reconciliation_v1",
    "apply_billing_reconciliation_v1",
    "retry_billing_event_v1",
    "reserve_subscription_advisory_v1",
    "complete_subscription_advisory_v1",
    "subscription_advisory_usage_v1",
)


def _normalize(sql):
    # This deliberately limited source check is not a SQL parser.
    sql = re.sub(r"/\*.*?\*/|--[^\n]*", " ", sql, flags=re.DOTALL)
    return re.sub(r"\s+", " ", sql).strip().lower()


def _table(sql, name):
    match = re.search(
        r"\bcreate table gvai_authority\." + re.escape(name) + r"\s*\((.*?)\);",
        sql,
    )
    assert match is not None, "Missing CREATE TABLE: " + name
    return match.group(1)


def _declaration(sql, name):
    match = re.search(
        r"\bcreate function gvai_authority\." + re.escape(name)
        + r"\s*\(.*?\bas \$function\$",
        sql,
    )
    assert match is not None, "Missing function declaration: " + name
    return match.group(0)


@pytest.fixture(scope="module")
def billing_sql():
    if not MIGRATION.is_file():
        pytest.skip(
            "Migration 004 intentionally not implemented in Phase 2A; "
            "dependent structural contract remains unvalidated."
        )
    return _normalize(MIGRATION.read_text(encoding="utf-8"))


def test_proposed_migration_exists():
    assert MIGRATION.is_file(), (
        "Expected test-first failure: 004_subscription_billing_v1.sql is not "
        "implemented. Do not create a stub or weaken the contract to pass."
    )


@pytest.mark.parametrize("name,digest", [
    ("001_reservation_authority_v1.sql",
     "f07891a1ebe6de955b96db6f0bbf88c7267ddde5e4367886cef06a1c025755af"),
    ("002_restricted_reservation_routine_v1.sql",
     "b9d73dbb0de5039ed8c7ce0aac99a64773660a8a7563fbd90ebbbf79ec16ecba"),
    ("003_advisory_pilots_v1.sql",
     "d5c6d46140bd21b2b6e848b142b23a162f99bab072a8cc9107d818c0069216a6"),
])
def test_existing_migrations_are_preserved_byte_for_byte(name, digest):
    assert hashlib.sha256((MIGRATIONS / name).read_bytes()).hexdigest() == digest


def test_existing_utc_month_accounting_and_pilot_gate_remain_explicit():
    reservation = _normalize(
        (MIGRATIONS / "002_restricted_reservation_routine_v1.sql").read_text()
    )
    assert "date_trunc( 'month', pg_catalog.clock_timestamp() at time zone 'utc' )" in reservation
    assert "gvai_authority.monthly_usage_buckets" in reservation
    pilot = _normalize((MIGRATIONS / "003_advisory_pilots_v1.sql").read_text())
    assert "from gvai_authority.advisory_pilots" in pilot
    assert "not pilot.active" in pilot
    assert "pilot.expires_at <= authorization_time" in pilot


def test_source_extractors_read_existing_objects_but_not_commented_declarations():
    schema = _normalize((MIGRATIONS / "001_reservation_authority_v1.sql").read_text())
    assert "tenant_id text not null unique" in _table(schema, "tenants")
    pilot = _normalize((MIGRATIONS / "003_advisory_pilots_v1.sql").read_text())
    assert "security definer" in _declaration(pilot, "reserve_advisory_v1")
    for comment in (
        "-- CREATE TABLE gvai_authority.fake (id bigint);\n",
        "/* CREATE TABLE gvai_authority.fake (id bigint); */",
    ):
        with pytest.raises(AssertionError, match="Missing CREATE TABLE"):
            _table(_normalize(comment), "fake")


def test_migration_is_atomic_additive_and_not_a_role_or_activation_script(billing_sql):
    assert billing_sql.startswith("begin;")
    assert billing_sql.endswith("commit;")
    for pattern in (
        r"\bcreate (?:role|user)\b", r"\balter (?:role|user|default privileges)\b",
        r"\bgrant\b", r"\bcreate or replace\b", r"\bdrop\b",
        r"\b(?:alter table|truncate|delete from|update|insert into)\s+"
        r"gvai_authority\.(?!billing_)",
    ):
        assert not re.search(pattern, billing_sql), pattern
    # Exclude stored bodies: future routines must insert records when called,
    # but the installation itself must never seed payment/customer access.
    installation_sql = re.sub(
        r"(\$(?:[a-z_][a-z_0-9]*)?\$).*?\1", " ", billing_sql
    )
    assert not re.search(
        r"\binsert into gvai_authority\.billing_(?!installation\b)", installation_sql
    )
    assert "current_user" in billing_sql and "rolsuper" in billing_sql
    installation = _table(billing_sql, "billing_installation")
    assert "'004_subscription_billing_v1'" in installation
    assert "contract_version = 1" in installation


@pytest.mark.parametrize("name,columns", TABLE_COLUMNS.items())
def test_required_tables_and_columns_are_declared(billing_sql, name, columns):
    body = _table(billing_sql, name)
    for column in columns:
        assert re.search(r"(?:^|,)\s*" + re.escape(column) + r"\s+\w+", body), column


@pytest.mark.parametrize("name,key", KEYS.items())
def test_stripe_object_identity_is_scoped_by_account_and_environment(billing_sql, name, key):
    assert key[0] + " (" + key[1] + ")" in _table(billing_sql, name)


@pytest.mark.parametrize("name", [
    name for name in TABLE_COLUMNS if name != "billing_installation"
])
def test_scoping_fields_cannot_be_null_or_cross_environment(billing_sql, name):
    body = _table(billing_sql, name)
    assert "stripe_account_id text not null" in body
    assert "environment text not null" in body
    assert "environment in ('sandbox')" in body


def test_prices_are_explicitly_approved_and_server_selected(billing_sql):
    body = _table(billing_sql, "billing_prices")
    for declaration in (
        "approved boolean not null default false",
        "currency text not null", "unit_amount bigint not null",
        "interval_unit text not null", "interval_count integer not null",
        "quantity integer not null",
    ):
        assert declaration in body
    for check in (
        "currency = 'usd'", "unit_amount = 9900", "interval_unit = 'month'",
        "interval_count = 1", "quantity = 1",
    ):
        assert check in body


@pytest.mark.parametrize("source,columns,target,target_columns", FOREIGN_KEYS)
def test_composite_relationships_bind_tenant_and_stripe_context(
    billing_sql, source, columns, target, target_columns
):
    body = _table(billing_sql, source)
    assert (
        "foreign key (" + columns + ") references gvai_authority."
        + target + " (" + target_columns + ")"
    ) in body
    for column in columns.split(", "):
        if column != "source_event_id":
            assert re.search(re.escape(column) + r"\s+\w+\s+not null", body), column


def test_parent_keys_support_composite_references_and_customer_uniqueness(billing_sql):
    assert "unique (" + SCOPE + ", tenant_ref)" in _table(billing_sql, "billing_customers")
    assert (
        "unique (" + SCOPE + ", tenant_ref, customer_id)"
        in _table(billing_sql, "billing_customers")
    )
    subscription = _table(billing_sql, "billing_subscriptions")
    for suffix in ("", ", price_id"):
        assert "unique (" + SUBSCRIPTION + suffix + ")" in subscription
    assert (
        "unique (" + SUBSCRIPTION + ", invoice_id)"
        in _table(billing_sql, "billing_invoices")
    )
    assert "unique (" + SCOPE + ", reconciliation_id)" in _table(
        billing_sql, "billing_reconciliations"
    )
    assert re.search(
        r"create unique index billing_subscriptions_one_current on "
        r"gvai_authority\.billing_subscriptions \(" + re.escape(SCOPE)
        + r", tenant_ref\) where admitted",
        billing_sql,
    )


def test_subscription_and_entitlement_defaults_cannot_activate_access(billing_sql):
    subscription = _table(billing_sql, "billing_subscriptions")
    for declaration in (
        "status text not null default 'incomplete'",
        "terminal_canceled boolean not null default false",
        "uncertain boolean not null default true",
        "admitted boolean not null default false",
    ):
        assert declaration in subscription
    for status in SubscriptionStatus:
        assert "'" + status.value + "'" in subscription
    projection = _table(billing_sql, "billing_entitlements")
    assert "eligibility text not null default 'deny'" in projection
    assert "eligibility in ('deny', 'eligible')" in projection
    assert "uncertain boolean not null default true" in projection
    assert "eligibility = 'deny'" in projection
    for expression in (
        "coverage_start is not null", "coverage_end is not null",
        "fresh_until is not null", "not uncertain", "coverage_end > coverage_start",
        "isfinite(coverage_start)", "isfinite(coverage_end)", "isfinite(fresh_until)",
    ):
        assert expression in projection


def test_paid_intervals_and_invoice_verification_have_explicit_constraints(billing_sql):
    invoices = _table(billing_sql, "billing_invoices")
    assert "verified boolean not null default false" in invoices
    assert "status = 'paid'" in invoices
    assert "amount_paid >= 0" in invoices
    intervals = _table(billing_sql, "billing_paid_intervals")
    for expression in (
        "period_start timestamptz not null", "period_end timestamptz not null",
        "isfinite(period_start)", "isfinite(period_end)", "period_end > period_start",
    ):
        assert expression in intervals
    assert "on delete cascade" not in billing_sql


def test_event_inbox_is_bounded_default_pending_and_not_payment_authority(billing_sql):
    body = _table(billing_sql, "billing_event_inbox")
    for expression in (
        "state text not null default 'pending'", "attempts bigint not null default 0",
        "attempts >= 0", "payload bytea not null", "payload_digest bytea not null",
        "octet_length(payload)", "octet_length(payload_digest) = 32",
        "received_at timestamptz not null default clock_timestamp()",
    ):
        assert expression in body
    assert re.search(r"octet_length\(payload\)\s+between\s+1\s+and\s+[1-9][0-9]*", body)
    for state in ("pending", "processing", "processed", "retry", "quarantined"):
        assert "'" + state + "'" in body
    for event_type in StripeEventType:
        assert "'" + event_type.value + "'" in body
    assert "create index billing_event_inbox_claimable" in billing_sql


def test_reconciliation_has_revisions_leases_and_explicit_uncertainty(billing_sql):
    for name in ("billing_subscriptions", "billing_event_inbox", "billing_reconciliations"):
        body = _table(billing_sql, name)
        assert "lease_generation bigint not null" in body
        assert "lease_generation >= 0" in body
    for name in ("billing_subscriptions", "billing_reconciliations"):
        assert "revision >= 0" in _table(billing_sql, name)
    reconciliations = _table(billing_sql, "billing_reconciliations")
    assert "certain boolean not null default false" in reconciliations
    assert "octet_length(evidence_digest) = 32" in reconciliations
    assert "isfinite(observed_at)" in reconciliations


@pytest.mark.parametrize("name,table,events", [
    ("billing_subscription_transition_guard", "billing_subscriptions", "before update or delete"),
    ("billing_invoice_evidence_guard", "billing_invoices", "before update or delete"),
    ("billing_paid_intervals_append_only", "billing_paid_intervals", "before update or delete"),
    ("billing_reconciliations_append_only", "billing_reconciliations", "before update or delete"),
    ("billing_event_identity_guard", "billing_event_inbox", "before update or delete"),
    ("billing_entitlement_consistency", "billing_entitlements", "after insert or update"),
])
def test_declared_guards_are_attached_to_the_correct_tables(billing_sql, name, table, events):
    assert re.search(
        r"create (?:constraint )?trigger " + name + " " + events
        + " on gvai_authority\\." + table + r"\b.*?execute (?:function|procedure) "
        + r"gvai_authority\.\w+\s*\(",
        billing_sql,
    ), name


@pytest.mark.parametrize("name", ENTRY_FUNCTIONS)
def test_future_role_entrypoints_declare_definer_and_trusted_search_path(billing_sql, name):
    declaration = _declaration(billing_sql, name)
    assert "security definer" in declaration
    assert "set search_path = pg_catalog, gvai_authority, pg_temp" in declaration


def test_all_declared_objects_revoke_public_access_without_runtime_grants(billing_sql):
    objects = re.findall(r"create (table|function) gvai_authority\.(\w+)", billing_sql)
    assert objects
    for kind, name in objects:
        assert name.startswith("billing_") or name in ENTRY_FUNCTIONS
        assert re.search(
            r"revoke all(?: privileges)? on " + kind
            + r"\s+gvai_authority\." + name + r"\b[^;]*\bfrom public\s*;",
            billing_sql,
        ), name
    assert not re.search(r"\bgrant\b", billing_sql)


def test_paid_attempts_reference_existing_reservation_events(billing_sql):
    body = _table(billing_sql, "billing_advisory_attempts")
    assert "event_id text primary key references gvai_authority.reservation_events" in body
    assert "state in ('reserved', 'completed', 'failed')" in body
