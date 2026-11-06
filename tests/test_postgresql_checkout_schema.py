"""Test-first source contracts only; no PostgreSQL or Stripe execution."""

import hashlib
import re
from pathlib import Path

import pytest

from gvai.checkout_attempts import AttemptState


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations/postgresql"
MIGRATION = MIGRATIONS / "005_checkout_attempts_v1.sql"
SCOPE = "stripe_account_id, environment"
IDENTITY = SCOPE + ", attempt_id"
ENTRYPOINTS = (
    "prepare_checkout_attempt_v1", "claim_checkout_attempt_v1",
    "confirm_checkout_session_v1", "claim_checkout_reconciliation_v1",
    "mark_checkout_unknown_v1", "quarantine_checkout_attempt_v1",
    "expire_checkout_unsent_v1", "close_checkout_verified_v1",
)
TABLES = {
    "checkout_authorizations": (
        "authorization_ref", "issuer", "principal_id", "tenant_ref", "membership_ref",
        "active", "checkout_approved", "expires_at",
    ),
    "checkout_attempts": (
        "stripe_account_id", "environment", "attempt_id", "authorization_ref",
        "issuer", "principal_id", "tenant_ref", "membership_ref", "customer_id",
        "price_id", "intent_bytes", "intent_fingerprint", "request_bytes",
        "request_fingerprint", "parameters", "idempotency_key", "adapter_version",
        "api_version", "state", "generation", "created_at", "updated_at",
        "prepare_expires_at", "lease_id", "lease_expires_at", "session_id",
        "session_status", "session_observed_at", "session_expires_at",
        "subscription_id", "handoff_id",
    ),
    "checkout_handoffs": (
        "handoff_id", "stripe_account_id", "environment", "tenant_ref",
        "attempt_id", "session_id", "customer_id", "subscription_id", "price_id",
        "verified_at",
    ),
}
BASELINES = {
    "001_reservation_authority_v1.sql":
        "f07891a1ebe6de955b96db6f0bbf88c7267ddde5e4367886cef06a1c025755af",
    "002_restricted_reservation_routine_v1.sql":
        "b9d73dbb0de5039ed8c7ce0aac99a64773660a8a7563fbd90ebbbf79ec16ecba",
    "003_advisory_pilots_v1.sql":
        "d5c6d46140bd21b2b6e848b142b23a162f99bab072a8cc9107d818c0069216a6",
    "004_subscription_billing_v1.sql":
        "1d61e4786db8c49c752315dfef1643f23961a1b22bb88889d5cdc5943df6642b",
}
SQL_REGIONS = re.compile(
    r"/\*.*?\*/|--[^\n]*|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\""
    r"|\$(?P<tag>[a-z_][a-z0-9_]*|)\$.*?\$(?P=tag)\$",
    flags=re.DOTALL | re.IGNORECASE,
)


def strip_comments(sql):
    def replace(match):
        text = match[0]
        if text.startswith(("/*", "--")):
            assert not text.startswith("/*") or "/*" not in text[2:-2], (
                "Nested SQL comments are unsupported"
            )
            return " "
        if text.startswith("$"):
            delimiter = "$" + match["tag"] + "$"
            return delimiter + strip_comments(text[len(delimiter):-len(delimiter)]) + delimiter
        return text

    return SQL_REGIONS.sub(replace, sql)


def normalize(sql):
    # Constrained source spelling, not a SQL parser or a proof of effective behavior.
    return re.sub(r"\s+", " ", strip_comments(sql)).strip().lower()


def table(sql, name):
    match = re.search(
        r"\bcreate table gvai_authority\." + re.escape(name) + r"\s*\((.*?)\);", sql,
    )
    assert match, "Missing table: " + name
    return match[1]


def source_outline(sql):
    # Keep offsets and identifier quote markers, never literal ACL/declaration text.
    def replace(match):
        if match[0].startswith('"'):
            return '"' + " " * (len(match[0]) - 2) + '"'
        return " " * len(match[0])

    return SQL_REGIONS.sub(replace, sql)


def input_signature(declaration, name):
    match = re.match(r"([^()]*)\)\s*returns\b", declaration)
    assert match, "Unsupported function signature: " + name
    arguments = match[1].strip()
    types = []
    for argument in arguments.split(",") if arguments else ():
        parsed = re.fullmatch(
            r"\s*p_[a-z0-9_]+\s+([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?(?:\[\])?)\s*",
            argument,
        )
        assert parsed, "Unsupported function argument: " + name
        types.append(parsed[1])
    return ", ".join(types)


def function_inventory(sql):
    functions = {}
    for start in re.finditer(r"\bcreate\b", source_outline(sql)):
        if re.match(
            r"create (?:table|(?:unique )?index|(?:constraint )?trigger)\b",
            sql[start.start():],
        ):
            continue
        match = re.match(
            r"create function gvai_authority\.([a-z_][a-z0-9_]*)\s*"
            r"\((.*?)\bas \$function\$(.*?)\$function\$;",
            sql[start.start():],
        )
        assert match, "Unsupported function declaration or CREATE form"
        name, declaration, body = match.groups()
        assert not re.search(r'["$;\\]', declaration), (
            "Unsupported function declaration: " + name
        )
        input_signature(declaration, name)
        assert name not in functions, "Overloaded function forbidden: " + name
        functions[name] = (declaration, body)
    return functions


def function(sql, name):
    functions = function_inventory(sql)
    assert name in functions, "Missing function: " + name
    return functions[name]


def function_signature(sql, name):
    declaration, _ = function(sql, name)
    return input_signature(declaration, name)


def assert_safe_search_path(declaration):
    outline = source_outline(declaration)
    assert len(re.findall(r"\bsearch_path\b", outline)) == 1, (
        "Missing or repeated search_path"
    )
    settings = list(re.finditer(r"\bset\b", outline))
    paths = []
    for index, setting in enumerate(settings):
        end = settings[index + 1].start() if index + 1 < len(settings) else len(outline)
        clause = declaration[setting.start():end].strip()
        if re.match(r"set\s+search_path\b", clause):
            parsed = re.fullmatch(
                r"set\s+search_path\s*=\s*([a-z_][a-z0-9_]*"
                r"(?:\s*,\s*[a-z_][a-z0-9_]*)*)", clause,
            )
            assert parsed, "Unsupported search_path setting"
            paths.append(tuple(part.strip() for part in parsed[1].split(",")))
    assert paths == [("pg_catalog", "gvai_authority", "pg_temp")], (
        "Unapproved search_path"
    )


@pytest.fixture(scope="module")
def checkout_sql():
    if not MIGRATION.is_file():
        pytest.skip("Migration 005 absent by design; SQL-dependent contract is unvalidated.")
    return normalize(MIGRATION.read_text(encoding="utf-8"))


def test_proposed_migration_exists():
    assert MIGRATION.is_file(), (
        "Expected Phase 3C test-first failure: migration 005 is not implemented. "
        "Keep it absent until separately authorized; do not create dummy SQL."
    )


@pytest.mark.parametrize("name,digest", BASELINES.items())
def test_existing_migrations_preserved(name, digest):
    assert hashlib.sha256((MIGRATIONS / name).read_bytes()).hexdigest() == digest


def test_extractors_read_real_source_and_ignore_comment_only_declarations():
    existing = normalize((MIGRATIONS / "004_subscription_billing_v1.sql").read_text())
    assert "approved boolean not null default false" in table(existing, "billing_prices")
    declaration, body = function(existing, "claim_billing_events_v1")
    assert "security definer" in declaration and "for update skip locked" in body
    for comment in (
        "-- CREATE TABLE gvai_authority.fake (id bigint);\n",
        "/* CREATE TABLE gvai_authority.fake (id bigint); */",
    ):
        with pytest.raises(AssertionError, match="Missing table"):
            table(normalize(comment), "fake")
    with pytest.raises(AssertionError, match="Missing function"):
        function(normalize("-- CREATE FUNCTION gvai_authority.fake()"), "fake")


def _function_fixture(arguments, *, definer=False):
    """In-memory SQL for extractor tests only, never a migration implementation."""
    return (
        "create function gvai_authority.checkout_probe(" + arguments + ") "
        "returns text language plpgsql "
        + ("security definer set search_path = pg_catalog, gvai_authority, pg_temp "
           if definer else "")
        + "as $function$ begin return 'fixture'; end; $function$;"
    )


@pytest.mark.parametrize("definer_first", [False, True])
def test_overloads_cannot_hide_definer_or_share_one_revocation(definer_first):
    sql = normalize(
        _function_fixture("p_value integer", definer=definer_first)
        + _function_fixture("p_value text", definer=not definer_first)
        + "revoke all on function gvai_authority.checkout_probe(integer) from public;"
    )
    with pytest.raises(AssertionError, match="Overloaded function"):
        function(sql, "checkout_probe")
    with pytest.raises(AssertionError, match="Overloaded function"):
        test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


def test_even_fully_revoked_overloads_are_outside_the_contract():
    sql = normalize(
        _function_fixture("p_value integer")
        + _function_fixture("p_value text", definer=True)
        + "revoke all on function gvai_authority.checkout_probe(integer) from public;"
        + "revoke all on function gvai_authority.checkout_probe(text) from public;"
    )
    with pytest.raises(AssertionError, match="Overloaded function"):
        test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


@pytest.mark.parametrize("arguments", [
    "p_value integer default 1", "out p_value text", "p_value numeric(10,2)",
    "in p_value integer", "inout p_value text", "variadic p_values text[]",
    "p_value double precision", 'p_value "integer"', "p_value integer = 1",
])
def test_unsupported_argument_syntax_is_not_silently_ignored(arguments):
    with pytest.raises(AssertionError, match="Unsupported function"):
        function_signature(normalize(_function_fixture(arguments)), "checkout_probe")


@pytest.mark.parametrize("signature", ["", "(text)", "(integer, text)"])
def test_name_only_or_wrong_signature_revocation_is_not_proof(signature):
    sql = normalize(
        _function_fixture("p_value integer")
        + "revoke all on function gvai_authority.checkout_probe"
        + signature + " from public;"
    )
    with pytest.raises(AssertionError, match="Missing exact PUBLIC revocation"):
        test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


@pytest.mark.parametrize("arguments,signature", [
    ("", "()"), ("p_value integer", "(integer)"),
    ("p_value text, p_digest bytea", "(text, bytea)"),
    ("p_expected_record gvai_authority.checkout_attempts, p_values text[]",
     "(gvai_authority.checkout_attempts, text[])"),
])
def test_exact_signature_revocation_is_accepted(arguments, signature):
    sql = normalize(
        _function_fixture(arguments, definer=True)
        + "revoke all privileges on function gvai_authority.checkout_probe"
        + signature + " from public;"
    )
    test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


@pytest.mark.parametrize("spelling", [
    'gvai_authority."checkout_probe"', '"gvai_authority".checkout_probe',
    '"gvai_authority"."checkout_probe"', 'gvai_authority.u&"checkout_probe"',
    "gvai_authority . checkout_probe", "checkout_probe",
    "public.checkout_probe", "gvai_authority.checkout_probe$hidden",
])
@pytest.mark.parametrize("hidden_first", [False, True])
def test_unsupported_names_cannot_hide_unrevoked_definer(spelling, hidden_first):
    plain = _function_fixture("p_value integer")
    hidden = _function_fixture("p_value text", definer=True).replace(
        "gvai_authority.checkout_probe", spelling,
    )
    sql = normalize(
        (hidden + plain if hidden_first else plain + hidden)
        + "revoke all on function gvai_authority.checkout_probe(integer) from public;"
    )
    with pytest.raises(AssertionError, match="Unsupported function"):
        function(sql, "checkout_probe")
    with pytest.raises(AssertionError, match="Unsupported function"):
        test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


@pytest.mark.parametrize("replacement", [
    "create or replace function", "create /* split */ or replace function",
    "create temporary function", "create function",
])
def test_unsupported_declarations_are_not_ignored(replacement):
    hidden = _function_fixture("p_value text", definer=True).replace(
        "create function", replacement,
    )
    if replacement == "create function":
        hidden = hidden.replace("$function$", "$hidden$")
    sql = normalize(_function_fixture("p_value integer") + hidden)
    with pytest.raises(AssertionError, match="Unsupported function"):
        function(sql, "checkout_probe")


def test_missing_or_literal_only_revocation_is_rejected():
    for suffix in ("", "select 'revoke all on function "
                   "gvai_authority.checkout_probe(integer) from public;';",
                   'select 1 as "revoke all on function '
                   'gvai_authority.checkout_probe(integer) from public;";'):
        with pytest.raises(AssertionError, match="Missing exact PUBLIC revocation"):
            test_all_new_objects_revoke_public_and_do_not_seed_approval(normalize(
                _function_fixture("p_value integer", definer=True) + suffix,
            ))


def test_inventory_ignores_literal_decoys_but_not_following_declarations():
    sql = normalize(
        "select '--', '/*', 'create function gvai_authority.checkout_probe()';"
        + _function_fixture("p_value integer")
        + "revoke all on function gvai_authority.checkout_probe(integer) from public;"
    )
    test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)
    with pytest.raises(AssertionError, match="Overloaded function"):
        function(sql + normalize(_function_fixture("p_value text")), "checkout_probe")


def test_supported_declaration_case_comments_and_spacing():
    sql = normalize(
        _function_fixture("p_value integer").upper().replace(
            "CREATE FUNCTION", "CREATE\n/* header */ FUNCTION",
        )
        + "REVOKE ALL ON FUNCTION gvai_authority.checkout_probe(integer) FROM PUBLIC;"
    )
    test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


def _entrypoint_fixture(settings):
    return normalize(
        "create function gvai_authority.prepare_checkout_attempt_v1() "
        "returns text language plpgsql security definer " + settings
        + " as $function$ begin "
        "perform 1 from gvai_authority.tenants for update; "
        "perform clock_timestamp(); return 'fixture'; end; $function$;"
    )


@pytest.mark.parametrize("settings", [
    "set search_path = pg_catalog, gvai_authority, pg_temp, public",
    "set search_path = public, pg_catalog, gvai_authority, pg_temp",
    "set search_path = gvai_authority, pg_catalog, pg_temp",
    "set search_path = pg_catalog, gvai_authority, pg_temp, pg_temp",
    "set search_path = pg_catalog, gvai_authority, pg_temp_suffix",
    "set search_path = pg_catalog, gvai_authority, pg_temp.public",
    'set search_path = pg_catalog, gvai_authority, pg_temp, "public"',
    'set search_path = "pg_catalog", gvai_authority, pg_temp',
    'set search_path = pg_catalog, gvai_authority, "pg_temp"',
    "set search_path = 'pg_catalog, gvai_authority, pg_temp'",
    "set search_path = pg_catalog, gvai_authority, pg_temp 'public'",
    "set search_path = pg_catalog, gvai_authority, pg_temp public",
    "set search_path = pg_catalog, gvai_authority, pg_temp,",
    "set search_path = pg_catalog,, gvai_authority, pg_temp",
    "set search_path = pg_catalog gvai_authority, pg_temp",
    "set search_path = pg_catalog, gvai_authority, pg_temp "
    "set search_path = public",
    "set search_path = pg_catalog, gvai_authority, pg_temp "
    'set "search_path" = public',
    "set search_path = pg_catalog, gvai_authority, pg_temp "
    "set search_path from current",
    "set search_path to pg_catalog, gvai_authority, pg_temp",
    "set search_path from current",
    "",
])
def test_unapproved_or_ambiguous_search_path_is_rejected(settings):
    with pytest.raises(AssertionError):
        test_entrypoints_are_definer_fenced_and_restricted(
            _entrypoint_fixture(settings), "prepare_checkout_attempt_v1",
        )


@pytest.mark.parametrize("settings", [
    "set search_path = pg_catalog, gvai_authority, pg_temp",
    "SET search_path=pg_catalog,gvai_authority,pg_temp",
    "set\nsearch_path\t=\npg_catalog ,\tgvai_authority , pg_temp",
    "set search_path = pg_catalog, gvai_authority, pg_temp "
    "set statement_timeout = '5s'",
])
def test_exact_search_path_allows_only_documented_formatting(settings):
    test_entrypoints_are_definer_fenced_and_restricted(
        _entrypoint_fixture(settings), "prepare_checkout_attempt_v1",
    )


def test_private_definer_helpers_also_require_exact_search_path():
    sql = normalize(
        _function_fixture("p_value integer", definer=True).replace(
            "gvai_authority, pg_temp", "gvai_authority, pg_temp, public",
        )
        + "revoke all on function gvai_authority.checkout_probe(integer) from public;"
    )
    with pytest.raises(AssertionError, match="Unapproved search_path"):
        test_all_new_objects_revoke_public_and_do_not_seed_approval(sql)


def test_atomic_additive_and_not_activation_or_role_provisioning(checkout_sql):
    assert checkout_sql.startswith("begin;") and checkout_sql.endswith("commit;")
    for pattern in (
        r"\bgrant\b", r"\bcreate (?:role|user)\b", r"\bdrop\b",
        r"\bcreate or replace\b", r"\btruncate\b", r"\bon delete cascade\b",
        r"\bexecute\s+(?:format\s*\(|')",
    ):
        assert not re.search(pattern, checkout_sql), pattern
    assert "non-superuser" in (ROOT / "docs/postgresql_checkout_schema_contract_v1.md").read_text()
    assert "rolsuper" in checkout_sql and "nspowner" in checkout_sql


def test_alter_only_adds_constraints_to_new_checkout_tables(checkout_sql):
    for statement in re.findall(r"\balter\b[^;]*;", checkout_sql):
        assert re.match(
            r"alter table gvai_authority\.(?:"
            + "|".join(TABLES) + r") add constraint \w+\s+", statement,
        ), statement


@pytest.mark.parametrize("name,columns", TABLES.items())
def test_required_tables_and_columns(checkout_sql, name, columns):
    body = table(checkout_sql, name)
    for column in columns:
        assert re.search(r"(?:^|,)\s*" + column + r"\s+\w+", body), column


def test_authorization_is_explicit_and_membership_bound(checkout_sql):
    body = table(checkout_sql, "checkout_authorizations")
    for expression in (
        "issuer text not null", "principal_id text not null", "tenant_ref bigint not null",
        "membership_ref bigint not null", "active boolean not null default false",
        "checkout_approved boolean not null default false",
        "unique (issuer, principal_id, tenant_ref)",
        "foreign key (tenant_ref, membership_ref) references "
        "gvai_authority.tenant_memberships (tenant_ref, membership_ref)",
        "unique (authorization_ref, issuer, principal_id, tenant_ref, membership_ref)",
    ):
        assert expression in body


def test_authorization_guard_checks_principal_and_retains_identity(checkout_sql):
    _, guard = function(checkout_sql, "checkout_authorization_guard")
    for token in (
        "tenant_memberships", "principal_id", "membership_ref", "tenant_ref",
        "old.issuer", "new.issuer", "old.principal_id", "new.principal_id",
        "old.tenant_ref", "new.tenant_ref", "old.membership_ref", "new.membership_ref",
        "is distinct from", "raise exception",
    ):
        assert token in guard


@pytest.mark.parametrize("columns,target,parent", [
    ("authorization_ref, issuer, principal_id, tenant_ref, membership_ref",
     "checkout_authorizations",
     "authorization_ref, issuer, principal_id, tenant_ref, membership_ref"),
    (SCOPE + ", tenant_ref, customer_id", "billing_customers",
     SCOPE + ", tenant_ref, customer_id"),
    (SCOPE + ", price_id", "billing_prices", SCOPE + ", price_id"),
])
def test_attempt_composite_associations(checkout_sql, columns, target, parent):
    body = table(checkout_sql, "checkout_attempts")
    assert f"foreign key ({columns}) references gvai_authority.{target} ({parent})" in body
    for column in columns.split(", "):
        assert re.search(r"\b" + column + r"\s+\w+\s+not null", body)


def test_identity_and_uniqueness_are_not_tenant_scoped_only(checkout_sql):
    body = table(checkout_sql, "checkout_attempts")
    for expression in (
        f"primary key ({IDENTITY})", f"unique ({SCOPE}, idempotency_key)",
        f"unique ({SCOPE}, session_id)", "environment in ('sandbox')",
        "attempt_id ~ '^[0-9a-f]{32}$'",
        "attempt_id <> '00000000000000000000000000000000'",
    ):
        assert expression in body
    assert re.search(
        r"create unique index checkout_attempts_one_unresolved on "
        r"gvai_authority\.checkout_attempts \(tenant_ref\) where "
        r"state not in \('expired_unsent', 'closed_verified'\)", checkout_sql,
    )


def test_bytes_digests_and_versions_are_required_not_jsonb_reserialization(checkout_sql):
    body = table(checkout_sql, "checkout_attempts")
    for column in ("intent_bytes", "request_bytes", "parameters"):
        assert column + " bytea not null" in body
        assert re.search(r"octet_length\(" + column + r"\) between 1 and [1-9][0-9]*", body)
    for column in ("intent_fingerprint", "request_fingerprint"):
        assert column + " bytea not null" in body
        assert f"octet_length({column}) = 32" in body
    for column in ("idempotency_key", "adapter_version", "api_version"):
        assert column + " text not null" in body
    _, guard = function(checkout_sql, "checkout_request_guard")
    for token in ("digest(", "intent_bytes", "request_bytes", "parameters", "raise exception"):
        assert token in guard


def test_lifecycle_defaults_all_states_and_bounded_generation(checkout_sql):
    body = table(checkout_sql, "checkout_attempts")
    for state in AttemptState:
        assert "'" + state.value + "'" in body
    for expression in (
        "state text not null default 'prepared'", "generation bigint not null default 0",
        "generation >= 0", "prepare_expires_at > created_at",
        "updated_at >= created_at", "session_id is not null",
        "lease_id is not null", "lease_expires_at is not null",
    ):
        assert expression in body
    _, guard = function(checkout_sql, "checkout_attempt_guard")
    for token in (
        "old.generation", "new.generation", "9223372036854775807",
        "old.state", "new.state", "raise exception",
    ):
        assert token in guard


def test_policy_times_and_lease_session_shapes_have_explicit_guards(checkout_sql):
    body = table(checkout_sql, "checkout_attempts")
    for column in ("created_at", "updated_at", "prepare_expires_at"):
        assert column + " timestamptz not null" in body
        assert re.search(
            r"(?:billing_valid_time|checkout_valid_time)\(" + column + r"\)", body,
        )
    for column in ("lease_expires_at", "session_observed_at", "session_expires_at"):
        assert column + " is null" in body
        assert re.search(
            r"(?:billing_valid_time|checkout_valid_time)\(" + column + r"\)", body,
        )
    for token in ("session_status", "'open'", "'expired'", "'complete'",
                  "subscription_id is not null", "handoff_id is not null"):
        assert token in body


@pytest.mark.parametrize("name,guard,events", [
    ("checkout_authorizations", "checkout_authorization_guard", "before insert or update or delete"),
    ("checkout_attempts", "checkout_request_guard", "before insert or update"),
    ("checkout_attempts", "checkout_attempt_guard", "before update or delete"),
    ("checkout_handoffs", "checkout_handoff_guard", "before insert or update or delete"),
])
def test_guards_attached_not_comment_only(checkout_sql, name, guard, events):
    assert re.search(
        r"create trigger \w+ " + events + r" on gvai_authority\." + name
        + r"\b[^;]*execute function gvai_authority\." + guard + r"\(\)", checkout_sql,
    )
    function(checkout_sql, guard)


def test_immutable_attempt_fields_have_old_new_comparisons(checkout_sql):
    _, guard = function(checkout_sql, "checkout_attempt_guard")
    for column in (
        "stripe_account_id", "environment", "attempt_id", "authorization_ref",
        "issuer", "principal_id", "tenant_ref", "membership_ref", "customer_id",
        "price_id", "intent_bytes", "intent_fingerprint", "request_bytes",
        "request_fingerprint", "parameters", "idempotency_key", "adapter_version",
        "api_version", "created_at", "prepare_expires_at",
    ):
        assert "old." + column in guard and "new." + column in guard, column
    assert "is distinct from" in guard and "raise exception" in guard


@pytest.mark.parametrize("name", ENTRYPOINTS)
def test_entrypoints_are_definer_fenced_and_restricted(checkout_sql, name):
    declaration, body = function(checkout_sql, name)
    assert "security definer" in declaration
    assert_safe_search_path(declaration)
    assert "for update" in body
    assert "clock_timestamp()" in body
    if name != "prepare_checkout_attempt_v1":
        assert "p_expected_generation" in declaration
        assert "p_expected_record" in declaration
        assert "generation" in body and "p_expected_record" in body


def test_prepare_replay_conflict_and_current_authorization_checks(checkout_sql):
    _, body = function(checkout_sql, "prepare_checkout_attempt_v1")
    for token in (
        "on conflict", "'duplicate'", "'conflict'", "request_bytes",
        "parameters", "checkout_authorizations", "tenant_memberships",
        "checkout_approved", "expires_at", "billing_prices", "approved",
        "billing_customers", "advisory_pilots", "billing_subscriptions", "admitted",
    ):
        assert token in body
    assert "on conflict do update" not in body


def test_creation_only_prepared_and_recovery_never_creates_dispatch(checkout_sql):
    _, claim = function(checkout_sql, "claim_checkout_attempt_v1")
    for token in (
        "'prepared'", "'dispatching'", "prepare_expires_at", "checkout_authorizations",
        "checkout_approved", "tenant_memberships", "billing_prices", "billing_customers",
        "advisory_pilots", "billing_subscriptions", "admitted",
        "p_lease_seconds", "between 1 and 300", "9223372036854775807",
    ):
        assert token in claim
    _, recovery = function(checkout_sql, "claim_checkout_reconciliation_v1")
    for token in ("'unknown'", "'session_attached'", "lease_expires_at",
                  "p_lease_seconds", "between 1 and 300"):
        assert token in recovery
    assert not re.search(r"\bset state\s*=\s*'dispatching'", recovery)


def test_confirmation_compares_request_and_external_associations(checkout_sql):
    _, body = function(checkout_sql, "confirm_checkout_session_v1")
    for token in (
        "p_lease_id", "lease_expires_at", "request_fingerprint", "request_bytes",
        "stripe_account_id", "environment", "customer_id", "price_id", "session_id",
        "session_observed_at", "subscription_id", "handoff_id",
        "'duplicate'", "'conflict'", "'session_attached'",
    ):
        assert token in body


def test_confirmation_replay_is_guarded_return_before_any_mutation(checkout_sql):
    _, body = function(checkout_sql, "confirm_checkout_session_v1")
    # Source anchor only: actual equality and branch semantics need database tests.
    replay = re.search(
        r"\bif\b[^;]*'session_attached'[^;]*\bthen\s+"
        r"return 'duplicate';\s*end if;", body,
    )
    assert replay, "Missing explicit zero-write attached-session replay branch"
    prefix = body[:replay.end()]
    for token in ("p_expected_generation", "p_expected_record", "session_id",
                  "request_bytes", "session_observed_at", "session_expires_at",
                  "subscription_id", "handoff_id", "is not distinct from"):
        assert token in prefix
    assert re.search(r"\blease_id is null\b", replay[0])
    assert not re.search(r"\b(?:insert into|update|delete from)\b", prefix.replace("for update", ""))
    assert "p_lease_id" in body[replay.end():]
    assert "lease_expires_at" in body[replay.end():]


def test_unknown_quarantine_and_expiration_are_distinct(checkout_sql):
    for name, state in (
        ("mark_checkout_unknown_v1", "unknown"),
        ("quarantine_checkout_attempt_v1", "quarantined"),
    ):
        _, body = function(checkout_sql, name)
        assert "'" + state + "'" in body and "lease_expires_at" in body
        assert not re.search(r"\bset state\s*=\s*'(prepared|dispatching|closed_verified)'", body)
    _, body = function(checkout_sql, "expire_checkout_unsent_v1")
    assert "'prepared'" in body and "'expired_unsent'" in body
    assert "prepare_expires_at" in body


def test_handoff_has_full_association_to_existing_subscription_and_attempt(checkout_sql):
    body = table(checkout_sql, "checkout_handoffs")
    for columns, target in (
        (SCOPE + ", tenant_ref, subscription_id, price_id", "billing_subscriptions"),
        (SCOPE + ", tenant_ref, attempt_id, session_id, customer_id, price_id",
         "checkout_attempts"),
    ):
        assert f"foreign key ({columns}) references gvai_authority.{target} ({columns})" in body
    assert (
        "unique (" + SCOPE + ", tenant_ref, attempt_id, session_id, customer_id, price_id)"
        in table(checkout_sql, "checkout_attempts")
    )
    _, close = function(checkout_sql, "close_checkout_verified_v1")
    for token in ("checkout_handoffs", "billing_subscriptions", "admitted",
                  "'expired'", "'complete'", "'closed_verified'", "lease_id"):
        assert token in close


def test_attempt_handoff_reference_is_composite_not_id_only(checkout_sql):
    columns = SCOPE + ", tenant_ref, attempt_id, session_id, customer_id, price_id, handoff_id"
    assert (
        f"foreign key ({columns}) references gvai_authority.checkout_handoffs ({columns})"
    ) in checkout_sql
    assert "unique (" + columns + ")" in table(checkout_sql, "checkout_handoffs")
    _, guard = function(checkout_sql, "checkout_handoff_guard")
    for token in ("billing_subscriptions", "customer_id", "subscription_id", "price_id",
                  "tenant_ref", "admitted", "raise exception"):
        assert token in guard


def test_no_existing_business_tables_are_mutated_or_authority_called(checkout_sql):
    for target in re.findall(
        r"\b(?:insert into|update|delete from)\s+gvai_authority\.(\w+)", checkout_sql,
    ):
        assert target in TABLES, "Unexpected mutation: " + target
    for name in (
        "reserve_v1", "reserve_advisory_v1", "reserve_subscription_advisory_v1",
        "complete_advisory_v1", "apply_billing_reconciliation_v1",
    ):
        assert not re.search(r"gvai_authority\." + name + r"\s*\(", checkout_sql)


def test_all_new_objects_revoke_public_and_do_not_seed_approval(checkout_sql):
    functions = function_inventory(checkout_sql)
    outline = source_outline(checkout_sql)
    objects = re.findall(r"create (table) gvai_authority\.(\w+)", outline)
    objects.extend(("function", name) for name in functions)
    assert objects
    for kind, name in objects:
        assert name.startswith("checkout_") or name in ENTRYPOINTS
        signature = ""
        if kind == "function":
            signature = r"\s*\(" + re.escape(function_signature(checkout_sql, name)) + r"\)"
            declaration, _ = functions[name]
            if "security definer" in declaration:
                assert_safe_search_path(declaration)
        assert re.search(
            r"revoke all(?: privileges)? on " + kind + r" gvai_authority\." + name
            + r"\b" + signature + r"\s+from public\s*;", outline,
        ), "Missing exact PUBLIC revocation: " + name
    assert not re.search(
        r"\binsert into gvai_authority\.(?:checkout_authorizations|checkout_attempts|checkout_handoffs)\b",
        checkout_sql.split("create function", 1)[0],
    )
