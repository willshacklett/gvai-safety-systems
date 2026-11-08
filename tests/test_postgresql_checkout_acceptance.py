"""Opt-in synthetic acceptance in a pinned, network-disabled disposable container."""

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading
import time
import uuid

import pytest

from gvai.checkout_attempts import freeze_checkout_request
from gvai.sandbox_checkout import (
    AuthenticatedCheckoutContext, CheckoutMembership, SandboxCheckoutBuilder,
    SandboxCheckoutConfig,
)


ROOT = Path(__file__).resolve().parents[1]
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
IMAGE = "sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c"
DATABASE = "gvai_checkout_test_" + uuid.uuid4().hex
ROLLBACK_DATABASE = "gvai_checkout_rollback_" + uuid.uuid4().hex
CONTAINER_TOKEN = uuid.uuid4().hex
CONTAINER_NAME = "gvai-checkout-acceptance-" + CONTAINER_TOKEN
CID = None
ENABLED = os.environ.get("GVAI_RUN_CHECKOUT_ACCEPTANCE") == "1"
pytestmark = pytest.mark.skipif(
    not ENABLED, reason="Requires explicit disposable-container execution opt-in.",
)


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def missing_container(result):
    message = result.stderr.casefold()
    return result.returncode != 0 and ("no such object" in message or "no such container" in message)


def sql(statement, *, admin=False, failure=None, database=None):
    result = subprocess.run(
        DOCKER + ["exec", "-i", CID, "psql", "-X", "-qAt",
                  "-h", "/var/run/postgresql", "-U",
                  "postgres" if admin else "checkout_owner", "-d", database or DATABASE,
                  "-v", "ON_ERROR_STOP=1", "-v", "VERBOSITY=verbose"],
        input="SET statement_timeout='8s'; SET lock_timeout='3s';\n" + statement,
        text=True, capture_output=True, timeout=15,
    )
    if failure:
        assert result.returncode != 0, "Expected database denial"
        assert failure in result.stderr, result.stderr
        return result.stderr
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def record(value):
    return (
        "jsonb_populate_record(NULL::gvai_authority.checkout_attempts,"
        + literal(json.dumps(value)) + "::jsonb)"
    )


@pytest.fixture(scope="module", autouse=True)
def isolated_cluster():
    global CID
    assert not any(
        name.upper().startswith("PG") or "DSN" in name.upper()
        or name.upper() in ("DATABASE_URL", "DATABASE_SERVICE", "DOCKER_HOST", "DOCKER_CONTEXT")
        for name in os.environ
    ), "Inherited database or container endpoint configuration forbidden"
    subprocess.run(DOCKER + ["image", "inspect", IMAGE], check=True, capture_output=True)
    existing = subprocess.run(DOCKER + ["inspect", CONTAINER_NAME], capture_output=True, text=True)
    assert missing_container(existing), existing.stderr or "Unique disposable container name unexpectedly exists"
    CID = CONTAINER_NAME
    try:
        subprocess.run(DOCKER + [
            "create", "--name", CONTAINER_NAME,
            "--label", "gvai.checkout.acceptance=" + CONTAINER_TOKEN,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128",
            "--memory", "512m", "--cpus", "1", "--user", "postgres",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=999,gid=999",
            "--tmpfs", "/var/run/postgresql:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=999,gid=999",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "--entrypoint", "sleep", IMAGE, "1800",
        ], check=True, capture_output=True, text=True)
        observed = json.loads(subprocess.check_output(DOCKER + ["inspect", CID]))[0]
        assert observed["Image"] == IMAGE
        assert observed["Config"]["Labels"]["gvai.checkout.acceptance"] == CONTAINER_TOKEN
        assert observed["HostConfig"]["NetworkMode"] == "none"
        assert not observed["HostConfig"].get("PortBindings")
        assert not observed["HostConfig"].get("Binds")
        assert observed["HostConfig"]["ReadonlyRootfs"]
        assert not observed["HostConfig"]["Privileged"]
        assert observed["HostConfig"]["CapDrop"] == ["ALL"]
        assert observed["Config"]["User"] == "postgres"
        assert all(mount["Type"] == "tmpfs" for mount in observed["Mounts"])
        assert not observed["State"]["Running"]
        subprocess.run(DOCKER + ["start", CID], check=True, capture_output=True)
        subprocess.run(DOCKER + ["exec", CID, "sh", "-c",
            'test -z "$(ls -A /var/lib/postgresql/data)" && '
            "/usr/lib/postgresql/16/bin/initdb -D /var/lib/postgresql/data "
            "--auth-local=trust --auth-host=reject --encoding=UTF8 --locale=C"],
            check=True, capture_output=True)
        control = subprocess.check_output(DOCKER + [
            "exec", CID, "/usr/lib/postgresql/16/bin/pg_controldata", "/var/lib/postgresql/data",
        ], text=True)
        system_id = next(line.split(":")[1].strip() for line in control.splitlines()
                         if line.startswith("Database system identifier:"))
        subprocess.run(DOCKER + [
            "exec", CID, "/usr/lib/postgresql/16/bin/pg_ctl", "-D", "/var/lib/postgresql/data",
            "-l", "/tmp/postgres.log", "-o",
            "-c listen_addresses='' -c unix_socket_directories='/var/run/postgresql' "
            "-c unix_socket_permissions=0700 -c max_connections=12 -c shared_buffers=32MB",
            "-w", "start",
        ], check=True, capture_output=True)
        bootstrap = DOCKER + ["exec", "-i", CID, "psql", "-X", "-qAt",
                              "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres",
                              "-v", "ON_ERROR_STOP=1"]
        result = subprocess.run(
            bootstrap, input="SELECT count(*) FROM pg_namespace WHERE nspname='gvai_authority';",
            text=True, capture_output=True, check=True,
        )
        assert result.stdout.strip() == "0"
        subprocess.run(
            bootstrap, input="CREATE ROLE checkout_owner LOGIN NOSUPERUSER NOCREATEDB "
            "NOCREATEROLE NOREPLICATION NOBYPASSRLS;\nCREATE DATABASE " + DATABASE + " OWNER checkout_owner;",
            text=True, capture_output=True, check=True,
        )
        assert sql("SELECT system_identifier FROM pg_control_system();", admin=True) == system_id
        assert sql("SHOW listen_addresses;") == ""
        assert sql("SELECT current_database();") == DATABASE
        assert sql("SHOW data_directory;", admin=True) == "/var/lib/postgresql/data"
        assert sql("SHOW unix_socket_directories;", admin=True) == "/var/run/postgresql"
        assert sql("SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolbypassrls "
                   "FROM pg_roles WHERE rolname=current_user;") == "f"
        print("\nDISPOSABLE:", sql("SELECT version();"), "system_identifier=" + system_id,
              "container=" + CID, "database=" + DATABASE, "network=none TCP=disabled tmpfs-only")
        for migration in sorted((ROOT / "migrations/postgresql").glob("00[1-5]*.sql")):
            sql(migration.read_text())
            print("APPLIED:", migration.name)
        yield
    finally:
        observed = subprocess.run(DOCKER + ["inspect", CONTAINER_NAME], capture_output=True, text=True)
        stopped_ok = True
        if observed.returncode == 0:
            container = json.loads(observed.stdout)[0]
            assert container["Config"]["Labels"].get("gvai.checkout.acceptance") == CONTAINER_TOKEN, (
                "Refusing to clean up a container without this run's unique ownership label"
            )
            stopped = subprocess.run(DOCKER + [
                "exec", CONTAINER_NAME, "/usr/lib/postgresql/16/bin/pg_ctl", "-D", "/var/lib/postgresql/data",
                "-m", "fast", "-w", "stop",
            ], capture_output=True, text=True)
            stopped_ok = stopped.returncode == 0
            subprocess.run(DOCKER + ["rm", "--force", CONTAINER_NAME], check=True, capture_output=True)
        else:
            assert missing_container(observed), observed.stderr
        absent = subprocess.run(DOCKER + ["inspect", CONTAINER_NAME], capture_output=True, text=True)
        assert missing_container(absent), absent.stderr or "Disposable container unexpectedly remains"
        print("\nCLEANUP: container absent; tmpfs destroyed; graceful_shutdown=" + str(stopped_ok))


@pytest.fixture
def purchase():
    suffix = secrets.token_hex(8)
    tenant = "synthetic-tenant-" + suffix
    principal = "synthetic-principal-" + suffix
    account = "acct_" + suffix
    price = "price_" + suffix
    customer = "cus_" + suffix
    tenant_ref = int(sql(
        "INSERT INTO gvai_authority.tenants(tenant_id,status) VALUES("
        + literal(tenant) + ",'active') RETURNING tenant_ref;"
    ))
    member = int(sql(
        "INSERT INTO gvai_authority.tenant_memberships(tenant_ref,principal_id,status) VALUES("
        + str(tenant_ref) + "," + literal(principal) + ",'active') RETURNING membership_ref;"
    ))
    authorization = "synthetic-auth-" + suffix
    sql(
        "INSERT INTO gvai_authority.checkout_authorizations VALUES("
        + ",".join((literal(authorization), "'synthetic-issuer'", literal(principal),
                    str(tenant_ref), str(member), "true", "true",
                    "date_trunc('second',clock_timestamp())+interval '1 hour'")) + ");"
        "INSERT INTO gvai_authority.billing_prices VALUES("
        + ",".join((literal(account), "'sandbox'", literal(price), "'synthetic-product'",
                    "'usd'", "9900", "'month'", "1", "1", "true", "3600")) + ");"
        "INSERT INTO gvai_authority.billing_customers VALUES("
        + ",".join((literal(account), "'sandbox'", str(tenant_ref), literal(customer), str(member)))
        + ");"
    )

    class Memberships:
        def lookup(self, issuer, subject, customer_tenant):
            return CheckoutMembership(issuer, subject, customer_tenant, True, True)

    now = int(sql("SELECT extract(epoch FROM date_trunc('second',clock_timestamp()))::bigint;"))
    intent = SandboxCheckoutBuilder(
        SandboxCheckoutConfig(account, "sandbox", price, True,
                              "https://billing.example/success", "https://billing.example/cancel"),
        Memberships(), clock=lambda: now,
    ).build({}, context=AuthenticatedCheckoutContext(
        "synthetic-issuer", principal, tenant, now + 3600,
    ), attempt_id=secrets.token_hex(16))
    frozen = freeze_checkout_request(
        intent, membership_ref=member, customer_id=customer,
        adapter_version="synthetic-adapter-v1", api_version="synthetic-api-v1",
    )
    canonical = lambda obj: json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    blank = asdict(replace(intent, request_fingerprint=""))
    intent_bytes = canonical({"domain": "gvai-sandbox-checkout-intent-v1", "intent": blank})
    request_bytes = canonical({
        "domain": "gvai-frozen-checkout-request-v1", "intent": asdict(intent),
        "membership_ref": member, "customer_id": customer,
        "adapter_version": frozen.adapter_version, "api_version": frozen.api_version,
        "parameters": frozen.parameters.decode("ascii"),
    })
    timestamp = lambda seconds: time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(seconds))
    return {
        "stripe_account_id": account, "environment": "sandbox", "attempt_id": intent.association.attempt_id,
        "authorization_ref": authorization, "issuer": "synthetic-issuer",
        "principal_id": principal, "tenant_ref": tenant_ref, "membership_ref": member,
        "customer_id": customer, "price_id": price, "intent_bytes": "\\x" + intent_bytes.hex(),
        "intent_fingerprint": "\\x" + intent.request_fingerprint,
        "request_bytes": "\\x" + request_bytes.hex(), "request_fingerprint": "\\x" + frozen.fingerprint,
        "parameters": "\\x" + frozen.parameters.hex(), "idempotency_key": intent.idempotency_key,
        "adapter_version": frozen.adapter_version, "api_version": frozen.api_version,
        "authenticated_until": timestamp(now + 3600), "state": "prepared", "generation": 0,
        "created_at": timestamp(now), "updated_at": timestamp(now),
        "prepare_expires_at": timestamp(now + 120),
    }


def key(value):
    return "stripe_account_id=" + literal(value["stripe_account_id"]) + (
        " AND environment='sandbox' AND attempt_id=" + literal(value["attempt_id"])
    )


def stored(value):
    return json.loads(sql(
        "SELECT row_to_json(a) FROM gvai_authority.checkout_attempts a WHERE " + key(value) + ";"
    ))


def invoke(name, expected, *arguments, failure=None):
    args = [record(expected), str(expected["generation"])] + list(arguments)
    return sql("SELECT gvai_authority." + name + "(" + ",".join(args) + ");", failure=failure)


def prepare(value):
    return sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(value) + ");")


def claim(value, seconds=30):
    assert prepare(value) == "prepared"
    current = stored(value)
    assert invoke("claim_checkout_attempt_v1", current, "'synthetic-worker'", str(seconds)) == "dispatching"
    return stored(value)


def evidence(current, status="open", **changes):
    observed = json.loads(sql(
        "SELECT json_build_object('observed',date_trunc('second',clock_timestamp()),"
        "'expires',date_trunc('second',clock_timestamp())+interval '10 minutes');"
    ))
    return dict(current, session_id="cs_test_" + secrets.token_hex(8),
                session_status=status, session_observed_at=observed["observed"],
                session_expires_at=observed["expires"], **changes)


def snapshot_business():
    return sql("""
        SELECT md5(string_agg(n,',' ORDER BY n)) FROM (
            SELECT table_name || ':' || (
                xpath('/row/data/text()',query_to_xml(
                    format('SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'
                           '''[]''::jsonb)::text AS data FROM gvai_authority.%I t',table_name),
                    false,true,'')))[1]::text AS n
            FROM information_schema.tables
            WHERE table_schema='gvai_authority' AND table_type='BASE TABLE'
              AND table_name NOT LIKE 'checkout_%'
        ) all_tables;
    """)


def test_catalogs_and_effective_denials():
    assert sql("SELECT count(*) FROM pg_constraint WHERE conrelid IN "
               "('gvai_authority.checkout_attempts'::regclass,"
               "'gvai_authority.checkout_handoffs'::regclass) "
               "AND contype='f' AND condeferrable AND condeferred AND convalidated;") == "2"
    assert sql("SELECT count(*) FROM pg_trigger WHERE tgrelid IN "
               "('gvai_authority.checkout_attempts'::regclass,"
               "'gvai_authority.checkout_handoffs'::regclass,"
               "'gvai_authority.checkout_authorizations'::regclass) AND NOT tgisinternal "
               "AND tgenabled='O';") == "4"
    assert sql("""
        SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='gvai_authority'
          AND (p.proname LIKE 'checkout_%' OR p.proname LIKE '%checkout%_v1')
          AND (p.proowner<>(SELECT oid FROM pg_roles WHERE rolname='checkout_owner')
            OR NOT p.proconfig @> ARRAY['search_path=pg_catalog, gvai_authority, pg_temp']
            OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                       WHERE a.grantee<>p.proowner));
    """) == "0"
    if sql("SELECT count(*) FROM pg_roles WHERE rolname='synthetic_unprivileged';") == "0":
        sql("CREATE ROLE synthetic_unprivileged NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;", admin=True)
    assert sql("SELECT bool_or(has_function_privilege('synthetic_unprivileged',p.oid,'EXECUTE')) "
               "FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
               "WHERE n.nspname='gvai_authority' AND p.proname LIKE '%checkout%';") == "f"
    assert sql("SELECT bool_or(has_table_privilege('synthetic_unprivileged',c.oid,'INSERT,UPDATE,DELETE')) "
               "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
               "WHERE n.nspname='gvai_authority' AND c.relname LIKE 'checkout_%';") == "f"
    sql("SET SESSION AUTHORIZATION synthetic_unprivileged; "
        "SELECT gvai_authority.prepare_checkout_attempt_v1(NULL);",
        admin=True, failure="42501")


@pytest.mark.parametrize("value", [
    {"a": "simple", "z": 9223372036854775807}, {"parameters": '{"a":"quoted\\\\value"}'},
    {"association": {"issuer": "synthetic-issuer"}, "items": [{"quantity": 1}]},
    *[chr(code) for code in range(32, 127)],
])
def test_database_canonical_golden_vectors(value):
    expected = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    actual = sql("SELECT encode(convert_to(gvai_authority.checkout_canonical("
                 + literal(json.dumps(value)) + "::jsonb),'UTF8'),'hex');")
    assert bytes.fromhex(actual) == expected.encode("ascii")
    assert sql("SELECT encode(gvai_authority.digest(convert_to("
               "gvai_authority.checkout_canonical(" + literal(json.dumps(value))
               + "::jsonb),'UTF8'),'sha256'),'hex');") == hashlib.sha256(expected.encode("ascii")).hexdigest()


def test_prepare_full_python_bytes_duplicate_conflict_and_rollback(purchase):
    assert prepare(purchase) == "prepared"
    before = stored(purchase)
    assert prepare(dict(purchase, prepare_expires_at=purchase["authenticated_until"])) == "duplicate"
    assert stored(purchase) == before
    assert prepare(dict(purchase, adapter_version="changed")) == "conflict"
    sql("BEGIN; UPDATE gvai_authority.checkout_attempts SET customer_id='cus_Changed' "
        "WHERE " + key(purchase) + "; COMMIT;", failure="immutable checkout association conflict")
    assert stored(purchase) == before


def test_claim_unknown_stale_fence_quarantine_and_business_preservation(purchase):
    before = snapshot_business()
    current = claim(purchase)
    stale = dict(current, generation=0)
    invoke("mark_checkout_unknown_v1", stale, failure="checkout full-record fence lost")
    assert invoke("mark_checkout_unknown_v1", current) == "unknown"
    unknown = stored(purchase)
    invoke("claim_checkout_attempt_v1", unknown, "'synthetic-worker'", "30",
           failure="checkout creation claim denied")
    assert invoke("quarantine_checkout_attempt_v1", unknown) == "quarantined"
    invoke("claim_checkout_reconciliation_v1", stored(purchase), "'recovery'", "30",
           failure="checkout reconciliation claim denied")
    assert snapshot_business() == before


def test_confirmation_replay_stale_worker_and_expired_closure(purchase):
    current = claim(purchase)
    proof = evidence(current)
    assert invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(proof)) == "session_attached"
    attached = stored(purchase)
    identity = sql("SELECT xmin::text||':'||ctid::text FROM gvai_authority.checkout_attempts WHERE " + key(purchase))
    assert invoke("confirm_checkout_session_v1", attached, "NULL", record(proof)) == "duplicate"
    assert stored(purchase) == attached
    assert sql("SELECT xmin::text||':'||ctid::text FROM gvai_authority.checkout_attempts WHERE "
               + key(purchase)) == identity
    invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(proof),
           failure="checkout full-record fence lost")
    invoke("close_checkout_verified_v1", attached, failure="checkout closure lacks")
    assert invoke("claim_checkout_reconciliation_v1", attached, "'recovery'", "30") == "session_attached"
    recovery = stored(purchase)
    expired = dict(proof, session_status="expired",
                   session_expires_at=proof["session_observed_at"])
    assert invoke("confirm_checkout_session_v1", recovery, "'recovery'", record(expired)) == "conflict"
    assert stored(purchase)["state"] == "quarantined"


def test_lease_expiry_and_recovery(purchase):
    current = claim(purchase, 1)
    time.sleep(1.1)
    invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(evidence(current)),
           failure="checkout confirmation lease lost")
    assert invoke("claim_checkout_reconciliation_v1", current, "'recovery'", "30") == "unknown"
    invoke("mark_checkout_unknown_v1", current, failure="checkout full-record fence lost")


def test_authoritative_expired_session_releases_slot(purchase):
    current = claim(purchase)
    before = snapshot_business()
    proof = evidence(current)
    proof["session_status"] = "expired"
    proof["session_expires_at"] = proof["session_observed_at"]
    assert invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(proof)) == "session_attached"
    assert invoke("close_checkout_verified_v1", stored(purchase)) == "closed_verified"
    assert snapshot_business() == before


def test_same_tenant_race_exact_prepare(purchase):
    """Prove competing prepares serialize while both sessions contend on the tenant lock."""
    outcomes = synchronized_prepares([purchase, purchase], purchase["tenant_ref"])
    assert sorted(outcomes) == ["duplicate", "prepared"]
    assert sql("SELECT count(*) FROM gvai_authority.checkout_attempts WHERE " + key(purchase)) == "1"


def test_revocation_blocks_claim(purchase):
    assert prepare(purchase) == "prepared"
    sql("UPDATE gvai_authority.checkout_authorizations SET active=false "
        "WHERE authorization_ref=" + literal(purchase["authorization_ref"]))
    invoke("claim_checkout_attempt_v1", stored(purchase), "'worker'", "30",
           failure="checkout creation claim denied")


def test_prepare_transaction_rollback(purchase):
    """Prove explicit rollback of a successful prepare, not migration-DDL rollback."""
    assert sql("BEGIN; SELECT gvai_authority.prepare_checkout_attempt_v1("
               + record(purchase) + "); ROLLBACK;") == "prepared"
    assert sql("SELECT count(*) FROM gvai_authority.checkout_attempts WHERE " + key(purchase)) == "0"


def synchronized_prepares(values, tenant_ref):
    blocker = DOCKER + ["exec", "-i", CID, "psql", "-X", "-qAt",
                        "-h", "/var/run/postgresql", "-U", "checkout_owner", "-d", DATABASE,
                        "-v", "ON_ERROR_STOP=1"]
    process = subprocess.Popen(
        blocker, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        process.stdin.write(
            "BEGIN; SELECT 'tenant_locked' FROM gvai_authority.tenants WHERE tenant_ref="
            + str(tenant_ref) + " FOR UPDATE;\n"
        )
        process.stdin.flush()
        assert process.stdout.readline().strip() == "tenant_locked"
        barrier = threading.Barrier(len(values))

        def compete(value):
            barrier.wait(timeout=10)
            try:
                return prepare(value)
            except AssertionError as error:
                if "checkout purchase admission denied" in str(error):
                    return "denied"
                raise

        with ThreadPoolExecutor(max_workers=len(values)) as workers:
            futures = [workers.submit(compete, value) for value in values]
            deadline = time.monotonic() + 10
            waiting = 0
            while time.monotonic() < deadline:
                waiting = int(sql(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname=" + literal(DATABASE)
                    + " AND wait_event_type='Lock' "
                    "AND query LIKE '%prepare_checkout_attempt_v1%';",
                    admin=True,
                ))
                if waiting >= len(values):
                    break
                time.sleep(0.05)
            assert waiting >= len(values), (
                f"Expected {len(values)} concurrent prepare sessions blocked on tenant lock; found {waiting}"
            )
            process.stdin.write("COMMIT;\n")
            process.stdin.flush()
            outcomes = [future.result(timeout=10) for future in futures]
        _, error = process.communicate(timeout=10)
        assert process.returncode == 0, error
        return outcomes
    finally:
        if process.stdin and not process.stdin.closed:
            process.stdin.write("ROLLBACK;\n")
            process.stdin.flush()
            process.communicate(timeout=10)


def different_request(original, *, other_account=False):
    value = dict(original)
    intent = json.loads(bytes.fromhex(value["intent_bytes"][2:]))["intent"]
    intent["association"]["attempt_id"] = secrets.token_hex(16)
    if other_account:
        value["stripe_account_id"] = "acct_" + secrets.token_hex(8)
        intent["stripe_account_id"] = value["stripe_account_id"]
        sql("INSERT INTO gvai_authority.billing_prices "
            "SELECT " + literal(value["stripe_account_id"]) + ",environment,price_id,product_id,"
            "currency,unit_amount,interval_unit,interval_count,quantity,approved,max_evidence_age_seconds "
            "FROM gvai_authority.billing_prices WHERE stripe_account_id="
            + literal(original["stripe_account_id"]) + " AND price_id=" + literal(value["price_id"]) + ";"
            "INSERT INTO gvai_authority.billing_customers VALUES("
            + ",".join((literal(value["stripe_account_id"]), "'sandbox'", str(value["tenant_ref"]),
                        literal(value["customer_id"]), str(value["membership_ref"]))) + ");")
    canonical = lambda obj: json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    value["attempt_id"] = intent["association"]["attempt_id"]
    value["idempotency_key"] = "gvai-checkout-v1-" + hashlib.sha256(canonical({
        "domain": "gvai-sandbox-checkout-attempt-v1", "account": value["stripe_account_id"],
        "environment": "sandbox", "attempt": value["attempt_id"],
    })).hexdigest()
    intent["idempotency_key"] = value["idempotency_key"]
    intent_bytes = canonical({"domain": "gvai-sandbox-checkout-intent-v1", "intent": intent})
    intent["request_fingerprint"] = hashlib.sha256(intent_bytes).hexdigest()
    parameters = json.loads(bytes.fromhex(value["parameters"][2:]))
    parameters["client_reference_id"] = value["attempt_id"]
    parameter_bytes = canonical(parameters)
    frozen = canonical({
        "domain": "gvai-frozen-checkout-request-v1", "intent": intent,
        "membership_ref": value["membership_ref"], "customer_id": value["customer_id"],
        "adapter_version": value["adapter_version"], "api_version": value["api_version"],
        "parameters": parameter_bytes.decode("ascii"),
    })
    value.update(
        intent_bytes="\\x" + intent_bytes.hex(), intent_fingerprint="\\x" + intent["request_fingerprint"],
        parameters="\\x" + parameter_bytes.hex(), request_bytes="\\x" + frozen.hex(),
        request_fingerprint="\\x" + hashlib.sha256(frozen).hexdigest(),
    )
    return value


@pytest.mark.parametrize("iteration", range(20))
def test_distinct_attempt_race_across_accounts(purchase, iteration):
    alternate = different_request(purchase, other_account=True)
    outcomes = synchronized_prepares([purchase, alternate], purchase["tenant_ref"])
    assert sorted(outcomes) == ["denied", "prepared"]
    assert sql("SELECT count(*) FROM gvai_authority.checkout_attempts "
               "WHERE tenant_ref=" + str(purchase["tenant_ref"])) == "1"


def test_cross_tenant_isolation(purchase):
    second = globals()["purchase"].__wrapped__()
    assert prepare(purchase) == "prepared"
    assert prepare(second) == "prepared"
    forged = dict(second, tenant_ref=purchase["tenant_ref"])
    sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(forged) + ");",
        failure="P0002")
    assert stored(purchase)["tenant_ref"] != stored(second)["tenant_ref"]


def test_scoped_idempotency_and_session_conflicts(purchase):
    current = claim(purchase)
    forged_key = different_request(purchase)
    forged_key["idempotency_key"] = purchase["idempotency_key"]
    sql("BEGIN; INSERT INTO gvai_authority.checkout_attempts SELECT ("
        + record(forged_key) + ").*; COMMIT;", failure="checkout idempotency conflict")
    proof = evidence(current)
    assert invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(proof)) == "session_attached"
    second = globals()["purchase"].__wrapped__()
    sql("INSERT INTO gvai_authority.billing_customers VALUES("
        + ",".join((literal(purchase["stripe_account_id"]), "'sandbox'", str(second["tenant_ref"]),
                    literal(second["customer_id"]), str(second["membership_ref"]))) + ");")
    second_intent = json.loads(bytes.fromhex(second["intent_bytes"][2:]))["intent"]
    second_intent["stripe_account_id"] = purchase["stripe_account_id"]
    second_intent["price_id"] = purchase["price_id"]
    # Rebuild from a valid alternate fixture in the first account.
    second["stripe_account_id"] = purchase["stripe_account_id"]
    second["price_id"] = purchase["price_id"]
    second["intent_bytes"] = "\\x" + json.dumps(
        {"domain": "gvai-sandbox-checkout-intent-v1", "intent": second_intent},
        sort_keys=True, separators=(",", ":"),
    ).encode().hex()
    parameters = json.loads(bytes.fromhex(second["parameters"][2:]))
    parameters["line_items"][0]["price"] = purchase["price_id"]
    second["parameters"] = "\\x" + json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode().hex()
    second = different_request(second)
    other = claim(second)
    other_proof = evidence(other)
    other_proof["session_id"] = proof["session_id"]
    assert invoke("confirm_checkout_session_v1", other, "'synthetic-worker'", record(other_proof)) == "conflict"
    assert stored(second)["state"] == "quarantined"
    assert stored(purchase)["session_id"] == proof["session_id"]


def test_generation_exhaustion_and_full_record_fence(purchase):
    current = claim(purchase)
    maximum = dict(current, generation=2**63 - 1)
    sql("SELECT gvai_authority.checkout_check_fence("
        + record(maximum) + "," + record(maximum) + ",9223372036854775807,"
        "date_trunc('second',clock_timestamp()),true);", failure="checkout generation exhausted")
    sql("SELECT gvai_authority.checkout_check_fence("
        + record(maximum) + "," + record(maximum) + ",9223372036854775807,"
        "date_trunc('second',clock_timestamp()),false);")
    forged = dict(current, request_bytes="\\x00")
    invoke("mark_checkout_unknown_v1", forged, failure="checkout full-record fence lost")
    assert stored(purchase) == current


def test_complete_session_requires_exact_admitted_handoff(purchase):
    current = claim(purchase)
    proof = evidence(current)
    proof.update(session_status="complete", subscription_id="sub_" + secrets.token_hex(8))
    assert invoke("confirm_checkout_session_v1", current, "'synthetic-worker'", record(proof)) == "session_attached"
    invoke("close_checkout_verified_v1", stored(purchase), failure="checkout closure lacks")
    sql("INSERT INTO gvai_authority.billing_subscriptions "
        "(stripe_account_id,environment,tenant_ref,customer_id,subscription_id,price_id,admitted) VALUES("
        + ",".join((literal(purchase["stripe_account_id"]), "'sandbox'", str(purchase["tenant_ref"]),
                    literal(purchase["customer_id"]), literal(proof["subscription_id"]),
                    literal(purchase["price_id"]), "true")) + ");")
    before = snapshot_business()
    sql("BEGIN; INSERT INTO gvai_authority.checkout_handoffs VALUES("
        + ",".join((literal("synthetic-wrong-" + secrets.token_hex(8)),
                    literal(purchase["stripe_account_id"]), "'sandbox'", str(purchase["tenant_ref"]),
                    literal(purchase["attempt_id"]), "'cs_test_MissingSession'",
                    literal(purchase["customer_id"]), literal(proof["subscription_id"]),
                    literal(purchase["price_id"]), "date_trunc('second',clock_timestamp())"))
        + "); SET CONSTRAINTS ALL IMMEDIATE; COMMIT;", failure="23503")
    assert invoke("claim_checkout_reconciliation_v1", stored(purchase), "'recovery'", "30") == "session_attached"
    recovery = stored(purchase)
    proof["session_observed_at"] = evidence(recovery)["session_observed_at"]
    proof["handoff_id"] = "synthetic-handoff-" + secrets.token_hex(8)
    assert invoke("confirm_checkout_session_v1", recovery, "'recovery'", record(proof)) == "session_attached"
    assert invoke("close_checkout_verified_v1", stored(purchase)) == "closed_verified"
    assert snapshot_business() == before


def test_unsent_expiry_never_dispatches(purchase):
    now = int(sql("SELECT extract(epoch FROM date_trunc('second',clock_timestamp()))::bigint;"))
    purchase["prepare_expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(now + 2))
    assert prepare(purchase) == "prepared"
    current = stored(purchase)
    invoke("expire_checkout_unsent_v1", current, failure="checkout attempt not proven unsent")
    time.sleep(2.1)
    assert invoke("expire_checkout_unsent_v1", current) == "expired_unsent"
    invoke("claim_checkout_attempt_v1", stored(purchase), "'worker'", "30",
           failure="checkout creation claim denied")


def test_revocation_race_rechecked_after_wait(purchase):
    assert prepare(purchase) == "prepared"
    current = stored(purchase)
    blocker = DOCKER + ["exec", "-i", CID, "psql", "-X", "-qAt",
                        "-h", "/var/run/postgresql", "-U", "checkout_owner", "-d", DATABASE,
                        "-v", "ON_ERROR_STOP=1"]
    with subprocess.Popen(blocker, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as process:
        process.stdin.write(
            "BEGIN; UPDATE gvai_authority.checkout_authorizations SET active=false WHERE authorization_ref="
            + literal(purchase["authorization_ref"]) + "; SELECT 'barrier'; SELECT pg_sleep(1); COMMIT;\n"
        )
        process.stdin.flush()
        assert process.stdout.readline().strip() == "barrier"
        invoke("claim_checkout_attempt_v1", current, "'worker'", "30",
               failure="checkout creation claim denied")
        _, error = process.communicate(timeout=10)
        assert process.returncode == 0, error
    assert stored(purchase)["state"] == "prepared"


def test_generation_jump_and_changed_bytes_are_rejected(purchase):
    malformed = dict(purchase, request_bytes="\\x00")
    sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(malformed) + ");",
        failure="checkout frozen request conflict")
    assert prepare(purchase) == "prepared"
    before = stored(purchase)
    sql("UPDATE gvai_authority.checkout_attempts SET state='dispatching',generation=2,"
        "lease_id='worker',lease_expires_at=updated_at+interval '30 seconds' WHERE "
        + key(purchase), failure="illegal checkout transition")
    assert stored(purchase) == before


def test_unknown_and_quarantine_retain_tenant_slot(purchase):
    current = claim(purchase)
    alternate = different_request(purchase, other_account=True)
    assert invoke("mark_checkout_unknown_v1", current) == "unknown"
    sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(alternate) + ");",
        failure="checkout purchase admission denied")
    invoke("close_checkout_verified_v1", stored(purchase), failure="checkout closure lacks")
    assert invoke("quarantine_checkout_attempt_v1", stored(purchase)) == "quarantined"
    sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(alternate) + ");",
        failure="checkout purchase admission denied")


def test_commit_readback_resolves_same_identity_without_replacement(purchase):
    sql("BEGIN; SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(purchase) + "); COMMIT;")
    committed = stored(purchase)
    assert prepare(purchase) == "duplicate"
    assert stored(purchase) == committed
    alternate = different_request(purchase)
    sql("SELECT gvai_authority.prepare_checkout_attempt_v1(" + record(alternate) + ");",
        failure="checkout purchase admission denied")


def test_reapply_fails_atomically_without_catalog_change():
    before = sql("SELECT count(*) FROM pg_proc WHERE pronamespace='gvai_authority'::regnamespace;")
    sql((ROOT / "migrations/postgresql/005_checkout_attempts_v1.sql").read_text(),
        failure="42P07")
    assert sql("SELECT count(*) FROM pg_proc WHERE pronamespace='gvai_authority'::regnamespace;") == before


def test_late_migration_failure_rolls_back_all_checkout_ddl():
    created = False
    try:
        sql("CREATE DATABASE " + ROLLBACK_DATABASE + " OWNER checkout_owner;",
            admin=True, database="postgres")
        created = True
        for migration in sorted((ROOT / "migrations/postgresql").glob("00[1-4]*.sql")):
            sql(migration.read_text(), database=ROLLBACK_DATABASE)

        def catalog_counts():
            return sql("""
                SELECT
                    (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                     WHERE n.nspname='gvai_authority') || ':' ||
                    (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
                     WHERE n.nspname='gvai_authority') || ':' ||
                    (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
                     WHERE n.nspname='gvai_authority') || ':' ||
                    (SELECT count(*) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
                     WHERE n.nspname='gvai_authority') || ':' ||
                    (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                     JOIN pg_namespace n ON n.oid=c.relnamespace
                     WHERE n.nspname='gvai_authority');
            """, database=ROLLBACK_DATABASE)

        before = catalog_counts()
        migration = (ROOT / "migrations/postgresql/005_checkout_attempts_v1.sql").read_text()
        prefix, separator, suffix = migration.rpartition("COMMIT;")
        assert separator and not suffix.strip(), "Expected migration's final COMMIT boundary"
        injected = prefix + "SELECT 1 / 0;\nCOMMIT;"
        sql(injected, database=ROLLBACK_DATABASE, failure="division by zero")
        assert catalog_counts() == before
        assert sql(
            "SELECT count(*) FROM gvai_authority.billing_installation "
            "WHERE migration_id='004_subscription_billing_v1' AND contract_version=1;",
            database=ROLLBACK_DATABASE,
        ) == "1"
        assert sql(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='gvai_authority' AND c.relname LIKE 'checkout%';",
            database=ROLLBACK_DATABASE,
        ) == "0"
    finally:
        if created:
            sql("DROP DATABASE " + ROLLBACK_DATABASE + ";", admin=True, database="postgres")
