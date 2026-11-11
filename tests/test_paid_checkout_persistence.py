"""Opt-in real-driver tests; only a pinned, owned disposable PostgreSQL instance."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

import pytest

from gvai.paid_checkout import CheckoutCommitUnknown, CheckoutUnavailable, PaidCheckoutStore


ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "migrations/postgresql"
IMAGE = "postgres@sha256:1beaa3084eee2676f20a9cd9928f0bf2c5bf674f8e49f81017912183d377c61c"
pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_PAID_CHECKOUT_POSTGRES") != "1",
    reason="Explicit disposable paid Checkout PostgreSQL opt-in required.",
)


@pytest.fixture(scope="module")
def cluster(request):
    import psycopg

    assert shutil.which("docker"), "Required Docker unavailable."
    assert psycopg.pq.__impl__ == "binary"
    assert not any(key.startswith("PG") for key in os.environ), "Inherited PostgreSQL configuration rejected."
    name = "gvai-checkout-" + secrets.token_hex(8)
    password = secrets.token_hex(32)
    container_id = None
    identity = secrets.token_hex(16)
    databases = set()
    diagnostics = None
    captures = 0
    initial_failures = request.session.testsfailed

    def docker(*args, input=None):
        result = subprocess.run(
            ["docker", *args], input=input, text=True, capture_output=True, timeout=60,
            env={**os.environ, "POSTGRES_PASSWORD": password},
        )
        assert result.returncode == 0, "Owned disposable PostgreSQL operation failed; details withheld."
        return result.stdout.strip()

    def owned_container():
        assert container_id and re.fullmatch(r"[0-9a-f]{64}", container_id)
        info = json.loads(docker("inspect", container_id))[0]
        assert info["Id"] == container_id and info["Name"] == "/" + name
        assert info["Image"] == image_id
        assert info["Config"]["Labels"]["gvai.checkout.fixture"] == identity
        assert not any(mount["Type"] == "bind" for mount in info["Mounts"])
        return info

    def capture_failure():
        nonlocal diagnostics, captures
        if diagnostics is None:
            diagnostics = Path(tempfile.mkdtemp(prefix="gvai-checkout-diagnostics-"))
        captures += 1
        evidence = {}
        try:
            info = owned_container()
            evidence["state"] = {
                key: info["State"][key]
                for key in ("Status", "Running", "OOMKilled", "Dead", "ExitCode", "StartedAt", "FinishedAt")
            }
            probes = {
                "postgresql_logs": ["logs", "--tail", "300", container_id],
                "storage": ["exec", container_id, "df", "-kP", "/var/lib/postgresql/data"],
                "databases": [
                    "exec", container_id, "psql", "-X", "-qAt", "-U", "postgres", "-d", "postgres",
                    "-c", "SELECT count(*),coalesce(sum(pg_database_size(oid)),0) FROM pg_database "
                    "WHERE datname ~ '^gvai_checkout_test_[0-9a-f]{16}$';",
                ],
            }
            for kind, args in probes.items():
                try:
                    result = subprocess.run(
                        ["docker", *args], capture_output=True, text=True, timeout=10,
                    )
                    entry = {"exit_code": result.returncode}
                    if kind == "postgresql_logs":
                        categories = {
                            "storage_exhaustion": r"no space left on device|disk full",
                            "memory_exhaustion": r"out of memory|cannot allocate memory",
                            "process_failure": r"terminated by signal|server process.*exited",
                            "recovery": r"recovery|redo|interrupted",
                            "shutdown": r"shut.down|shutdown",
                            "ready": r"ready to accept connections",
                        }
                        entry["sanitized_records"] = [
                            {
                                "severity": severity.group(1) if severity else "OTHER",
                                "categories": [
                                    category for category, pattern in categories.items()
                                    if re.search(pattern, line, re.IGNORECASE)
                                ],
                            }
                            for line in (result.stdout + result.stderr).splitlines()
                            for severity in [re.search(r"\b(DEBUG|LOG|INFO|NOTICE|WARNING|ERROR|FATAL|PANIC):", line)]
                        ]
                    elif kind == "storage":
                        entry["usage_kib"] = [
                            [int(value) for value in fields[1:4]]
                            for line in result.stdout.splitlines()
                            if len(fields := line.split()) >= 6
                            and all(value.isdigit() for value in fields[1:4])
                        ]
                    else:
                        entry["count_and_total_bytes"] = [
                            [int(value) for value in line.split("|")]
                            for line in result.stdout.splitlines()
                            if re.fullmatch(r"\d+\|\d+", line)
                        ]
                    evidence[kind] = entry
                except (OSError, subprocess.SubprocessError) as error:
                    evidence[kind] = {"capture_error": type(error).__name__}
        except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
            evidence["identity_or_state_error"] = type(error).__name__
        path = diagnostics / f"failure-{captures}.json"
        path.write_text(json.dumps(evidence, indent=2))
        print(f"Sanitized disposable PostgreSQL diagnostics: {path}", flush=True)

    def cleanup_database(database):
        assert re.fullmatch(r"gvai_checkout_test_[0-9a-f]{16}", database)
        assert database in databases, "Database not allocated by this fixture."
        owned_container()
        # FORCE terminates only sessions connected to this exact disposable database.
        admin(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE);')
        assert admin(f"SELECT count(*) FROM pg_database WHERE datname='{database}';") == "0"
        databases.remove(database)

    try:
        info = json.loads(docker("image", "inspect", IMAGE))[0]
        assert info["Id"] == IMAGE.split("@")[1]
        image_id = info["Id"]
        container_id = docker(
            "create", "--pull=never", "--name", name,
            "--label", f"gvai.checkout.fixture={identity}",
            "--memory", "512m", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m",
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD", IMAGE,
            "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
            "-c", "log_parameter_max_length=0", "-c", "log_parameter_max_length_on_error=0",
        )
        owned_container()
        docker("start", container_id)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["docker", "exec", container_id, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                capture_output=True, timeout=5,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("Disposable database readiness failed.")
        info = owned_container()
        ports = info["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1"
        assert not any(mount["Type"] == "bind" for mount in info["Mounts"])
        port = int(ports[0]["HostPort"])

        def admin(statement):
            owned_container()
            return docker(
                "exec", "-i", container_id, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1",
                "-U", "postgres", "-d", "postgres", input=statement,
            )

        roles = ("checkout_owner", "worker_a", "worker_b", "worker_disabled", "paid_runtime", "pilot_runtime")
        for role in roles:
            admin(f"CREATE ROLE {role} LOGIN PASSWORD '{password}';")

        def connect(database, role="checkout_owner"):
            assert database.startswith("gvai_checkout_test_")
            assert re.fullmatch(r"gvai_checkout_test_[0-9a-f]{16}", database)
            owned_container()
            return psycopg.connect(
                host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname=database,
                user=role, password=password, sslmode="disable", connect_timeout=3,
                options="-c statement_timeout=5000 -c lock_timeout=2000",
            )

        yield admin, connect, databases, cleanup_database, capture_failure
    except BaseException:
        if container_id:
            capture_failure()
        raise
    finally:
        if container_id:
            try:
                if request.session.testsfailed > initial_failures and captures == 0:
                    capture_failure()
            finally:
                owned_container()
                docker("rm", "--force", "--volumes", container_id)
                remaining = docker("ps", "--all", "--quiet", "--no-trunc", "--filter", f"id={container_id}")
                assert not remaining, "Owned container teardown unverified."


@pytest.fixture
def database(cluster, request):
    admin, connect, databases, cleanup, capture_failure = cluster
    name = "gvai_checkout_test_" + secrets.token_hex(8)
    initial_failures = request.session.testsfailed
    databases.add(name)
    captured = False
    try:
        admin(f"CREATE DATABASE {name} OWNER checkout_owner;")
        admin(f"REVOKE ALL ON DATABASE {name} FROM PUBLIC;")
        admin(f"GRANT CONNECT ON DATABASE {name} TO worker_a,worker_b,worker_disabled,paid_runtime,pilot_runtime;")
        manifest = json.loads((SQL / "paid_checkout_manifest_v1.json").read_text())
        with connect(name) as connection:
            for entry in manifest["migrations"][:-1]:
                content = (SQL / entry["file"]).read_bytes()
                if "sha256" in entry:
                    assert hashlib.sha256(content).hexdigest() == entry["sha256"]
                connection.execute(content.decode(), prepare=False)
        yield name, lambda role="checkout_owner": connect(name, role)
    except BaseException:
        capture_failure()
        captured = True
        raise
    finally:
        try:
            if request.session.testsfailed > initial_failures and not captured:
                capture_failure()
        finally:
            try:
                cleanup(name)
            except BaseException:
                capture_failure()
                raise


def install(database):
    with database[1]() as connection:
        connection.execute((SQL / "007_paid_checkout_state_v1.sql").read_text(), prepare=False)


def seed(database):
    with database[1]() as c:
        c.execute("""
            INSERT INTO gvai_authority.authority_state(singleton_id,authority_id,epoch,trust_domain)
                VALUES(1,'checkout-test',1,'disposable');
            INSERT INTO gvai_authority.tenants(tenant_id,status)
                VALUES('tenant-a','active'),('tenant-b','active'),('tenant-history','active');
            INSERT INTO gvai_authority.tenant_memberships(tenant_ref,principal_id,status)
                SELECT tenant_ref,tenant_id||'-principal','active' FROM gvai_authority.tenants;
            INSERT INTO gvai_authority.resource_ownerships
                (resource_id,ownership_version,tenant_ref,resource_kind,status)
                SELECT tenant_id||'-project',1,tenant_ref,'evaluation','active' FROM gvai_authority.tenants;
            INSERT INTO gvai_authority.customer_credentials
                (key_id,tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,expires_at)
                SELECT repeat(CASE WHEN tenant_id='tenant-history' THEN 'c' ELSE right(tenant_id,1) END,32),
                    tenant_ref,membership_ref,decode(repeat('d',64),'hex'),
                    ARRAY['evaluation:run','usage:read'],'active',
                    clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day'
                FROM gvai_authority.tenants JOIN gvai_authority.tenant_memberships USING(tenant_ref);
            INSERT INTO gvai_authority.advisory_pilots(tenant_ref,starts_at,expires_at,allowance,consumed)
                SELECT tenant_ref,clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day',10,0
                FROM gvai_authority.tenants WHERE tenant_id='tenant-a';
            INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id)
                SELECT tenant_ref,'cus_'||replace(tenant_id,'-','') FROM gvai_authority.tenants;
            UPDATE gvai_authority.billing_customers SET subscription_id='sub_history'
                WHERE customer_id='cus_tenanthistory';
            INSERT INTO gvai_authority.billing_periods(invoice_id,tenant_ref,subscription_id,starts_at,ends_at)
                SELECT 'in_history',tenant_ref,'sub_history',
                    clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day'
                FROM gvai_authority.billing_customers WHERE subscription_id='sub_history';
            UPDATE gvai_authority.billing_customers SET current_invoice='in_history',eligible=true,
                verified_until=clock_timestamp()+interval '1 hour',access_until=clock_timestamp()+interval '1 day'
                WHERE subscription_id='sub_history';
            INSERT INTO gvai_authority.billing_events(event_id,tenant_ref,payload_hash)
                SELECT 'evt_history',tenant_ref,repeat('e',64) FROM gvai_authority.tenants
                WHERE tenant_id='tenant-history';
        """, prepare=False)
        assert c.execute(
            "SELECT gvai_authority.reserve_paid_v1(%s,%s,'checkout-test',1,'disposable','history','tenant-history-project',%s)",
            ("c" * 32, bytes.fromhex("d" * 64), "f" * 64),
        ).fetchone() == ("reserved",)
        c.execute("UPDATE gvai_authority.billing_customers SET revoked=true,eligible=false WHERE subscription_id='sub_history'")


def configure(database, enabled=True):
    with database[1]() as c:
        c.execute("""
            INSERT INTO gvai_authority.paid_checkout_installation
                (singleton_id,account_id,environment,price_id,currency,unit_amount,interval_unit,
                 quantity,success_url,cancel_url)
            VALUES(1,'acct_test','sandbox','price_test','usd',9900,'month',1,
                'https://example.test/return','https://example.test/cancel');
            INSERT INTO gvai_authority.paid_checkout_workers(role_name,tenant_ref,membership_ref,enabled)
                SELECT 'worker_'||right(tenant_id,1),tenant_ref,membership_ref,false
                FROM gvai_authority.tenants JOIN gvai_authority.tenant_memberships USING(tenant_ref)
                WHERE tenant_id IN ('tenant-a','tenant-b');
            INSERT INTO gvai_authority.paid_checkout_workers(role_name,tenant_ref,membership_ref)
                SELECT 'worker_disabled',tenant_ref,membership_ref FROM gvai_authority.tenants
                JOIN gvai_authority.tenant_memberships USING(tenant_ref) WHERE tenant_id='tenant-a';
            GRANT USAGE ON SCHEMA gvai_authority TO worker_a,worker_b,worker_disabled,paid_runtime,pilot_runtime;
            GRANT EXECUTE ON FUNCTION gvai_authority.prepare_paid_checkout_v1(text,bytea),
                gvai_authority.read_paid_checkout_v1(text),
                gvai_authority.block_paid_checkout_v1(text,jsonb,text)
                TO worker_a,worker_b,worker_disabled;
        """, prepare=False)
        if enabled:
            c.execute("UPDATE gvai_authority.paid_checkout_workers SET enabled=true WHERE role_name IN ('worker_a','worker_b')")


def request(database, attempt="a" * 32, tenant="a", **changes):
    value = {
        "version": 1, "attempt_id": attempt, "tenant_id": "tenant-" + tenant,
        "account_id": "acct_test", "environment": "sandbox", "customer_id": "cus_tenant" + tenant,
        "price_id": "price_test", "currency": "usd", "unit_amount": 9900,
        "interval": "month", "quantity": 1, "success_url": "https://example.test/return",
        "cancel_url": "https://example.test/cancel",
    }
    value.update(changes)
    with database[1]() as c:
        return c.execute("SELECT %s::jsonb::text", (json.dumps(value),)).fetchone()[0].encode()


@pytest.fixture
def ready(database):
    seed(database)
    install(database)
    configure(database)
    return database


def store(database, role="worker_a"):
    return PaidCheckoutStore(lambda: database[1](role))


def history(database):
    with database[1]() as c:
        tables = c.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname='gvai_authority' "
            "AND tablename NOT LIKE 'paid_checkout_%%' ORDER BY tablename",
        ).fetchall()
        return {name: c.execute(
            f"SELECT coalesce(jsonb_agg(r ORDER BY r::text),'[]') FROM "
            f"(SELECT to_jsonb(t) r FROM gvai_authority.{name} t) q"
        ).fetchone()[0] for (name,) in tables}


def test_fresh_migration_empty_denied(database):
    install(database)
    with database[1]() as c:
        assert c.execute("SELECT count(*) FROM gvai_authority.paid_checkout_installation").fetchone()[0] == 0
    with pytest.raises(CheckoutUnavailable):
        store(database).prepare("a" * 32, b"{}")


def test_populated_history_and_existing_migrations_unchanged(database):
    seed(database)
    before = history(database)
    assert before["paid_attempts"] and before["billing_events"] and before["advisory_pilots"]
    install(database)
    assert history(database) == before


@pytest.mark.parametrize("mixed", ["billing_installation", "billing_subscriptions", "checkout_attempts"])
def test_mixed_schema_rejected_atomically(database, mixed):
    import psycopg

    with database[1]() as c:
        c.execute(f"CREATE TABLE gvai_authority.{mixed}(id integer)")
    before = history(database)
    with pytest.raises(psycopg.Error):
        install(database)
    assert history(database) == before
    with database[1]() as c:
        assert c.execute("SELECT to_regclass('gvai_authority.paid_checkout_requests')").fetchone()[0] is None


def test_default_acl_rejected_after_ddl_atomically(database):
    import psycopg

    with database[1]() as c:
        c.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA gvai_authority GRANT SELECT ON TABLES TO worker_a")
    with pytest.raises(psycopg.Error):
        install(database)
    with database[1]() as c:
        assert c.execute("SELECT to_regclass('gvai_authority.paid_checkout_requests')").fetchone()[0] is None
        assert c.execute("SELECT to_regprocedure('gvai_authority.prepare_paid_checkout_v1(text,bytea)')").fetchone()[0] is None


def test_real_roles_effective_privileges(ready):
    import psycopg

    for role in ("worker_a", "worker_b", "worker_disabled", "paid_runtime", "pilot_runtime"):
        with ready[1](role) as c:
            assert c.execute(
                "SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication,"
                "pg_has_role(current_user,'checkout_owner','MEMBER') FROM pg_roles WHERE rolname=current_user",
            ).fetchone() == (False,) * 6
            assert c.execute("SELECT has_schema_privilege(current_user,'gvai_authority','CREATE')").fetchone() == (False,)
            assert c.execute(
                "SELECT has_table_privilege(current_user,'gvai_authority.paid_checkout_requests','SELECT,INSERT,UPDATE,DELETE')",
            ).fetchone() == (False,)
        with pytest.raises(psycopg.Error):
            with ready[1](role) as c:
                c.execute("SELECT * FROM gvai_authority.paid_checkout_requests")
        with pytest.raises(psycopg.Error):
            with ready[1](role) as c:
                c.execute("SET ROLE checkout_owner")
        with pytest.raises(psycopg.Error):
            with ready[1](role) as c:
                c.execute("SELECT gvai_authority.paid_checkout_scope_v1()")
    for role in ("paid_runtime", "pilot_runtime", "worker_disabled"):
        with pytest.raises(CheckoutUnavailable):
            store(ready, role).prepare("a" * 32, request(ready))
    with ready[1]() as c:
        assert c.execute(
            "SELECT bool_and(prosecdef AND proconfig @> ARRAY['search_path=pg_catalog, gvai_authority, pg_temp']) "
            "FROM pg_proc WHERE oid IN ("
            "'gvai_authority.prepare_paid_checkout_v1(text,bytea)'::regprocedure,"
            "'gvai_authority.read_paid_checkout_v1(text)'::regprocedure,"
            "'gvai_authority.block_paid_checkout_v1(text,jsonb,text)'::regprocedure)",
        ).fetchone() == (True,)


def test_admission_cannot_be_enabled(ready):
    import psycopg

    with pytest.raises(psycopg.Error):
        with ready[1]() as c:
            c.execute("UPDATE gvai_authority.paid_checkout_installation SET admission_enabled=true")
    assert store(ready).prepare("a" * 32, request(ready))["state"] == "prepared"
    with ready[1]() as c:
        assert c.execute("SELECT admission_enabled FROM gvai_authority.paid_checkout_installation").fetchone() == (False,)
        assert c.execute(
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname='gvai_authority' AND p.proname LIKE '%%dispatch%%'",
        ).fetchone() == (0,)


@pytest.mark.parametrize("changes", [
    {"account_id": "acct_other"}, {"environment": "live"}, {"price_id": "price_other"},
    {"customer_id": "cus_tenantb"}, {"tenant_id": "tenant-b"}, {"unit_amount": 1},
    {"quantity": 2}, {"extra": True}, {"success_url": "https://attacker.test/return"},
])
def test_exact_binding_and_failure_atomicity(ready, changes):
    before = history(ready)
    with pytest.raises(CheckoutUnavailable):
        store(ready).prepare("a" * 32, request(ready, **changes))
    with ready[1]() as c:
        assert c.execute("SELECT count(*) FROM gvai_authority.paid_checkout_requests").fetchone() == (0,)
    assert history(ready) == before


def test_noncanonical_bytes_and_changed_request_denied(ready):
    raw = request(ready)
    for invalid in (raw + b" ", b'{"version":1,"version":1}', b"\xff"):
        with pytest.raises(CheckoutUnavailable):
            store(ready).prepare("a" * 32, invalid)
    first = store(ready).prepare("a" * 32, raw)
    assert store(ready).prepare("a" * 32, raw) == first
    with pytest.raises(CheckoutUnavailable):
        store(ready).prepare("a" * 32, raw.replace(b"9900", b"9901"))


def test_tenant_isolation_and_unresolved_slot(ready):
    first = store(ready).prepare("a" * 32, request(ready))
    with pytest.raises(CheckoutUnavailable):
        store(ready, "worker_b").read("a" * 32)
    with pytest.raises(CheckoutUnavailable):
        store(ready, "worker_b").block("a" * 32, first, "quarantined")
    with pytest.raises(CheckoutUnavailable):
        store(ready).prepare("c" * 32, request(ready, "c" * 32))
    assert store(ready, "worker_b").prepare("b" * 32, request(ready, "b" * 32, "b"))["tenant_ref"] != first["tenant_ref"]


def test_full_record_fence_and_no_recovery(ready):
    s = store(ready)
    first = s.prepare("a" * 32, request(ready))
    for changed in ({**first, "generation": 1}, {**first, "request_digest": "0" * 64}):
        with pytest.raises(CheckoutUnavailable):
            s.block("a" * 32, changed, "unknown")
    unknown = s.block("a" * 32, first, "unknown")
    assert unknown["generation"] == 1
    with pytest.raises(CheckoutUnavailable):
        s.block("a" * 32, first, "quarantined")
    with pytest.raises(CheckoutUnavailable):
        s.block("a" * 32, unknown, "prepared")
    quarantined = s.block("a" * 32, unknown, "quarantined")
    with pytest.raises(CheckoutUnavailable):
        s.block("a" * 32, quarantined, "unknown")
    assert s.prepare("a" * 32, request(ready)) == quarantined


def test_concurrent_duplicate_and_distinct_attempts(ready):
    def prepare(attempt):
        try:
            return store(ready).prepare(attempt, request(ready, attempt))["attempt_id"]
        except CheckoutUnavailable:
            return "denied"
    with ThreadPoolExecutor(4) as executor:
        assert list(executor.map(prepare, ["a" * 32] * 4)) == ["a" * 32] * 4
    with ThreadPoolExecutor(4) as executor:
        assert list(executor.map(prepare, ["b" * 32, "c" * 32, "d" * 32, "e" * 32])) == ["denied"] * 4


@pytest.mark.parametrize("commit_happens", [False, True])
def test_ambiguous_real_commit_never_reports_success(ready, commit_happens):
    class LostAcknowledgement:
        def __init__(self):
            self.connection = ready[1]("worker_a")

        @property
        def autocommit(self):
            return self.connection.autocommit

        @autocommit.setter
        def autocommit(self, value):
            self.connection.autocommit = value

        def cursor(self):
            return self.connection.cursor()

        def commit(self):
            if commit_happens:
                self.connection.commit()
            raise OSError("Synthetic acknowledgement loss")

        def rollback(self):
            self.connection.rollback()

        def close(self):
            self.connection.close()

    with pytest.raises(CheckoutCommitUnknown):
        PaidCheckoutStore(LostAcknowledgement).prepare("a" * 32, request(ready))
    if commit_happens:
        assert store(ready).read("a" * 32)["state"] == "prepared"
    else:
        with pytest.raises(CheckoutUnavailable):
            store(ready).read("a" * 32)


@pytest.mark.parametrize("column,value", [
    ("revoked", "true"), ("checkout_started_at", "clock_timestamp()"),
    ("checkout_session_id", "'cs_test_legacy'"), ("checkout_url", "'https://checkout.stripe.com/legacy'"),
    ("subscription_id", "'sub_legacy'"),
])
def test_legacy_or_revoked_billing_blocks_without_history_loss(ready, column, value):
    with ready[1]() as c:
        c.execute(f"UPDATE gvai_authority.billing_customers SET {column}={value} WHERE customer_id='cus_tenanta'")
    before = history(ready)
    with pytest.raises(CheckoutUnavailable):
        store(ready).prepare("a" * 32, request(ready))
    assert history(ready) == before


def test_current_worker_membership_and_tenant_denial(ready):
    for statement in (
        "UPDATE gvai_authority.paid_checkout_workers SET enabled=false WHERE role_name='worker_a'",
        "UPDATE gvai_authority.tenant_memberships SET status='disabled' WHERE principal_id='tenant-a-principal'",
        "UPDATE gvai_authority.tenants SET status='disabled' WHERE tenant_id='tenant-a'",
    ):
        with ready[1]() as c:
            c.execute(statement)
        with pytest.raises(CheckoutUnavailable):
            store(ready).prepare("a" * 32, request(ready))


def test_request_history_cannot_be_rewritten_or_deleted(ready):
    import psycopg

    original = store(ready).prepare("a" * 32, request(ready))
    for statement in (
        "DELETE FROM gvai_authority.paid_checkout_requests",
        "UPDATE gvai_authority.paid_checkout_requests SET request_bytes=request_bytes||decode('20','hex')",
        "UPDATE gvai_authority.paid_checkout_requests SET membership_ref=membership_ref+1",
        "UPDATE gvai_authority.paid_checkout_requests SET generation=generation+1",
    ):
        with pytest.raises(psycopg.Error):
            with ready[1]() as c:
                c.execute(statement)
        assert store(ready).read("a" * 32) == original


def test_simultaneous_distinct_attempts_only_one_wins(ready):
    def prepare(attempt):
        try:
            return store(ready).prepare(attempt, request(ready, attempt))["state"]
        except CheckoutUnavailable:
            return "denied"
    with ThreadPoolExecutor(4) as executor:
        results = list(executor.map(prepare, [char * 32 for char in "abcd"]))
    assert results.count("prepared") == 1
    assert results.count("denied") == 3
