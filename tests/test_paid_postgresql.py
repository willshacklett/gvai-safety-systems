"""Opt-in real paid SQL contracts in a cached, network-disabled disposable image."""

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_PAID_POSTGRES") != "1",
    reason="Opt in to cached, network-disabled disposable PostgreSQL SQL contracts.",
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def postgres():
    if shutil.which("docker") is None:
        pytest.skip("Docker unavailable; no installation.")
    if subprocess.run(
        ["docker", "image", "inspect", "postgres:16"], capture_output=True, timeout=10,
    ).returncode:
        pytest.skip("Cached postgres:16 unavailable; no image pull.")
    name = "gvai-paid-contract-" + secrets.token_hex(8)
    created = False

    def docker(*args, input=None, timeout=60):
        result = subprocess.run(
            ["docker", *args], input=input, text=True, capture_output=True, timeout=timeout,
            env={**os.environ, "POSTGRES_PASSWORD": secrets.token_hex(32)},
        )
        assert result.returncode == 0, "Disposable paid PostgreSQL operation failed: " + result.stderr[-1500:]
        return result.stdout.strip()

    def sql(statement, *, user="paid_owner", allow_error=False):
        result = subprocess.run(
            ["docker", "exec", "-i", name, "psql", "-X", "-qAt",
             "-v", "ON_ERROR_STOP=1", "-U", user, "-d", "gvai_advisory_test_paid"],
            input=statement, text=True, capture_output=True, timeout=30,
        )
        if allow_error:
            return result
        assert result.returncode == 0, "Synthetic paid SQL failed: " + result.stderr[-1500:]
        return result.stdout.strip()

    try:
        docker(
            "create", "--pull=never", "--network=none", "--name", name,
            "--memory", "512m", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m",
            "--env", "POSTGRES_PASSWORD", "postgres:16",
            "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
        )
        created = True
        docker("start", name)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                capture_output=True, timeout=5,
            )
            if result.returncode == 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("Disposable paid PostgreSQL startup timed out.")
        assert docker("inspect", "--format", "{{.HostConfig.NetworkMode}}", name) == "none"
        assert docker("inspect", "--format", "{{len .HostConfig.PortBindings}}", name) == "0"
        docker(
            "exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
            input="CREATE ROLE paid_owner LOGIN; CREATE ROLE paid_runtime LOGIN;\n"
                  "CREATE DATABASE gvai_advisory_test_paid OWNER paid_owner;\n"
                  "REVOKE ALL ON DATABASE gvai_advisory_test_paid FROM PUBLIC;\n"
                  "GRANT CONNECT ON DATABASE gvai_advisory_test_paid TO paid_owner,paid_runtime;\n",
        )
        for filename in (
            "001_reservation_authority_v1.sql", "002_restricted_reservation_routine_v1.sql",
            "003_advisory_pilots_v1.sql", "004_paid_advisory_v1.sql",
        ):
            sql((ROOT / "migrations/postgresql" / filename).read_text())
        sql("""
            GRANT USAGE ON SCHEMA gvai_authority TO paid_runtime;
            GRANT EXECUTE ON FUNCTION
                gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text),
                gvai_authority.complete_paid_v1(text,bytea,text,text,boolean),
                gvai_authority.paid_usage_v1(text,bytea,text) TO paid_runtime;
            INSERT INTO gvai_authority.authority_state(singleton_id,authority_id,epoch,trust_domain)
                VALUES(1,'billing-test',1,'disposable');
            INSERT INTO gvai_authority.tenants(tenant_id,status)
                VALUES('tenant-a','active'),('tenant-b','active');
            INSERT INTO gvai_authority.tenant_memberships(tenant_ref,principal_id,status)
                SELECT tenant_ref,tenant_id||'-principal','active' FROM gvai_authority.tenants;
            INSERT INTO gvai_authority.resource_ownerships
                (resource_id,ownership_version,tenant_ref,resource_kind,status)
                SELECT 'project-'||right(tenant_id,1),1,tenant_ref,'evaluation','active'
                FROM gvai_authority.tenants;
            INSERT INTO gvai_authority.customer_credentials
                (key_id,tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,expires_at)
                SELECT repeat(right(tenant_id,1),32),tenant_ref,membership_ref,
                       decode(repeat('c',64),'hex'),ARRAY['evaluation:run','usage:read'],
                       'active',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day'
                FROM gvai_authority.tenants JOIN gvai_authority.tenant_memberships USING(tenant_ref);
            INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id,subscription_id)
                SELECT tenant_ref,'cus_'||right(tenant_id,1),'sub_'||right(tenant_id,1)
                FROM gvai_authority.tenants;
            INSERT INTO gvai_authority.billing_periods(invoice_id,tenant_ref,subscription_id,starts_at,ends_at)
                SELECT 'in_'||right(tenant_id,1),tenant_ref,'sub_'||right(tenant_id,1),
                       clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour'
                FROM gvai_authority.tenants;
            UPDATE gvai_authority.billing_customers SET
                current_invoice='in_'||right(customer_id,1),eligible=true,
                verified_until=clock_timestamp()+interval '1 minute',
                access_until=clock_timestamp()+interval '1 hour';
        """)
        yield sql
    finally:
        if created:
            docker("rm", "--force", "--volumes", name)


def test_real_paid_sql_isolation_replay_quota_revocation_and_privileges(postgres):
    sql = postgres

    def reserve(request, project="project-a", payload="d"):
        return sql(
            "SELECT gvai_authority.reserve_paid_v1(repeat('a',32),decode(repeat('c',64),'hex'),"
            f"'billing-test',1,'disposable','{request}','{project}',repeat('{payload}',64));",
            user="paid_runtime",
        )

    assert reserve("foreign", "project-b") == "unauthorized"
    with ThreadPoolExecutor(4) as executor:
        duplicate = list(executor.map(lambda _: reserve("same"), range(4)))
    assert duplicate.count("reserved") == 1
    assert duplicate.count("replay") == 3
    assert reserve("same", payload="e") == "conflict"
    assert sql(
        "SELECT gvai_authority.complete_paid_v1(repeat('a',32),decode(repeat('c',64),'hex'),"
        "'project-a','same',true);", user="paid_runtime",
    ) == "completed"
    assert sql(
        "SELECT * FROM gvai_authority.paid_usage_v1(repeat('a',32),"
        "decode(repeat('c',64),'hex'),'project-a');", user="paid_runtime",
    ) == "100000|1|0|1|0"
    assert sql(
        "SELECT * FROM gvai_authority.billing_customers;", user="paid_runtime", allow_error=True,
    ).returncode != 0
    assert sql(
        "UPDATE gvai_authority.billing_periods SET consumed=consumed+1 WHERE invoice_id='in_a';",
        allow_error=True,
    ).returncode != 0, "Deferred count validation must reject unmatched consumption."
    # Owner-only fixture seeding creates 99,999 matching synthetic attempts without
    # running 99,998 HTTP calls; restore every guard before testing the actual boundary.
    sql("""
        BEGIN;
        ALTER TABLE gvai_authority.billing_periods DISABLE TRIGGER billing_period_guard;
        ALTER TABLE gvai_authority.billing_periods DISABLE TRIGGER paid_period_count;
        ALTER TABLE gvai_authority.paid_attempts DISABLE TRIGGER paid_attempt_count;
        INSERT INTO gvai_authority.paid_attempts
            SELECT 1,'in_a',encode(gvai_authority.digest(convert_to('seed-'||n,'UTF8'),'sha256'),'hex'),
                   repeat('d',64),repeat('e',64),'completed'
            FROM generate_series(1,99998) n;
        UPDATE gvai_authority.billing_periods SET consumed=99999 WHERE invoice_id='in_a';
        ALTER TABLE gvai_authority.billing_periods ENABLE TRIGGER billing_period_guard;
        ALTER TABLE gvai_authority.billing_periods ENABLE TRIGGER paid_period_count;
        ALTER TABLE gvai_authority.paid_attempts ENABLE TRIGGER paid_attempt_count;
        COMMIT;
    """)
    assert sql("SELECT count(*) FROM gvai_authority.paid_attempts WHERE invoice_id='in_a';") == "99999"
    with ThreadPoolExecutor(4) as executor:
        race = list(executor.map(lambda n: reserve("final-" + str(n)), range(4)))
    assert race.count("reserved") == 1
    assert race.count("quota_exhausted") == 3
    assert sql("SELECT consumed FROM gvai_authority.billing_periods WHERE invoice_id='in_a';") == "100000"
    sql("UPDATE gvai_authority.billing_customers SET eligible=false WHERE customer_id='cus_a';")
    assert reserve("suspended") == "unauthorized"
    sql("UPDATE gvai_authority.billing_customers SET eligible=true,verified_until=clock_timestamp()-interval '1 second' WHERE customer_id='cus_a';")
    assert reserve("stale") == "unauthorized"
    sql("UPDATE gvai_authority.billing_customers SET verified_until=clock_timestamp()+interval '1 minute' WHERE customer_id='cus_a';")
    sql("UPDATE gvai_authority.customer_credentials SET status='revoked',revoked_at=clock_timestamp() WHERE key_id=repeat('a',32);")
    assert reserve("revoked") == "unauthorized"
    sql("UPDATE gvai_authority.billing_customers SET revoked=true WHERE customer_id='cus_a';")
    assert sql(
        "UPDATE gvai_authority.billing_customers SET revoked=false WHERE customer_id='cus_a';",
        allow_error=True,
    ).returncode != 0
