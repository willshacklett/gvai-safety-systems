"""Disposable PostgreSQL harness shared by the reconciliation tests.

Needs Docker and a cached postgres:16 image (never pulled by tests). When the
caller sets the require flag (CI), a missing prerequisite fails instead of skipping.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
from typing import Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = (
    "001_reservation_authority_v1.sql", "002_restricted_reservation_routine_v1.sql",
    "003_advisory_pilots_v1.sql", "004_paid_advisory_v1.sql",
    "007_paid_checkout_state_v1.sql", "008_self_service_accounts_v1.sql",
    "009_subscription_reconciliation_v1.sql", "010_subscription_denial_hold_v1.sql",
    "011_legacy_billing_quarantine_v1.sql",
    "012_bounded_billing_integrity_v1.sql",
)
RECONCILER_FUNCTIONS = (
    "billing_upgrade_ready_v1()",
    "billing_integrity_ready_v12()",
    "reconcile_claim_due_v1(integer,integer)",
    "reconcile_signal_v1(text,text,text,bigint,boolean)",
    "reconcile_signal_v1(text,text,text,bigint,boolean,text,text)",
    "reconcile_apply_v1(text,bigint,bigint,bigint,text,text,bigint,bigint,boolean,bigint,boolean)",
    "reconcile_fail_v1(text,bigint,text,text)",
    "reconcile_status_v1()",
)
PAID_FUNCTIONS = (
    "reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)",
    "complete_paid_v1(text,bytea,text,text,boolean)",
    "paid_usage_v1(text,bytea,text)",
)


class Postgres:
    def __init__(self, port: int, passwords: dict[str, str], database: str) -> None:
        self.port, self.passwords, self.database = port, passwords, database

    def dsn(self, role: str) -> str:
        return (
            f"host=127.0.0.1 port={self.port} dbname={self.database} "
            f"user={role} password={self.passwords[role]}"
        )

    def connect(self, role: str):
        import psycopg
        return psycopg.connect(self.dsn(role), connect_timeout=3)


@contextmanager
def disposable_postgres(
    require_flag: str, *, migrations: tuple[str, ...] = MIGRATIONS,
    roles: tuple[str, ...] = ("m2_owner", "m2_runtime", "m2_reconciler"),
) -> Iterator[Postgres]:
    import psycopg

    unavailable = pytest.fail if os.environ.get(require_flag) == "1" else pytest.skip
    if shutil.which("docker") is None:
        unavailable("Docker unavailable.")
    if subprocess.run(["docker", "image", "inspect", "postgres:16"], capture_output=True).returncode:
        unavailable("Cached postgres:16 unavailable; no image pull.")
    name = "gvai-m2-" + secrets.token_hex(8)
    admin_password = secrets.token_hex(16)
    passwords = {role: secrets.token_hex(16) for role in roles}
    database = "gvai_m2_test"

    def docker(*args: str, input: str | None = None) -> str:
        result = subprocess.run(
            ["docker", *args], input=input, text=True, capture_output=True, timeout=120,
            env={**os.environ, "POSTGRES_PASSWORD": admin_password},
        )
        assert result.returncode == 0, "docker failed: " + result.stderr[-800:]
        return result.stdout.strip()

    created = False
    try:
        docker(
            "run", "--detach", "--pull=never", "--name", name, "--memory", "512m",
            "--pids-limit", "256", "--security-opt", "no-new-privileges:true",
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m", "postgres:16",
            "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
            "-c", "max_connections=100",
        )
        created = True
        port = int(docker("port", name, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                capture_output=True,
            )
            if probe.returncode == 0:
                time.sleep(1)
                break
            time.sleep(0.2)
        else:
            pytest.fail("PostgreSQL startup timed out.")
        grants = "".join(f"CREATE ROLE {role} LOGIN PASSWORD '{passwords[role]}';" for role in roles)
        grants += f"CREATE DATABASE {database} OWNER m2_owner;"
        grants += f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;"
        grants += f"GRANT CONNECT ON DATABASE {database} TO {','.join(roles)};"
        docker("exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres", input=grants)
        server = Postgres(port, passwords, database)
        with psycopg.connect(server.dsn("m2_owner"), autocommit=True) as connection:
            for migration in migrations:
                connection.execute((ROOT / "migrations/postgresql" / migration).read_text())
            connection.execute(
                "GRANT USAGE ON SCHEMA gvai_authority TO m2_runtime, m2_reconciler;"
                "GRANT EXECUTE ON FUNCTION "
                + ",".join("gvai_authority." + f for f in PAID_FUNCTIONS) + " TO m2_runtime;"
                "INSERT INTO gvai_authority.authority_state(singleton_id,authority_id,epoch,trust_domain)"
                " VALUES(1,'m2-test',1,'disposable');"
            )
            if "011_legacy_billing_quarantine_v1.sql" in migrations:
                connection.execute("GRANT EXECUTE ON FUNCTION gvai_authority.billing_upgrade_ready_v1() TO m2_runtime;")
            if "012_bounded_billing_integrity_v1.sql" in migrations:
                connection.execute("GRANT EXECUTE ON FUNCTION gvai_authority.billing_integrity_ready_v12() TO m2_runtime;")
            if "009_subscription_reconciliation_v1.sql" in migrations:
                connection.execute(
                    "GRANT EXECUTE ON FUNCTION "
                    + ",".join("gvai_authority." + f for f in RECONCILER_FUNCTIONS
                        if ("boolean,text,text" not in f or "010_subscription_denial_hold_v1.sql" in migrations)
                        and ("billing_upgrade_ready" not in f or "011_legacy_billing_quarantine_v1.sql" in migrations)
                        and ("billing_integrity_ready" not in f or "012_bounded_billing_integrity_v1.sql" in migrations)) + " TO m2_reconciler;"
                )
        yield server
    finally:
        if created:
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True)
