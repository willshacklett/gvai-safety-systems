"""Opt-in disposable HTTPS -> real advisory application -> PostgreSQL acceptance."""

import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import time
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from gvai.commercial_api_keys import CustomerApiKeys
from gvai.commercial_identity import CommercialCapability
from gvai.postgresql_advisory import PostgreSQLCustomerStore
from gvai.private_staging import PrivateStagingApplication, StagingConfig
from test_postgresql_advisory_integration import (
    AUTHORITY, TELEMETRY, database as migrated_database,
)
from test_private_https import real_proxy


pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_ADVISORY_HTTPS_POSTGRES") != "1",
    reason="Opt in to disposable local Nginx/mTLS and PostgreSQL acceptance.",
)


@pytest.fixture(scope="module")
def disposable_postgres():
    missing = [name for name in ("docker", "nginx", "openssl") if shutil.which(name) is None]
    if importlib.util.find_spec("psycopg") is None:
        missing.append("psycopg")
    if missing:
        pytest.skip("Missing existing prerequisites (no installation): " + ", ".join(missing))

    def docker(*args, **kwargs):
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=60, **kwargs,
        )
        if result.returncode:
            pytest.fail("Disposable PostgreSQL operation failed (details withheld).")
        return result.stdout

    if subprocess.run(
        ["docker", "image", "inspect", "postgres:16"], capture_output=True, timeout=10,
    ).returncode:
        pytest.skip("Cached postgres:16 image unavailable; pulling is not permitted.")
    suffix = secrets.token_hex(8)
    container = "gvai-https-postgres-" + suffix
    database_name = "gvai_advisory_test_" + suffix
    owner, runtime = "owner_" + suffix, "runtime_" + suffix
    admin_password, owner_password, runtime_password = (
        secrets.token_hex(32) for _ in range(3)
    )
    created = False
    try:
        docker(
            "create", "--pull=never", "--name", container,
            "--memory", "512m", "--pids-limit", "128",
            "--security-opt", "no-new-privileges:true",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m",
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
            "postgres:16", "-c", "log_statement=none",
            "-c", "log_min_error_statement=panic",
            "-c", "log_parameter_max_length=0",
            "-c", "log_parameter_max_length_on_error=0",
            env={**os.environ, "POSTGRES_PASSWORD": admin_password},
        )
        created = True
        docker("start", container)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["docker", "exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                capture_output=True, timeout=5,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.1)
        else:
            pytest.fail("Disposable PostgreSQL startup timed out.")
        info = json.loads(docker("inspect", container))[0]
        bindings = info["NetworkSettings"]["Ports"]["5432/tcp"]
        assert len(bindings) == 1 and bindings[0]["HostIp"] == "127.0.0.1"
        assert not any(mount["Type"] == "bind" for mount in info["Mounts"])
        port = int(bindings[0]["HostPort"])
        # All SQL identifiers/passwords below are locally generated hex, not input.
        docker(
            "exec", "-i", container, "psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1",
            input=(
                f"CREATE ROLE {owner} LOGIN PASSWORD '{owner_password}';\n"
                f"CREATE ROLE {runtime} LOGIN PASSWORD '{runtime_password}';\n"
                f"CREATE DATABASE {database_name} OWNER {owner};\n"
                f"REVOKE ALL ON DATABASE {database_name} FROM PUBLIC;\n"
                f"GRANT CONNECT ON DATABASE {database_name} TO {owner}, {runtime};\n"
            ),
        )
        with patch.dict(os.environ, {
            "GVAI_TEST_POSTGRES_OWNER_DSN":
                f"host=127.0.0.1 port={port} dbname={database_name} user={owner} password={owner_password}",
            "GVAI_TEST_POSTGRES_RUNTIME_DSN":
                f"host=127.0.0.1 port={port} dbname={database_name} user={runtime} password={runtime_password}",
        }):
            yield
    finally:
        if created:
            docker("rm", "--force", "--volumes", container)


@pytest.fixture(scope="module")
def database(disposable_postgres, request):
    # Reuse the fresh-database, migration and restricted-role checks unchanged.
    return request.getfixturevalue("migrated_database")


@pytest.fixture
def tmp_path(tmp_path_factory):
    with TemporaryDirectory(prefix="gvai-combined-pki-", dir=tmp_path_factory.getbasetemp()) as directory:
        yield Path(directory)


@pytest.fixture
def verifier_secret():
    return secrets.token_bytes(32)


@pytest.fixture
def postgres_application(database, verifier_secret):
    app = PrivateStagingApplication(StagingConfig(
        os.environ["GVAI_TEST_POSTGRES_RUNTIME_DSN"], verifier_secret, AUTHORITY, port=0,
    ))
    app.start()
    try:
        yield app
    finally:
        app.stop()


@pytest.mark.parametrize("real_proxy", ["postgres_application"], indirect=True)
def test_disposable_mtls_durable_advisory_pilot(
    database, verifier_secret, postgres_application, real_proxy,
):
    app = postgres_application
    store = PostgreSQLCustomerStore(database.owner)
    keys = CustomerApiKeys(store, verifier_secret=verifier_secret)
    now = int(time.time())
    tenants = []
    for label in ("a", "b"):
        suffix = label + secrets.token_hex(6)
        tenant, principal, project = "tenant-" + suffix, "principal-" + suffix, "project-" + suffix
        store.provision_pilot(
            tenant_id=tenant, principal_id=principal, resource_id=project,
            allowance=2, starts_at=now - 60, expires_at=now + 3600,
        )
        issued = keys.issue(
            tenant_id=tenant, principal_id=principal,
            capabilities=frozenset(CommercialCapability), expires_at=now + 3600,
        )
        tenants.append((tenant, principal, project, issued.key_id, issued.take_secret()))
    a, b = tenants

    def request(method, path, credential=None, payload=None, client=True):
        # Respect the unchanged ingress's 2 requests/second source bucket.
        time.sleep(0.55)
        headers = {"Content-Type": "application/json"}
        if credential is not None:
            headers["Authorization"] = "Bearer " + credential
        status, body = real_proxy.request(
            path, method=method, headers=headers, payload=payload, client=client,
        )
        return status, json.loads(body)

    def evaluate(tenant, identifier):
        return request("POST", "/v1/evaluations", tenant[4], {
            "version": "v1", "request_id": identifier, "resource_id": tenant[2],
            "telemetry": TELEMETRY, "reported_effects": [],
        })

    for tenant in tenants:
        status, body = evaluate(tenant, "first")
        assert status == 200
        assert body["evaluation"]["decision"] in {"ALLOW", "QUALIFY", "BLOCK"}
        assert body["evaluation"]["advisory_only"] is True
        assert body["evaluation"]["enforcement_applied"] is False
        status, body = request("GET", "/v1/usage/" + tenant[2], tenant[4])
        assert status == 200 and body["usage"]["consumed"] == 1
    try:
        assert request("GET", "/v1/usage/" + a[2], a[4], client=False)[0] != 200
    except ssl.SSLError:
        pass
    assert request("GET", "/v1/usage/" + a[2])[0] == 401
    assert request("GET", "/v1/usage/" + a[2], "invalid")[0] == 403
    assert request("GET", "/v1/usage/" + b[2], a[4])[0] == 403
    assert request("POST", "/v1/evaluations", a[4], {
        "version": "v1", "request_id": "foreign", "resource_id": b[2],
        "telemetry": TELEMETRY, "reported_effects": [],
    })[0] == 403
    assert evaluate(a, "first")[0] == 409
    assert evaluate(a, "second")[0] == 200
    assert evaluate(a, "over-cap")[0] == 429
    historical = CustomerApiKeys(store, verifier_secret=verifier_secret, clock=lambda: now - 120)
    expired = historical.issue(
        tenant_id=b[0], principal_id=b[1], capabilities=frozenset(CommercialCapability),
        expires_at=now - 60,
    ).take_secret()
    assert request("GET", "/v1/usage/" + b[2], expired)[0] == 403
    assert evaluate((*b[:4], expired), "expired")[0] == 403
    assert keys.revoke(b[3])
    assert request("GET", "/v1/usage/" + b[2], b[4])[0] == 403
    assert evaluate(b, "revoked")[0] == 403

    port = app.server.server_port
    app.stop()
    restarted = PrivateStagingApplication(StagingConfig(
        os.environ["GVAI_TEST_POSTGRES_RUNTIME_DSN"], verifier_secret, AUTHORITY, port=port,
    ))
    try:
        restarted.start()
        status, body = request("GET", "/v1/usage/" + a[2], a[4])
        assert status == 200
        assert body["usage"] == {
            "allowance": 2, "consumed": 2, "reserved": 0,
            "completed": 2, "failed": 0, "remaining": 0,
        }
        assert evaluate(a, "first")[0] == 409
        assert evaluate(a, "still-over-cap")[0] == 429
        assert request("GET", "/v1/usage/" + b[2], b[4])[0] == 403
    finally:
        restarted.stop()
    for credential in (a[4], b[4], expired):
        assert credential not in real_proxy.log.read_text()
