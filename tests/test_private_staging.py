from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
import json
import os
import threading
import time

import pytest

from gvai.commercial_http import PrivateHttpEndpoints, create_server
from gvai.commercial_service import CommercialEvaluationService
from gvai.commercial_usage import UsageReason, UsageResult
from gvai.postgresql_advisory import AdvisoryPilotUsage
from gvai.private_staging import (
    BoundedConnections, StagingConfig, StagingUnavailable, main, read_private_json,
)


class Connection:
    autocommit = False

    def __init__(self):
        self.commits = self.rollbacks = self.closes = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closes += 1


def test_connections_cap_and_checkout_deadline():
    opened = []

    def connect():
        connection = Connection()
        opened.append(connection)
        return connection

    factory = BoundedConnections(connect, maximum=2, checkout_timeout=0.02)
    first, second = factory(), factory()
    start = time.monotonic()
    with ThreadPoolExecutor(4) as executor:
        futures = [executor.submit(factory) for _ in range(4)]
        for future in futures:
            with pytest.raises(StagingUnavailable):
                future.result(timeout=1)
    assert time.monotonic() - start < 1
    assert len(opened) == 2
    first.close()
    first.close()
    with factory():
        pass
    second.close()
    factory.shutdown()
    assert [item.closes for item in opened] == [1, 1, 1]
    assert opened[2].commits == 1
    with pytest.raises(StagingUnavailable):
        factory()


def test_connection_failure_does_not_leak_or_retry(caplog):
    attempts = []

    def fail():
        attempts.append(1)
        raise RuntimeError("postgresql://private-password@host/database")

    factory = BoundedConnections(fail, maximum=1)
    for _ in range(2):
        with pytest.raises(StagingUnavailable) as error:
            factory()
        assert "private-password" not in str(error.value)
        assert error.value.__suppress_context__
    factory.shutdown()
    assert len(attempts) == 2
    assert "private-password" not in caplog.text


def test_context_rollback_and_ambiguous_commit_are_not_retried():
    connection = Connection()
    factory = BoundedConnections(lambda: connection, maximum=1)
    with pytest.raises(ValueError):
        with factory():
            raise ValueError("failed attempt")
    assert (connection.commits, connection.rollbacks, connection.closes) == (0, 1, 1)

    def unknown():
        connection.commits += 1
        raise RuntimeError("acknowledgement lost")

    connection.commit = unknown
    with pytest.raises(RuntimeError):
        with factory():
            pass
    assert connection.commits == 1
    assert connection.rollbacks == 1
    assert connection.closes == 2
    factory.shutdown()


def test_shutdown_denies_waiters_and_drains_active():
    factory = BoundedConnections(Connection, maximum=1, checkout_timeout=1)
    lease = factory()
    with ThreadPoolExecutor(2) as executor:
        waiting = executor.submit(factory)
        stopping = executor.submit(factory.shutdown, 1)
        with pytest.raises(StagingUnavailable):
            waiting.result(timeout=2)
        lease.close()
        stopping.result(timeout=2)
    with pytest.raises(StagingUnavailable):
        factory()


def test_drain_timeout_reports_failure_without_forcing_unknown_transaction():
    factory = BoundedConnections(Connection, maximum=1)
    lease = factory()
    with pytest.raises(StagingUnavailable):
        factory.shutdown(0.01)
    assert lease._connection.closes == 0
    lease.close()
    factory.shutdown()


def test_stopping_immediately_fences_new_connections_before_drain():
    factory = BoundedConnections(Connection, maximum=2)
    lease = factory()
    factory.stop_accepting()
    with pytest.raises(StagingUnavailable):
        factory()
    lease.close()
    factory.shutdown()


@pytest.mark.parametrize("maximum", [0, 33, True, 1.5])
def test_invalid_connection_bounds(maximum):
    with pytest.raises(ValueError):
        BoundedConnections(Connection, maximum=maximum)


@pytest.mark.parametrize("timeout", [0, -1, 6, True, float("inf"), float("nan")])
def test_invalid_checkout_bounds(timeout):
    with pytest.raises(ValueError):
        BoundedConnections(Connection, checkout_timeout=timeout)


def private_file(tmp_path, data):
    path = tmp_path / "private.json"
    path.write_text(json.dumps(data), encoding="ascii")
    path.chmod(0o600)
    return path


def config_data():
    return {
        "mode": "private-staging",
        "database_dsn": "test-only-secret-dsn",
        "verifier_secret_hex": "01" * 32,
        "authority": {"authority_id": "test", "epoch": 1, "trust_domain": "test"},
        "port": 0, "max_connections": 2,
    }


def test_private_config_redacted_and_strict(tmp_path):
    data = config_data()
    path = private_file(tmp_path, data)
    config = StagingConfig.load(str(path))
    assert config.verifier_secret == b"\x01" * 32
    assert data["database_dsn"] not in repr(config)
    assert data["verifier_secret_hex"] not in repr(config)
    for name, value in (
        ("mode", "production"), ("host", "0.0.0.0"), ("max_connections", True),
        ("port", -1), ("verifier_secret_hex", "short"),
        ("operator_database_dsn", "owner"), ("authority", {"epoch": 0}),
    ):
        path.write_text(json.dumps({**data, name: value}))
        with pytest.raises(StagingUnavailable):
            StagingConfig.load(str(path))


def test_private_files_reject_readable_symlink_duplicate_oversize_and_fifo(tmp_path):
    path = private_file(tmp_path, {"value": "secret"})
    path.chmod(0o644)
    with pytest.raises(StagingUnavailable):
        read_private_json(str(path))
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(StagingUnavailable):
        read_private_json(str(link))
    for content in ('{"value":1,"value":2}', '{"value":NaN}', "x" * 16385):
        path.write_text(content)
        with pytest.raises(StagingUnavailable):
            read_private_json(str(path))
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(StagingUnavailable):
        read_private_json(str(fifo))


def test_cli_failure_is_redacted(tmp_path, caplog, capsys):
    path = private_file(tmp_path, config_data())
    assert main(["--config", str(path), "serve"]) == 1
    assert "test-only-secret-dsn" not in caplog.text + capsys.readouterr().err


@pytest.fixture
def private_http():
    class Usage:
        def reserve_evaluation(self, *args):
            return UsageResult(UsageReason.UNAUTHORIZED)

    state = {"ready": True, "calls": []}

    def summary(credential, resource):
        state["calls"].append((credential, resource))
        if credential == "unavailable":
            raise RuntimeError("secret-dsn")
        if credential == "tenant-a-key" and resource == "project-a":
            return AdvisoryPilotUsage(3, 1, 0, 1, 0)
        return None

    server = create_server(
        CommercialEvaluationService(Usage()),
        private_endpoints=PrivateHttpEndpoints(summary, lambda: state["ready"]),
    )
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def http(server, path, credential=None, method="GET", headers=None):
    request_headers = {} if headers is None else dict(headers)
    if credential is not None:
        request_headers["Authorization"] = "Bearer " + credential
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        connection.request(method, path, headers=request_headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read()), dict(response.getheaders())
    finally:
        connection.close()


def test_private_usage_authentication_scoping_and_failure(private_http):
    server, state = private_http
    assert server.server_address[0] == "127.0.0.1"
    assert http(server, "/v1/usage/project-a")[0] == 401
    assert http(server, "/v1/usage/project-b", "tenant-a-key")[0] == 403
    status, body, headers = http(server, "/v1/usage/project-a", "tenant-a-key")
    assert status == 200
    assert body == {
        "version": 1, "usage": {
            "allowance": 3, "consumed": 1, "reserved": 0, "completed": 1,
            "failed": 0, "remaining": 2,
        }, "advisory_only": True, "enforcement_applied": False,
    }
    assert headers["Cache-Control"] == "no-store"
    status, body, _ = http(server, "/v1/usage/project-a", "unavailable")
    assert status == 503
    assert "secret-dsn" not in json.dumps(body)


@pytest.mark.parametrize("path", [
    "/v1/usage/project-a?tenant=tenant-b", "/v1/usage/project-a%2Fproject-b",
    "/v1/usage/../project-a", "/v1/usage/project-a/other",
    "/v1/provision", "/v1/keys", "/v1/suspend",
])
def test_private_routes_cannot_inject_ownership_or_provision(private_http, path):
    server, state = private_http
    assert http(server, path, "tenant-a-key")[0] == 404
    assert state["calls"] == []
    assert http(server, path, "tenant-a-key", method="POST")[0] == (400 if "?" in path else 404)


def test_private_diagnostics_are_fixed_redacted_and_fail_closed(private_http):
    server, state = private_http
    assert http(server, "/healthz")[1] == {
        "status": "ok", "advisory_only": True, "enforcement_applied": False,
    }
    assert http(server, "/readyz")[0] == 200
    state["ready"] = False
    assert http(server, "/readyz")[:2] == (503, {
        "status": "unavailable", "advisory_only": True, "enforcement_applied": False,
    })
    assert http(server, "/healthz")[0] == 200
    assert http(server, "/readyz?dsn=secret")[0] == 404
    assert http(server, "/v1/usage/project-a", headers={"Content-Length": "0"})[0] == 400
    assert http(server, "/v1/usage/project-a", headers={"Transfer-Encoding": "chunked"})[0] == 400
