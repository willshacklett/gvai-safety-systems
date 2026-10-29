from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPConnection
import json
import socket
import time
from threading import Event, Lock, Thread, Timer

import pytest

from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
from gvai.commercial_http import MAX_BODY_BYTES, create_server
from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability,
    CommercialResourceKind,
    CommercialResourceOwnership,
)
from gvai.commercial_service import (
    CommercialEvaluationService,
    CommercialServiceResponse,
    ServiceOutcome,
    ServiceReason,
)
from gvai.commercial_usage import CommercialUsage, InMemoryUsageStore, UsageReason, UsageResult
from gvai.evaluation import evaluate_request


def timestamp(year, month):
    return datetime(year, month, 1, tzinfo=timezone.utc).timestamp()


class OwnershipStore:
    def lookup(self, resource_id):
        return {
            "project-a": CommercialResourceOwnership(
                "project-a", "tenant-a", CommercialResourceKind.EVALUATION
            ),
            "project-b": CommercialResourceOwnership(
                "project-b", "tenant-b", CommercialResourceKind.EVALUATION
            ),
        }.get(resource_id)


@pytest.fixture
def api():
    now = [timestamp(2026, 10)]
    key_store = InMemoryApiKeyStore()
    keys = CustomerApiKeys(
        key_store,
        verifier_secret=b"http-test-only-independent-verifier-secret",
        clock=lambda: now[0],
    )
    issued_a = keys.issue(
        principal_id="customer-a",
        tenant_id="tenant-a",
        capabilities=frozenset({CommercialCapability.EVALUATE}),
        expires_at=int(timestamp(2030, 1)),
    )
    credential_a = issued_a.take_secret()
    issued_b = keys.issue(
        principal_id="customer-b",
        tenant_id="tenant-b",
        capabilities=frozenset({CommercialCapability.EVALUATE}),
        expires_at=int(timestamp(2030, 1)),
    )
    credential_b = issued_b.take_secret()
    authorizer = CommercialAuthorizer(keys, OwnershipStore(), clock=lambda: now[0])
    usage = CommercialUsage(
        authorizer, InMemoryUsageStore({"tenant-a": 100, "tenant-b": 100}, clock=lambda: now[0])
    )
    evaluation_calls = [0]
    calls_lock = Lock()

    def evaluator(request):
        with calls_lock:
            evaluation_calls[0] += 1
        return evaluate_request(request)

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    server = create_server(service)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "server": server,
            "service": service,
            "usage": usage,
            "keys": keys,
            "issued_a": issued_a,
            "credential_a": credential_a,
            "credential_b": credential_b,
            "now": now,
            "evaluation_calls": evaluation_calls,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def request(api, method="POST", payload=None, *, credential=None, path="/v1/evaluations", headers=None, raw=None):
    body = raw
    if body is None and payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request_headers = {"Content-Type": "application/json"}
    if credential is not None:
        request_headers["Authorization"] = f"Bearer {credential}"
    if headers:
        request_headers.update(headers)
    connection = HTTPConnection("127.0.0.1", api["server"].server_port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def payload(**changes):
    request_data = {
        "version": "v1",
        "request_id": "request-http-1",
        "resource_id": "project-a",
        "telemetry": {
            "token_delta": 100,
            "tool_calls_delta": 1,
            "error_delta": 0,
            "repeated_action_delta": 0,
            "recursion_depth": 0,
            "latency_ms": None,
        },
        "reported_effects": [],
    }
    request_data.update(changes)
    return request_data


def wire_request(*headers, body=None):
    if body is None:
        body = json.dumps(payload(), separators=(",", ":")).encode("utf-8")
    lines = [
        b"POST /v1/evaluations HTTP/1.1",
        b"Host: localhost",
        b"Content-Type: application/json",
        f"Content-Length: {len(body)}".encode("ascii"),
        b"Authorization: Bearer test-credential",
        *[header.encode("ascii") for header in headers],
        b"",
        b"",
    ]
    return b"\r\n".join(lines) + body


def exchange_wire(server, raw):
    connection = socket.create_connection(server.server_address, timeout=2)
    connection.settimeout(2)
    try:
        connection.sendall(raw)
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)
    finally:
        connection.close()


def response_status(response):
    if not response:
        return None
    return int(response.split(b" ", 2)[1])


def start_server(service, **options):
    server = create_server(service, **options)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join()


class ErrorService:
    def __init__(self):
        self.calls = 0
        self.lock = Lock()

    def evaluate(self, *_args):
        with self.lock:
            self.calls += 1
        return CommercialServiceResponse(
            ServiceOutcome.ERROR, ServiceReason.EVALUATION_FAILURE
        )


def test_authorized_evaluation_is_advisory_and_response_is_non_cacheable(api):
    status, body, headers = request(api, payload=payload(), credential=api["credential_a"])

    result = json.loads(body)
    assert status == 200
    assert result["outcome"] == "evaluated"
    assert result["evaluation"]["decision"] in {"ALLOW", "QUALIFY", "BLOCK"}
    assert result["evaluation"]["advisory_only"] is True
    assert result["evaluation"]["enforcement_applied"] is False
    assert "allowed" not in result
    assert headers["Cache-Control"] == "no-store"
    assert api["server"].server_address[0] == "127.0.0.1"


@pytest.mark.parametrize(
    ("credential", "expected_status"),
    [(None, 401), ("not-a-customer-key", 403)],
)
def test_missing_and_invalid_credentials_fail_closed(api, credential, expected_status):
    status, body, _ = request(api, payload=payload(), credential=credential)

    assert status == expected_status
    assert json.loads(body)["error"]["code"] in {
        "authentication_required", "authorization_denied"
    }
    assert api["evaluation_calls"] == [0]


def test_expired_and_revoked_credentials_fail_closed(api):
    expired = api["keys"].issue(
        principal_id="expired-customer",
        tenant_id="tenant-a",
        capabilities=frozenset({CommercialCapability.EVALUATE}),
        expires_at=int(timestamp(2026, 11)),
    ).take_secret()
    api["now"][0] = timestamp(2026, 11)
    expired_status, expired_body, _ = request(
        api, payload=payload(), credential=expired
    )
    api["now"][0] = timestamp(2026, 10)
    assert api["keys"].revoke(api["issued_a"].key_id)
    revoked_status, revoked_body, _ = request(
        api, payload=payload(request_id="revoked-request"), credential=api["credential_a"]
    )

    assert expired_status == revoked_status == 403
    assert json.loads(expired_body)["error"]["code"] == "authorization_denied"
    assert json.loads(revoked_body)["error"]["code"] == "authorization_denied"
    assert api["evaluation_calls"] == [0]


def test_cross_tenant_resource_is_denied(api):
    status, body, _ = request(
        api, payload=payload(resource_id="project-b"), credential=api["credential_a"]
    )

    assert status == 403
    assert json.loads(body)["error"]["code"] == "authorization_denied"
    assert api["evaluation_calls"] == [0]


@pytest.mark.parametrize("allowance", [None, 0])
def test_missing_or_exhausted_quota_is_denied(api, allowance):
    allowances = api["usage"]._store._allowances
    if allowance is None:
        del allowances["tenant-a"]
    else:
        allowances["tenant-a"] = allowance
    status, body, _ = request(api, payload=payload(), credential=api["credential_a"])

    assert status == 429
    assert json.loads(body)["error"]["code"] == "quota_denied"
    assert api["evaluation_calls"] == [0]


def test_replay_and_concurrent_duplicate_requests_evaluate_once(api):
    body = payload(request_id="concurrent-http-request")

    def submit(_index):
        return request(api, payload=body, credential=api["credential_a"])[0]

    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(submit, range(24)))

    assert statuses.count(200) == 1
    assert statuses.count(409) == 23
    assert api["evaluation_calls"] == [1]


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b'{"version":"v1","version":"v1"}',
        b'{"version":"v1","n":NaN}',
    ],
)
def test_malformed_and_duplicate_json_fields_are_rejected(api, raw):
    status, body, _ = request(api, credential=api["credential_a"], raw=raw)

    assert status == 400
    assert json.loads(body)["error"]["code"] == "invalid_request"
    assert api["evaluation_calls"] == [0]


@pytest.mark.parametrize("extra_field", ["tenant_id", "roles", "capabilities"])
def test_caller_cannot_supply_trusted_identity_fields(api, extra_field):
    data = payload()
    data[extra_field] = "tenant-b"
    status, body, _ = request(api, payload=data, credential=api["credential_a"])

    assert status == 400
    assert json.loads(body)["error"]["code"] == "invalid_request"
    assert api["evaluation_calls"] == [0]


def test_oversized_body_and_headers_are_rejected(api):
    status, body, _ = request(
        api,
        credential=api["credential_a"],
        raw=b"x" * (MAX_BODY_BYTES + 1),
    )
    assert status == 413
    assert json.loads(body)["error"]["code"] == "request_too_large"

    header_status, header_body, _ = request(
        api,
        payload=payload(),
        credential=api["credential_a"],
        headers={"X-Oversized": "x" * 17_000},
    )
    assert header_status == 431
    assert json.loads(header_body)["error"]["code"] == "headers_too_large"

    line_status, line_body, _ = request(
        api,
        method="GET",
        path="/" + "x" * 65_536,
    )
    assert line_status == 414
    assert json.loads(line_body)["error"]["code"] == "request_too_large"
    assert api["evaluation_calls"] == [0]


def test_method_content_type_and_query_string_are_restricted(api, capsys):
    get_status, get_body, get_headers = request(api, method="GET")
    type_status, type_body, _ = request(
        api,
        payload=payload(),
        credential=api["credential_a"],
        headers={"Content-Type": "text/plain"},
    )
    query_status, query_body, _ = request(
        api,
        payload=payload(),
        credential=api["credential_a"],
        path=f"/v1/evaluations?credential={api['credential_a']}",
    )

    assert get_status == 405
    assert get_headers["Allow"] == "POST"
    assert json.loads(get_body)["error"]["code"] == "method_not_allowed"
    assert type_status == 415
    assert json.loads(type_body)["error"]["code"] == "unsupported_media_type"
    assert query_status == 400
    assert json.loads(query_body)["error"]["code"] == "query_not_allowed"
    assert api["credential_a"].encode() not in get_body + type_body + query_body
    captured = capsys.readouterr()
    assert api["credential_a"] not in captured.out + captured.err
    assert api["evaluation_calls"] == [0]


def test_accounting_completion_failure_is_sanitized(api):
    def failed_completion(*_args, **_kwargs):
        return UsageResult(UsageReason.ACCOUNTING_ERROR)

    api["usage"].complete = failed_completion
    status, body, _ = request(api, payload=payload(), credential=api["credential_a"])

    assert status == 503
    assert json.loads(body)["error"]["code"] == "accounting_failure"
    assert "evaluation" not in json.loads(body)
    assert api["evaluation_calls"] == [1]


def test_sensitive_exception_data_is_not_returned_or_logged(api, capsys):
    marker = api["credential_a"] + " internal-marker"

    def failing_evaluator(_request):
        raise RuntimeError(marker)

    api["service"]._evaluator = failing_evaluator
    status, body, _ = request(api, payload=payload(), credential=api["credential_a"])
    captured = capsys.readouterr()

    assert status == 500
    assert json.loads(body)["error"]["code"] == "evaluation_failure"
    assert marker.encode() not in body
    assert api["credential_a"] not in captured.out + captured.err


def test_http_evaluation_never_invokes_supervisor_stop(api, monkeypatch):
    from gvai.external_control import GVExternalControlPlane
    from gvai.runtime_policy import GVRuntimePolicy

    def forbidden(*_args, **_kwargs):
        raise AssertionError("HTTP evaluation must not call supervisor STOP")

    monkeypatch.setattr(GVExternalControlPlane, "evaluate_internal_shutdown", forbidden)
    monkeypatch.setattr(GVRuntimePolicy, "evaluate_internal_shutdown", forbidden)

    status, body, _ = request(api, payload=payload(), credential=api["credential_a"])

    assert status == 200
    assert json.loads(body)["evaluation"]["enforcement_applied"] is False



@pytest.mark.parametrize(
    ("options",),
    [
        ({"max_concurrent_handlers": 0},),
        ({"max_concurrent_handlers": 129},),
        ({"max_concurrent_handlers": True},),
        ({"request_timeout": 0.049},),
        ({"request_timeout": 60.1},),
        ({"request_timeout": 10**1000},),
        ({"request_timeout": True},),
    ],
)
def test_server_rejects_unbounded_or_invalid_configuration(options):
    with pytest.raises(ValueError):
        create_server(ErrorService(), **options)


def test_handler_cap_rejects_excess_and_recovers_after_normal_completion():
    entered = Event()
    release = Event()

    class BlockingService(ErrorService):
        def evaluate(self, *_args):
            with self.lock:
                self.calls += 1
            entered.set()
            assert release.wait(2)
            return CommercialServiceResponse(
                ServiceOutcome.ERROR, ServiceReason.EVALUATION_FAILURE
            )

    service = BlockingService()
    server, thread = start_server(
        service, max_concurrent_handlers=1, request_timeout=3
    )
    first = socket.create_connection(server.server_address, timeout=2)
    first.settimeout(2)
    try:
        first.sendall(wire_request())
        first.shutdown(socket.SHUT_WR)
        assert entered.wait(1)

        excess = exchange_wire(server, wire_request())
        assert response_status(excess) == 503
        assert b'"code":"service_unavailable"' in excess
        assert service.calls == 1

        release.set()
        first_response = bytearray()
        while True:
            chunk = first.recv(4096)
            if not chunk:
                break
            first_response.extend(chunk)
        assert response_status(bytes(first_response)) == 500

        deadline = time.monotonic() + 1
        while True:
            recovered = exchange_wire(server, wire_request())
            status = response_status(recovered)
            if status != 503:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status == 500
        assert service.calls == 2
    finally:
        release.set()
        first.close()
        stop_server(server, thread)


def test_handler_permit_recovers_after_client_disconnect():
    service = ErrorService()
    server, thread = start_server(
        service, max_concurrent_handlers=1, request_timeout=2
    )
    incomplete = socket.create_connection(server.server_address, timeout=2)
    try:
        incomplete.sendall(b"POST /v1/evaluations HTTP/1.1\r\nHost:")
        assert response_status(exchange_wire(server, wire_request())) == 503
        incomplete.close()

        deadline = time.monotonic() + 1
        while True:
            response = exchange_wire(server, wire_request())
            status = response_status(response)
            if status != 503:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status == 500
        assert service.calls == 1
    finally:
        incomplete.close()
        stop_server(server, thread)


def test_handler_permit_recovers_after_handler_exception(monkeypatch):
    service = ErrorService()
    server, thread = start_server(service, max_concurrent_handlers=1)
    original_finish_request = server.finish_request

    def fail_handler(*_args, **_kwargs):
        raise RuntimeError("injected handler failure")

    try:
        monkeypatch.setattr(server, "finish_request", fail_handler)
        assert exchange_wire(server, wire_request()) == b""
        monkeypatch.setattr(server, "finish_request", original_finish_request)

        deadline = time.monotonic() + 1
        while True:
            response = exchange_wire(server, wire_request())
            status = response_status(response)
            if status != 503:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status == 500
        assert service.calls == 1
    finally:
        stop_server(server, thread)


def test_incomplete_request_deadline_closes_without_evaluation():
    service = ErrorService()
    server, thread = start_server(service, request_timeout=0.2)
    connection = socket.create_connection(server.server_address, timeout=2)
    connection.settimeout(1)
    started = time.monotonic()
    try:
        connection.sendall(b"POST /v1/evaluations HTTP/1.1\r\nHost: localhost\r\n")
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        assert time.monotonic() - started < 1
        assert service.calls == 0
    finally:
        connection.close()
        stop_server(server, thread)


def test_trickled_header_data_cannot_extend_absolute_deadline():
    service = ErrorService()
    server, thread = start_server(service, request_timeout=0.35)
    connection = socket.create_connection(server.server_address, timeout=2)
    connection.settimeout(1.5)
    timers = []

    def send_late_chunk(chunk):
        try:
            connection.sendall(chunk)
        except OSError:
            pass

    try:
        connection.sendall(
            b"POST /v1/evaluations HTTP/1.1\r\nHost: localhost\r\nX-Partial: "
        )
        for delay, chunk in ((0.1, b"a"), (0.2, b"b"), (0.3, b"c")):
            timer = Timer(delay, send_late_chunk, (chunk,))
            timer.start()
            timers.append(timer)
        started = time.monotonic()
        while connection.recv(4096):
            pass
        assert time.monotonic() - started < 1
        assert service.calls == 0
    finally:
        connection.close()
        for timer in timers:
            timer.join()
        stop_server(server, thread)


def test_trickled_body_data_cannot_extend_absolute_deadline():
    service = ErrorService()
    server, thread = start_server(service, request_timeout=0.35)
    connection = socket.create_connection(server.server_address, timeout=2)
    connection.settimeout(1.5)
    timers = []

    def send_late_chunk(chunk):
        try:
            connection.sendall(chunk)
        except OSError:
            pass

    headers = (
        b"POST /v1/evaluations HTTP/1.1\r\nHost: localhost\r\n"
        b"Content-Type: application/json\r\nContent-Length: 10\r\n"
        b"Authorization: Bearer test\r\n\r\n"
    )
    try:
        connection.sendall(headers + b"0")
        for delay, chunk in ((0.1, b"1"), (0.2, b"2"), (0.3, b"3")):
            timer = Timer(delay, send_late_chunk, (chunk,))
            timer.start()
            timers.append(timer)
        started = time.monotonic()
        while connection.recv(4096):
            pass
        assert time.monotonic() - started < 1
        assert service.calls == 0
    finally:
        connection.close()
        for timer in timers:
            timer.join()
        stop_server(server, thread)


def test_incomplete_body_deadline_does_not_evaluate_or_hold_permit():
    service = ErrorService()
    server, thread = start_server(
        service, max_concurrent_handlers=1, request_timeout=0.2
    )
    connection = socket.create_connection(server.server_address, timeout=2)
    connection.settimeout(1)
    try:
        connection.sendall(
            b"POST /v1/evaluations HTTP/1.1\r\nHost: localhost\r\n"
            b"Content-Type: application/json\r\nContent-Length: 10\r\n"
            b"Authorization: Bearer test\r\n\r\n{"
        )
        while connection.recv(4096):
            pass
        assert service.calls == 0
        deadline = time.monotonic() + 1
        while True:
            status = response_status(exchange_wire(server, wire_request()))
            if status != 503:
                break
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert status == 500
        assert service.calls == 1
    finally:
        connection.close()
        stop_server(server, thread)


@pytest.mark.parametrize("expect_headers", [
    ("Expect: extension-token",),
    ("Expect: extension-a", "Expect: extension-b"),
    ("Expect: 100-continue",),
    ("Expect: 100-continue", "Expect: extension-token"),
])
def test_all_expect_headers_are_rejected_before_service(expect_headers):
    service = ErrorService()
    server, thread = start_server(service)
    try:
        response = exchange_wire(server, wire_request(*expect_headers))
        assert response_status(response) == 417
        assert service.calls == 0
    finally:
        stop_server(server, thread)


@pytest.mark.parametrize(
    ("extra_headers", "expected_status"),
    [
        (("Content-Length: 1",), 400),
        (("Content-Length: 999",), 400),
        (("Transfer-Encoding: chunked",), 400),
        (("Authorization: Bearer duplicate",), 401),
    ],
)
def test_ambiguous_framing_and_duplicate_auth_are_rejected(
    api, extra_headers, expected_status
):
    raw = wire_request(*extra_headers)
    response = exchange_wire(api["server"], raw)

    assert response_status(response) == expected_status
    assert api["evaluation_calls"] == [0]


def test_malformed_utf8_is_rejected_before_service(api):
    response = exchange_wire(
        api["server"],
        wire_request(body=b"\xff\xfe"),
    )

    assert response_status(response) == 400
    assert api["evaluation_calls"] == [0]
