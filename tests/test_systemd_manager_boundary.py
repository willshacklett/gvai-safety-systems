from dataclasses import replace
import json
import os
import threading
from uuid import uuid4

import pytest

from gvai.linux_containment_identity import ContainmentIdentity
from gvai.systemd_manager_boundary import (
    MAX_MANAGER_REQUEST_BYTES,
    MAX_MANAGER_RESPONSE_BYTES,
    MAX_TRACKED_REQUESTS,
    MANAGER_REQUEST_TIMEOUT_SECONDS,
    MAX_INVENTORY_WORKERS,
    ManagerBoundaryError,
    ManagerRequest,
    ManagerTransportReply,
    SystemdManagerBoundary,
    WORKER_SERVICE_PREFIX,
)
from gvai.supervisor_stop import StopJournal
from gvai.systemd_worker_contract import (
    ManagerInventory,
    ManagerObservation,
    REQUIRED_RESTRICTIONS,
    ResourceLimits,
    SystemdWorkerContract,
    WorkerIdentity,
    WorkerSpec,
)


def worker(boot, *, inode=10, uid=1001):
    return WorkerSpec(
        WorkerIdentity(uuid4(), boot, ContainmentIdentity(1, inode)),
        uid, uid, ResourceLimits(64 * 1024**2, 8, 50, 1024**2),
    )


class FakeTransport:
    def __init__(self):
        self.requests = []
        self.response = None
        self.peer_evidence = object()
        self.error = None
        self.timeout = None
        self.max_request_bytes = None
        self.max_response_bytes = None

    def exchange(
        self, request, timeout_seconds, max_request_bytes, max_response_bytes,
    ):
        self.requests.append(request)
        self.timeout = timeout_seconds
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        if self.error:
            raise self.error
        response = self.response(request) if callable(self.response) else self.response
        return ManagerTransportReply(response, self.peer_evidence)


class FakeAuthenticator:
    def __init__(self):
        self.accept = True
        self.calls = []

    def verify(self, request, response, peer_evidence):
        self.calls.append((request, response, peer_evidence))
        return self.accept


@pytest.fixture
def setup():
    boot, session, request = uuid4(), uuid4(), uuid4()
    spec = worker(boot)
    transport = FakeTransport()
    authenticator = FakeAuthenticator()
    boundary = SystemdManagerBoundary(boot, transport, authenticator)
    return boundary, transport, authenticator, boot, session, request, spec


def observation(worker_spec, expected_session, expected_request, **changes):
    result = ManagerObservation(
        expected_session, expected_request, worker_spec, worker_spec.identity.service,
        REQUIRED_RESTRICTIONS,
        "trusted-manager", True, True, True, True,
    )
    return replace(result, **changes)


def test_cancel_uses_fixed_identity_and_explicit_correlation(setup):
    boundary, transport, authenticator, _, session, request, spec = setup
    expected = observation(spec, session, request)
    transport.response = expected

    assert boundary.cancel(spec, session, request) is expected
    envelope = transport.requests[0]
    assert envelope == ManagerRequest(
        "cancel", spec.identity.boot, session, request,
        spec.identity.service, spec,
    )
    assert envelope.service_scope == f"gvai-worker-{spec.identity.attempt.hex}.service"
    assert transport.timeout == MANAGER_REQUEST_TIMEOUT_SECONDS
    assert transport.max_request_bytes == MAX_MANAGER_REQUEST_BYTES
    assert transport.max_response_bytes == MAX_MANAGER_RESPONSE_BYTES
    assert authenticator.calls == [(envelope, expected, transport.peer_evidence)]


def test_inventory_is_bounded_and_uses_fixed_service_namespace(setup):
    boundary, transport, authenticator, boot, session, request, spec = setup
    expected = ManagerInventory(session, request, boot, True, (spec,))
    transport.response = expected

    assert boundary.inventory(session, request) is expected
    envelope = transport.requests[0]
    assert envelope.operation == "inventory"
    assert envelope.service_scope == WORKER_SERVICE_PREFIX and envelope.spec is None
    assert authenticator.calls[0][0] == envelope


@pytest.mark.parametrize("auth_result", [False, 1, None])
def test_authentication_is_mandatory_and_not_a_reply_field(setup, auth_result):
    boundary, transport, authenticator, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    authenticator.accept = auth_result

    with pytest.raises(ManagerBoundaryError, match="authentication"):
        boundary.cancel(spec, session, request)

    assert len(authenticator.calls) == 1
    assert not hasattr(transport.response, "authenticated")


def test_missing_external_peer_evidence_is_rejected(setup):
    boundary, transport, _, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    transport.peer_evidence = None

    with pytest.raises(ManagerBoundaryError, match="peer evidence"):
        boundary.cancel(spec, session, request)


def test_timeout_and_disconnect_fail_closed(setup):
    boundary, transport, _, _, session, request, spec = setup
    for error, message, request_id in (
        (TimeoutError("expired"), "timed out", request),
        (ConnectionError("closed"), "disconnected", uuid4()),
    ):
        transport.error = error
        with pytest.raises(ManagerBoundaryError, match=message):
            boundary.cancel(spec, session, request_id)


@pytest.mark.parametrize("response", [None, {}, True, "inactive"])
def test_malformed_responses_are_rejected(setup, response):
    boundary, transport, _, _, session, request, spec = setup
    transport.response = response

    with pytest.raises(ManagerBoundaryError):
        boundary.cancel(spec, session, request)


@pytest.mark.parametrize("field", ["session", "request"])
def test_replayed_or_stale_response_is_rejected(setup, field):
    boundary, transport, _, _, session, request, spec = setup
    old = uuid4()
    transport.response = observation(spec, session, request, **{field: old})

    with pytest.raises(ManagerBoundaryError, match="correlation"):
        boundary.cancel(spec, session, request)


def test_duplicate_request_id_is_rejected_before_transport_and_authentication(setup):
    boundary, transport, authenticator, _, session, request, spec = setup
    cached = observation(spec, session, request)
    transport.response = cached

    assert boundary.cancel(spec, session, request) is cached
    calls_after_first = len(authenticator.calls)
    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.cancel(spec, session, request)

    assert len(transport.requests) == 1
    assert len(authenticator.calls) == calls_after_first


def test_request_id_cannot_be_reused_for_another_operation_in_same_session(setup):
    boundary, transport, _, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    assert boundary.cancel(spec, session, request)

    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.inventory(session, request)

    assert len(transport.requests) == 1


def test_authentication_failure_consumes_request_id(setup):
    boundary, transport, authenticator, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    authenticator.accept = False

    with pytest.raises(ManagerBoundaryError, match="authentication"):
        boundary.cancel(spec, session, request)

    authenticator.accept = True
    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.cancel(spec, session, request)
    assert len(transport.requests) == 1


def test_timed_out_request_id_remains_consumed_against_late_cached_reply(setup):
    boundary, transport, _, _, session, request, spec = setup
    transport.error = TimeoutError("late response may still arrive")

    with pytest.raises(ManagerBoundaryError, match="timed out"):
        boundary.cancel(spec, session, request)

    transport.error = None
    transport.response = observation(spec, session, request)
    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.cancel(spec, session, request)
    assert len(transport.requests) == 1


def test_duplicate_request_is_rejected_while_first_dispatch_is_outstanding(setup):
    boundary, transport, _, _, session, request, spec = setup
    entered = threading.Event()
    release = threading.Event()
    calls = []
    errors = []

    def block_exchange(*args, **kwargs):
        transport.requests.append((args, kwargs))
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test synchronization")
        return ManagerTransportReply(
            observation(spec, session, request), transport.peer_evidence,
        )

    transport.exchange = block_exchange

    def invoke():
        try:
            calls.append(boundary.cancel(spec, session, request))
        except BaseException as error:
            errors.append(error)

    first = threading.Thread(target=invoke)
    first.start()
    try:
        assert entered.wait(5)
        with pytest.raises(ManagerBoundaryError, match="already consumed"):
            boundary.cancel(spec, session, request)
    finally:
        release.set()
        first.join(5)

    assert not first.is_alive()
    assert len(transport.requests) == 1
    assert len(calls) == 1 and not errors


def test_request_id_cannot_be_reused_across_sessions(setup):
    boundary, transport, _, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    assert boundary.cancel(spec, session, request)

    other_session = uuid4()
    transport.response = observation(spec, other_session, request)
    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.cancel(spec, other_session, request)
    assert len(transport.requests) == 1


def test_delayed_response_for_timed_out_id_is_rejected_on_new_request(setup):
    boundary, transport, authenticator, _, session, request, spec = setup
    transport.error = TimeoutError("old request timed out")
    with pytest.raises(ManagerBoundaryError, match="timed out"):
        boundary.cancel(spec, session, request)

    new_request = uuid4()
    transport.error = None
    transport.response = observation(spec, session, request)
    auth_calls_before = len(authenticator.calls)
    with pytest.raises(ManagerBoundaryError, match="correlation"):
        boundary.cancel(spec, session, new_request)

    assert len(transport.requests) == 2
    assert len(authenticator.calls) == auth_calls_before + 1


def test_tracking_capacity_fails_closed_without_eviction_or_id_reuse(setup, monkeypatch):
    monkeypatch.setattr(
        "gvai.systemd_manager_boundary.MAX_TRACKED_REQUESTS", 1,
    )
    boundary, transport, _, _, session, request, spec = setup
    transport.response = observation(spec, session, request)
    assert boundary.cancel(spec, session, request)

    with pytest.raises(ManagerBoundaryError, match="capacity exhausted"):
        boundary.cancel(spec, session, uuid4())
    with pytest.raises(ManagerBoundaryError, match="already consumed"):
        boundary.cancel(spec, session, request)
    assert len(transport.requests) == 1


@pytest.mark.parametrize("changes", [
    {"service": "ssh.service"},
    {"spec": None},
    {"restrictions": frozenset()},
    {"kill_requested": False},
    {"terminal": True, "descendants_reaped": False},
    {"terminal": True, "empty": False},
])
def test_contradictory_or_unsafe_observations_are_rejected(setup, changes):
    boundary, transport, _, _, session, request, spec = setup
    transport.response = observation(spec, session, request, **changes)

    with pytest.raises(ManagerBoundaryError):
        boundary.cancel(spec, session, request)


def test_incomplete_cleanup_is_valid_pending_evidence_not_termination(setup):
    boundary, transport, _, _, session, request, spec = setup
    pending = observation(
        spec, session, request, empty=False,
        descendants_reaped=False, terminal=False,
    )
    transport.response = pending

    assert boundary.cancel(spec, session, request) is pending


def test_incomplete_cleanup_through_contract_never_proves_termination(setup, tmp_path):
    _, transport, authenticator, boot, _, _, spec = setup
    record = tmp_path / "stop.json"
    record.write_text(json.dumps({
        "version": 1, "stopped": True, "generation": 7, "uncertain": False,
    }))
    record.chmod(0o600)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        journal = StopJournal(fd)
    finally:
        os.close(fd)

    transport.response = lambda request: observation(
        spec, request.session, request.request,
        empty=False, descendants_reaped=False, terminal=False,
    )
    manager = SystemdManagerBoundary(boot, transport, authenticator)
    try:
        report = SystemdWorkerContract(journal, manager, boot).register(spec)
        assert report.cleanup.status == "pending"
        assert not report.cleanup.reaped and not report.reconciled
        assert report.authenticated is False and report.allowed is False
    finally:
        journal.close()


def test_cancel_rejects_wrong_boot_and_arbitrary_service_identity(setup):
    boundary, transport, _, _, session, request, spec = setup
    wrong_boot = replace(
        spec, identity=replace(spec.identity, boot=uuid4()),
    )
    with pytest.raises(ManagerBoundaryError):
        boundary.cancel(wrong_boot, session, request)

    with pytest.raises(ValueError, match="fixed worker identity"):
        ManagerRequest(
            "cancel", spec.identity.boot, session, request, "ssh.service", spec,
        )
    assert not transport.requests


def test_cancel_rejects_unbounded_resource_integer(setup):
    boundary, transport, _, _, session, request, spec = setup
    unbounded = replace(
        spec, limits=replace(spec.limits, memory_bytes=1 << 65),
    )

    with pytest.raises(ManagerBoundaryError, match="specification"):
        boundary.cancel(unbounded, session, request)
    assert not transport.requests


def test_incomplete_oversized_and_duplicate_inventory_fail_closed(setup):
    boundary, transport, _, boot, session, request, spec = setup
    invalid = (
        ManagerInventory(session, request, boot, False, ()),
        ManagerInventory(
            session, request, boot, True,
            tuple(worker(boot, inode=index + 10, uid=1001 + index)
                  for index in range(MAX_INVENTORY_WORKERS + 1)),
        ),
        ManagerInventory(session, request, boot, True, (spec, spec)),
    )
    for response in invalid:
        transport.response = response
        with pytest.raises(ManagerBoundaryError):
            boundary.inventory(session, request)


def test_inventory_rejects_wrong_boot_and_shared_containment(setup):
    boundary, transport, _, boot, session, request, spec = setup
    transport.response = ManagerInventory(
        session, request, boot, True, (replace(
            spec, identity=replace(spec.identity, boot=uuid4()),
        ),),
    )
    with pytest.raises(ManagerBoundaryError):
        boundary.inventory(session, request)

    shared_cgroup = worker(boot, inode=spec.identity.cgroup.inode, uid=1002)
    transport.response = ManagerInventory(
        session, request, boot, True, (spec, shared_cgroup),
    )
    with pytest.raises(ManagerBoundaryError):
        boundary.inventory(session, request)
