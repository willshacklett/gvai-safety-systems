from dataclasses import replace
import json
import os
import socket
import subprocess
import threading
from uuid import uuid4

import pytest

from gvai.linux_containment_identity import ContainmentIdentity
from gvai.supervisor_stop import StopJournal
from gvai.systemd_worker_contract import (
    ManagerInventory, ManagerObservation, OutputFence, REQUIRED_RESTRICTIONS,
    ResourceLimits, SystemdWorkerContract, WorkerIdentity, WorkerSpec,
)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No real worker, manager, network, signal or reaping operations.")

    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)
    for name in ("kill", "killpg", "waitid", "system"):
        monkeypatch.setattr(os, name, prohibited)


def worker(boot, *, inode=10, uid=1001):
    return WorkerSpec(
        WorkerIdentity(uuid4(), boot, ContainmentIdentity(1, inode)),
        uid, uid, ResourceLimits(64 * 1024**2, 8, 50, 1024**2),
    )


class FakeManager:
    def __init__(self, boot):
        self.boot = boot
        self.workers = ()
        self.calls = []
        self.transform = lambda value: value
        self.inventory_transform = lambda value: value

    def inventory(self, session, request):
        return self.inventory_transform(
            ManagerInventory(session, request, self.boot, True, self.workers),
        )

    def cancel(self, spec, session, request):
        self.calls.append(spec)
        return self.transform(ManagerObservation(
            session, request, spec, spec.identity.service, REQUIRED_RESTRICTIONS,
            "trusted-manager", True, True, True, True,
        ))


@pytest.fixture
def setup(tmp_path):
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
    boot = uuid4()
    manager = FakeManager(boot)
    contract = SystemdWorkerContract(journal, manager, boot)
    yield contract, manager, journal, boot
    journal.close()


def denied(report):
    assert not report and report.allowed is False
    assert report.authenticated is False and report.state.stopped


def test_registration_and_duplicate_stop_never_admit(setup):
    contract, manager, _, boot = setup
    spec = worker(boot)
    for report in (contract.register(spec), contract.request_stop(), contract.register(spec)):
        denied(report)
        assert report.cleanup.status == "terminated"
        assert not report.reconciled
    assert manager.calls == [spec] * 3


def test_empty_without_inventory_is_not_success(setup):
    contract, _, _, _ = setup
    report = contract.request_stop()
    assert report.cleanup.status == "uncertain" and report.errors
    denied(report)
    report = contract.reconcile()
    assert report.reconciled and report.cleanup.status == "terminated"
    denied(report)


def test_reconcile_discovers_and_stops_prior_attempts(setup):
    contract, manager, _, boot = setup
    manager.workers = (worker(boot), worker(boot, inode=11, uid=1002))
    report = contract.reconcile()
    assert report.reconciled and manager.calls == list(manager.workers)
    denied(report)


@pytest.mark.parametrize("changes", [
    {"session": uuid4()}, {"request": uuid4()}, {"service": "ssh.service"},
    {"reaper": "supervisor-pidfd"}, {"kill_requested": False},
    {"empty": False}, {"descendants_reaped": False}, {"terminal": 1},
    {"empty": 1}, {"restrictions": frozenset()},
    {"restrictions": REQUIRED_RESTRICTIONS | {"unknown"}},
    {"restrictions": REQUIRED_RESTRICTIONS - {"private-pid"}},
    {"restrictions": REQUIRED_RESTRICTIONS - {"private-user"}},
])
def test_invalid_observations_fail_closed(setup, changes):
    contract, manager, _, boot = setup
    manager.transform = lambda value: replace(value, **changes)
    report = contract.register(worker(boot))
    assert report.cleanup.status == "uncertain" and report.errors
    assert not report.cleanup.reaped
    denied(report)


@pytest.mark.parametrize("response", [None, {}, True, "inactive"])
def test_unknown_manager_response(setup, response):
    contract, manager, _, boot = setup
    manager.transform = lambda value: response
    report = contract.register(worker(boot))
    assert report.cleanup.status == "uncertain"
    denied(report)


@pytest.mark.parametrize("restriction", sorted(REQUIRED_RESTRICTIONS))
def test_every_effective_restriction_is_mandatory(setup, restriction):
    contract, manager, _, boot = setup
    manager.transform = lambda value: replace(
        value, restrictions=REQUIRED_RESTRICTIONS - {restriction},
    )
    report = contract.register(worker(boot))
    assert report.errors and report.cleanup.status == "uncertain"
    denied(report)


def test_cached_observation_is_rejected_on_next_stop(setup):
    contract, manager, _, boot = setup
    captured = []
    def capture(value):
        captured.append(value)
        return value
    manager.transform = capture
    contract.register(worker(boot))
    manager.transform = lambda value: captured[0]
    report = contract.request_stop()
    assert report.errors and report.cleanup.status == "uncertain"
    denied(report)


def test_contradictory_nonterminal_reaping_is_rejected(setup):
    contract, manager, _, boot = setup
    manager.transform = lambda value: replace(value, terminal=False, empty=False)
    report = contract.register(worker(boot))
    assert report.cleanup.status == "uncertain" and report.errors


def test_wrong_attempt_or_resource_limits_rejected(setup):
    contract, manager, _, boot = setup
    other = worker(boot)
    manager.transform = lambda value: replace(value, spec=other)
    assert contract.register(worker(boot)).cleanup.status == "uncertain"
    manager.transform = lambda value: replace(
        value, spec=replace(value.spec, limits=ResourceLimits(1, 1, 1, 1)),
    )
    assert contract.request_stop().cleanup.status == "uncertain"


def test_incomplete_reaping_is_pending_not_success(setup):
    contract, manager, _, boot = setup
    manager.transform = lambda value: replace(value, terminal=False, descendants_reaped=False)
    report = contract.register(worker(boot))
    assert report.cleanup.status == "pending"
    assert not report.cleanup.reaped and not report.reconciled
    denied(report)


def test_manager_failure_does_not_skip_other_workers_or_journal(setup):
    contract, manager, _, boot = setup
    first = worker(boot)
    second = worker(boot, inode=11, uid=1002)
    contract.register(first)
    def failure(value):
        if value.spec == first:
            raise OSError("manager disconnected")
        return value
    manager.transform = failure
    report = contract.register(second)
    assert manager.calls[-2:] == [first, second]
    assert report.durable and report.cleanup.status == "uncertain"
    assert "manager disconnected" in report.errors[0]


def test_journal_failure_does_not_skip_cancellation(setup, monkeypatch):
    contract, manager, journal, boot = setup
    monkeypatch.setattr(journal, "latch", lambda: (_ for _ in ()).throw(OSError("disk")))
    report = contract.register(worker(boot))
    assert manager.calls and not report.durable
    assert report.cleanup.status == "uncertain" and report.errors


@pytest.mark.parametrize("changes", [
    {"complete": False}, {"complete": 1}, {"session": uuid4()},
    {"request": uuid4()}, {"boot": uuid4()}, {"workers": []},
])
def test_bad_inventory_never_reconciles(setup, changes):
    contract, manager, _, _ = setup
    manager.inventory_transform = lambda value: replace(value, **changes)
    report = contract.reconcile()
    assert not report.reconciled and report.errors


def test_omitted_known_attempt_and_duplicate_inventory_rejected(setup):
    contract, manager, _, boot = setup
    spec = worker(boot)
    contract.register(spec)
    assert not contract.reconcile().reconciled
    manager.workers = (spec, spec)
    assert not contract.reconcile().reconciled
    manager.workers = (spec,)
    assert contract.reconcile().reconciled


def test_inventory_failure_still_cancels_known_attempts(setup):
    contract, manager, _, boot = setup
    contract.register(worker(boot))
    manager.inventory_transform = lambda value: (_ for _ in ()).throw(OSError("inventory"))
    report = contract.reconcile()
    assert len(manager.calls) == 2 and report.errors and not report.reconciled


def test_restart_requires_inventory_and_rejects_old_output(setup):
    contract, manager, journal, boot = setup
    spec = worker(boot)
    contract.register(spec)
    fence = contract.output_fence(spec.identity)
    manager.workers = (spec,)
    assert contract.reconcile().reconciled
    restarted = SystemdWorkerContract(journal, manager, boot)
    assert not restarted.check_output(fence)
    assert not restarted.request_stop().reconciled
    assert restarted.reconcile().reconciled
    assert not restarted.check_output(fence)


def test_missing_journal_blocks_reconciliation(tmp_path):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        journal = StopJournal(fd)
    finally:
        os.close(fd)
    try:
        boot = uuid4()
        report = SystemdWorkerContract(journal, FakeManager(boot), boot).reconcile()
        assert report.state.uncertain and not report.reconciled and report.errors
        denied(report)
    finally:
        journal.close()


def test_attempt_cgroup_and_uid_cannot_be_rebound(setup):
    contract, _, _, boot = setup
    spec = worker(boot)
    contract.register(spec)
    for bad in (
        replace(spec, uid=1002), worker(boot),
        worker(boot, inode=11), worker(uuid4(), inode=11, uid=1002),
    ):
        with pytest.raises(ValueError):
            contract.register(bad)


@pytest.mark.parametrize("value", [True, 0, -1, "10", None])
def test_invalid_limits_and_identity(value):
    with pytest.raises(ValueError):
        ResourceLimits(value, 1, 1, 1)
    with pytest.raises(ValueError):
        WorkerSpec(WorkerIdentity(uuid4(), uuid4(), ContainmentIdentity(1, 1)),
                   value, 1001, ResourceLimits(1, 1, 1, 1))


def test_late_output_and_forged_fences_never_publish(setup):
    contract, _, _, boot = setup
    spec = worker(boot)
    contract.register(spec)
    fence = contract.output_fence(spec.identity)
    assert not contract.check_output(fence)
    contract.request_stop()
    for bad in (fence, None, {}, replace(fence, session=uuid4()),
                OutputFence(worker(boot).identity, fence.session, fence.revision)):
        result = contract.check_output(bad)
        assert result.allowed is False and "stale" in result.reason


def test_stop_registration_race_is_serialized_and_output_denied(setup):
    contract, manager, _, boot = setup
    spec = worker(boot)
    entered = threading.Event()
    release = threading.Event()
    reports = []
    errors = []
    def blocking(value):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test synchronization")
        return value
    manager.transform = blocking
    def run(operation):
        try:
            reports.append(operation())
        except BaseException as error:
            errors.append(error)
    registration = threading.Thread(target=run, args=(lambda: contract.register(spec),))
    stopping = threading.Thread(target=run, args=(contract.request_stop,))
    registration.start()
    try:
        assert entered.wait(5)
        stopping.start()
    finally:
        release.set()
        registration.join(5)
        if stopping.ident is not None:
            stopping.join(5)
    assert not registration.is_alive() and not stopping.is_alive() and not errors
    assert len(reports) == 2 and len(manager.calls) == 2
    for report in reports:
        denied(report)
    assert not contract.check_output(contract.output_fence(spec.identity))


def test_no_launch_admission_or_publication_api():
    public = {name for name in vars(SystemdWorkerContract) if not name.startswith("_")}
    assert public == {
        "register", "request_stop", "reconcile", "output_fence", "check_output",
    }
