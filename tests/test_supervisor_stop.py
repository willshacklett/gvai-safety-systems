import json
import os
from pathlib import Path
import socket
import subprocess
import threading

import pytest

from gvai import supervisor_stop as module
from gvai.linux_containment_stop import CleanupEvidence, OwnedContainment
from gvai.supervisor_stop import MAX_GENERATION, StopController, StopJournal


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No real process, cgroup or network operations in journal tests.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(os, "kill", prohibited)
    monkeypatch.setattr(os, "killpg", prohibited)
    monkeypatch.setattr(os, "waitid", prohibited)


def seed(directory, generation=7, uncertain=False):
    path = directory / "stop.json"
    path.write_text(json.dumps({
        "version": 1, "stopped": True, "generation": generation, "uncertain": uncertain,
    }), encoding="ascii")
    path.chmod(0o600)


def open_journal(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return StopJournal(fd)
    finally:
        os.close(fd)


def assert_denied(report):
    assert report.state.stopped
    assert report.allowed is False and report.authenticated is False
    assert not report


@pytest.fixture
def handle(monkeypatch):
    # No Linux handles are provisioned: only the controller's call boundary is tested.
    value = object.__new__(OwnedContainment)
    calls = []
    monkeypatch.setattr(OwnedContainment, "stop", lambda self: calls.append(self) or CleanupEvidence(
        "terminated", True, True, True,
    ))
    return value, calls


def test_real_journal_commit_and_reopen_are_restrictive(tmp_path):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    state, durable = journal.latch()
    assert state.stopped and state.generation == 7 and not state.uncertain and durable
    assert journal.latch() == (state, True)
    journal.close()
    journal.close()
    reopened = open_journal(tmp_path)
    assert reopened.latch() == (state, True)
    reopened.close()
    assert not (tmp_path / "stop.pending").exists()
    assert not (tmp_path / "stop.intent").exists()
    assert (tmp_path / "stop.json").stat().st_mode & 0o777 == 0o600


def test_missing_journal_never_initializes_a_reset_generation(tmp_path, handle):
    journal = open_journal(tmp_path)
    controller = StopController(journal)
    value, calls = handle
    report = controller.register(value)
    assert_denied(report)
    assert report.status == "uncertain" and report.durable
    assert report.state.generation is None
    assert calls == [value]
    assert json.loads((tmp_path / "stop.json").read_text())["generation"] is None
    journal.close()


@pytest.mark.parametrize("raw", [
    b"{}", b"null", b"[]", b"\xff", b"x" * 4097,
    b'{"version":1,"stopped":true,"generation":7,"generation":8,"uncertain":false}',
])
def test_corrupt_journal_preserved_and_never_authoritative(tmp_path, raw, handle):
    record = tmp_path / "stop.json"
    record.write_bytes(raw)
    record.chmod(0o600)
    journal = open_journal(tmp_path)
    value, calls = handle
    report = StopController(journal).register(value)
    assert_denied(report)
    assert report.status == "uncertain"
    assert record.read_bytes() == raw
    assert calls == [value]
    journal.close()


@pytest.mark.parametrize("generation", [None, True, -1, 2**63, "7"])
def test_invalid_or_unknown_generation_never_resets(tmp_path, generation):
    seed(tmp_path, generation)
    journal = open_journal(tmp_path)
    state, _ = journal.latch()
    assert state.stopped and state.uncertain and state.generation is None
    journal.close()


def test_terminal_generation_stays_terminal_across_restart(tmp_path, handle):
    seed(tmp_path, MAX_GENERATION)
    for _ in range(3):
        journal = open_journal(tmp_path)
        report = StopController(journal).register(handle[0])
        assert_denied(report)
        assert report.state.generation == MAX_GENERATION
        assert report.state.uncertain and report.status == "uncertain"
        journal.close()


@pytest.mark.parametrize("operation", ["write", "fsync", "replace"])
def test_persistence_failure_does_not_prevent_stop(tmp_path, monkeypatch, handle, operation):
    seed(tmp_path)
    journal = open_journal(tmp_path)

    def failure(*args, **kwargs):
        raise OSError("Storage fault.")

    with monkeypatch.context() as patch:
        patch.setattr(module.os, operation, failure)
        report = StopController(journal).register(handle[0])
    assert_denied(report)
    assert not report.durable and report.state.uncertain
    assert handle[1] == [handle[0]]
    assert report.cleanup.status == "terminated"
    assert report.status == "uncertain"
    journal.close()
    reopened = open_journal(tmp_path)
    state, durable = reopened.latch()
    assert state.uncertain and not durable
    reopened.close()


def test_directory_sync_failure_never_reports_durable_success(tmp_path, monkeypatch, handle):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    real_sync = module.os.fsync

    directory_syncs = 0

    def fail_directory(fd):
        nonlocal directory_syncs
        if fd == journal._dir:
            directory_syncs += 1
        if fd == journal._dir and directory_syncs == 2:
            raise OSError("Directory sync failed.")
        real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(module.os, "fsync", fail_directory)
        report = StopController(journal).register(handle[0])
    assert_denied(report)
    assert not report.durable and report.state.uncertain
    assert handle[1] == [handle[0]]
    journal.close()
    # The durable intent survives rename and its failed directory sync.
    assert (tmp_path / "stop.intent").exists()
    reopened = open_journal(tmp_path)
    report = StopController(reopened).request_stop()
    assert_denied(report)
    assert report.state.uncertain and not report.durable
    reopened.close()


def test_short_writes_are_completed_and_ordering_is_synced(tmp_path, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    original = module.os.write
    calls = []
    sync = module.os.fsync
    rename = module.os.replace

    def short_write(fd, raw):
        calls.append("write")
        return original(fd, raw[:3])

    def synced(fd):
        calls.append("directory_sync" if fd == journal._dir else "file_sync")
        sync(fd)

    def renamed(*args, **kwargs):
        calls.append("rename")
        rename(*args, **kwargs)

    monkeypatch.setattr(module.os, "write", short_write)
    monkeypatch.setattr(module.os, "fsync", synced)
    monkeypatch.setattr(module.os, "replace", renamed)
    assert journal.latch()[1]
    assert calls[-4:] == ["file_sync", "rename", "directory_sync", "directory_sync"]
    assert calls.count("write") > 1
    journal.close()


def test_exclusive_owner_symlinks_and_crash_left_intent(tmp_path):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    with pytest.raises(BlockingIOError):
        open_journal(tmp_path)
    journal.close()
    pending = tmp_path / "stop.pending"
    pending.write_bytes(b"partial")
    journal = open_journal(tmp_path)
    assert journal.latch()[0].uncertain
    journal.close()
    pending.unlink()
    record = tmp_path / "stop.json"
    record.unlink()
    record.symlink_to(tmp_path / "outside")
    journal = open_journal(tmp_path)
    assert journal.latch()[0].uncertain
    journal.close()
    assert not (tmp_path / "outside").exists()


def test_stop_before_and_after_registration_is_idempotent(tmp_path, handle):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    controller = StopController(journal)
    assert controller.request_stop().status == "uncertain"
    first = controller.register(handle[0])
    second = controller.register(handle[0])
    assert first == second and first.status == "terminated"
    assert_denied(first)
    assert handle[1] == [handle[0], handle[0]]
    journal.close()


@pytest.mark.parametrize("status", ["pending", "uncertain"])
def test_cleanup_failure_or_delay_never_reports_terminated(tmp_path, handle, monkeypatch, status):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    monkeypatch.setattr(OwnedContainment, "stop", lambda self: CleanupEvidence(status))
    report = StopController(journal).register(handle[0])
    assert report.status == status
    assert_denied(report)
    journal.close()


def test_one_failed_containment_cannot_prevent_other_stops(tmp_path, handle, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    controller = StopController(journal)
    first = handle[0]
    second = object.__new__(OwnedContainment)
    calls = []

    def stop(value):
        calls.append(value)
        if value is first:
            raise OSError("Kernel unavailable")
        return CleanupEvidence("terminated", True, True, True)

    monkeypatch.setattr(OwnedContainment, "stop", stop)
    controller.register(first)
    report = controller.register(second)
    assert calls == [first, first, second]
    assert report.status == "uncertain"
    assert_denied(report)
    journal.close()


def test_storage_is_not_touched_before_emergency_cleanup(tmp_path, handle, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    original = StopJournal.latch

    def latch(self):
        assert handle[1] == [handle[0]]
        return original(self)

    monkeypatch.setattr(StopJournal, "latch", latch)
    assert StopController(journal).register(handle[0]).status == "terminated"
    journal.close()


def test_stop_serializes_with_late_registration(tmp_path, handle, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    controller = StopController(journal)
    first = handle[0]
    second = object.__new__(OwnedContainment)
    entered = threading.Event()
    proceed = threading.Event()
    registered = threading.Event()
    calls = []
    reports = []

    def stop(value):
        calls.append(value)
        if not entered.is_set():
            entered.set()
            assert proceed.wait(5)
        return CleanupEvidence("terminated", True, True, True)

    monkeypatch.setattr(OwnedContainment, "stop", stop)

    def register(value, mark=False):
        reports.append(controller.register(value))
        if mark:
            registered.set()

    worker = threading.Thread(target=register, args=(first,))
    late = threading.Thread(target=register, args=(second, True))
    worker.start()
    try:
        assert entered.wait(5)
        late.start()
        assert not registered.is_set()
    finally:
        proceed.set()
        worker.join(5)
        if late.ident is not None:
            late.join(5)
    assert not worker.is_alive() and not late.is_alive()
    assert calls == [first, first, second]
    assert len(reports) == 2
    for report in reports:
        assert_denied(report)
    journal.close()


@pytest.mark.parametrize("point", ["intent_file", "intent_directory", "record_file", "record_directory"])
def test_each_commit_sync_cut_reopens_uncertain(tmp_path, monkeypatch, point):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    real_sync = os.fsync
    step = 0
    steps = ["intent_file", "intent_directory", "record_file", "record_directory"]

    def fault(fd):
        nonlocal step
        current = steps[step]
        step += 1
        if current == point:
            raise OSError("Crash cut at sync.")
        real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fault)
        assert not journal.latch()[1]
    journal.close()
    reopened = open_journal(tmp_path)
    assert reopened.read().uncertain
    assert not reopened.latch()[1]
    reopened.close()


def test_final_intent_deletion_sync_failure_has_already_durable_record(tmp_path, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    real_sync = os.fsync
    syncs = 0

    def fault(fd):
        nonlocal syncs
        syncs += 1
        if syncs == 5:
            raise OSError("Intent deletion durability is unknown.")
        real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fault)
        state, durable = journal.latch()
    assert durable and not state.uncertain
    journal.close()
    # Either absence (as here) or resurrection of intent is safe: data was synced.
    reopened = open_journal(tmp_path)
    assert reopened.read().stopped
    reopened.close()


def test_closed_journal_and_unsafe_permissions_fail_closed(tmp_path):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    journal.close()
    assert journal.read().uncertain
    assert journal.latch()[0].uncertain
    assert not journal.latch()[1]
    (tmp_path / "stop.json").chmod(0o644)
    reopened = open_journal(tmp_path)
    assert reopened.read().uncertain
    reopened.close()
    tmp_path.chmod(0o777)
    with pytest.raises(ValueError):
        open_journal(tmp_path)


def test_journal_close_failure_still_closes_all_handles_once(tmp_path, monkeypatch):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    lock_fd, directory_fd = journal._lock_fd, journal._dir
    real_close = os.close
    calls = []

    def close(fd):
        calls.append(fd)
        real_close(fd)
        if fd == lock_fd:
            raise OSError("Lock close failed after release.")

    monkeypatch.setattr(module.os, "close", close)
    with pytest.raises(OSError, match="Lock close failed"):
        journal.close()
    assert calls == [lock_fd, directory_fd]
    assert journal._lock_fd is None and journal._dir is None
    assert journal.read().uncertain
    journal.close()
    assert calls == [lock_fd, directory_fd]


def test_journal_constructor_rollback_closes_all_handles_and_preserves_error(
    tmp_path, monkeypatch,
):
    seed(tmp_path)
    caller_fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    real_close = os.close
    duplicated = []
    opened = []
    calls = []
    signal = OSError("Journal lock acquisition failed.")
    real_dup = os.dup
    real_open = os.open

    def duplicate(fd):
        result = real_dup(fd)
        duplicated.append(result)
        return result

    def open_file(path, flags, *args, **kwargs):
        result = real_open(path, flags, *args, **kwargs)
        opened.append(result)
        return result

    def close(fd):
        if fd in duplicated + opened:
            calls.append(fd)
            real_close(fd)
            if fd == opened[0]:
                raise OSError("Lock rollback close failed.")
            return
        real_close(fd)

    monkeypatch.setattr(module.os, "dup", duplicate)
    monkeypatch.setattr(module.os, "open", open_file)
    monkeypatch.setattr(module.os, "close", close)
    monkeypatch.setattr(module.fcntl, "flock", lambda *args: (_ for _ in ()).throw(signal))
    try:
        with pytest.raises(OSError, match="Journal lock acquisition failed") as error:
            StopJournal(caller_fd)
        assert error.value is signal
        assert error.value.__cause__ is not None
        assert str(error.value.__cause__) == "Lock rollback close failed."
        assert calls == [opened[0], duplicated[0]]
    finally:
        real_close(caller_fd)


def test_no_forward_or_recovery_api():
    for cls in (StopJournal, StopController, OwnedContainment):
        public = {name for name in vars(cls) if not name.startswith("_")}
        assert public <= {"close", "latch", "read", "register", "request_stop", "stop"}


@pytest.mark.parametrize("value", [None, True, 123, "/sys/fs/cgroup/arbitrary", {"terminated": True}])
def test_untrusted_target_or_ack_cannot_register(tmp_path, value):
    seed(tmp_path)
    journal = open_journal(tmp_path)
    with pytest.raises(ValueError):
        StopController(journal).register(value)
    journal.close()


def find_unapproved_containment_callers(root):
    modules = (
        "supervisor_stop",
        "linux_containment_stop",
        "linux_containment_identity",
        "systemd_worker_contract",
    )
    callers = set()
    for directory in (root / "gvai", root / "scripts"):
        for path in directory.rglob("*.py"):
            relative = path.relative_to(root).as_posix()
            for line in path.read_text(encoding="utf-8").splitlines():
                if not any(module_name in line for module_name in modules):
                    continue
                legitimate_import = (
                    relative in {
                        "gvai/supervisor_stop.py",
                        "gvai/linux_containment_identity.py",
                    }
                    and line.strip().startswith(
                        "from gvai.linux_containment_stop import "
                    )
                )
                legitimate_import = legitimate_import or (
                    relative == "gvai/systemd_worker_contract.py"
                    and line.strip() in {
                        "from gvai.linux_containment_identity import ContainmentIdentity",
                        "from gvai.linux_containment_stop import CleanupEvidence",
                        "from gvai.supervisor_stop import StopJournal, StopState",
                    }
                )
                legitimate_import = legitimate_import or (
                    relative == "gvai/systemd_observation_validator.py"
                    and line.strip() == "from gvai.systemd_worker_contract import ("
                )
                legitimate_import = legitimate_import or (
                    relative == "gvai/systemd_manager_boundary.py"
                    and line.strip() == "from gvai.systemd_worker_contract import ("
                )
                legitimate_import = legitimate_import or (
                    relative == "gvai/systemd_worker_profile.py"
                    and line.strip()
                    == "from gvai.systemd_worker_contract import WorkerSpec, _valid_worker_spec"
                )
                if not legitimate_import:
                    callers.add(relative)
    return sorted(callers)


def test_no_existing_runtime_or_publication_callers(tmp_path):
    root = Path(__file__).resolve().parents[1]
    assert find_unapproved_containment_callers(root) == []

    synthetic_root = tmp_path / "source"
    synthetic_gvai = synthetic_root / "gvai"
    synthetic_gvai.mkdir(parents=True)
    (synthetic_gvai / "supervisor_stop.py").write_text(
        "from gvai.linux_containment_stop import OwnedContainment\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "linux_containment_stop.py").write_text(
        "class OwnedContainment: pass\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "linux_containment_identity.py").write_text(
        "from gvai.linux_containment_stop import OwnedContainment\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "runtime_publication.py").write_text(
        "from gvai.supervisor_stop import StopController\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "systemd_worker_contract.py").write_text(
        "from gvai.linux_containment_identity import ContainmentIdentity\n"
        "from gvai.supervisor_stop import StopJournal, StopState\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "runtime_worker.py").write_text(
        "from gvai.systemd_worker_contract import SystemdWorkerContract\n",
        encoding="utf-8",
    )
    (synthetic_gvai / "systemd_manager_boundary.py").write_text(
        "from gvai.systemd_worker_contract import (\n",
        encoding="utf-8",
    )
    assert find_unapproved_containment_callers(synthetic_root) == [
        "gvai/runtime_publication.py",
        "gvai/runtime_worker.py",
    ]
