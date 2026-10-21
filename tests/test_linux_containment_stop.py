from types import SimpleNamespace
import socket
import subprocess

import pytest

from gvai import linux_containment_stop as module
from gvai.linux_containment_stop import OwnedContainment


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No real process or network operations in stop tests.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(module.os, "kill", prohibited)
    monkeypatch.setattr(module.os, "killpg", prohibited)


@pytest.fixture
def syscalls(monkeypatch):
    calls = []
    monkeypatch.setattr(module.os, "dup", lambda fd: calls.append(("dup", fd)) or fd + 100)
    monkeypatch.setattr(module.os, "set_inheritable", lambda fd, flag: calls.append(("inherit", fd, flag)))
    monkeypatch.setattr(module.os, "close", lambda fd: calls.append(("close", fd)))
    monkeypatch.setattr(module.os, "write", lambda fd, data: calls.append(("write", fd, data)) or len(data))
    monkeypatch.setattr(module.os, "lseek", lambda fd, offset, whence: calls.append(("seek", fd, offset, whence)) or 0)
    monkeypatch.setattr(module.os, "read", lambda fd, size: calls.append(("read", fd, size)) or b"populated 0\nfrozen 0\n")
    monkeypatch.setattr(
        module.os, "waitid",
        lambda kind, fd, flags: calls.append(("wait", kind, fd, flags))
        or SimpleNamespace(si_pid=42, si_code=module.os.CLD_KILLED),
    )
    return calls


def owned():
    return OwnedContainment(kill_fd=10, events_fd=11, child_pidfds=(12, 13))


def test_only_retained_descriptors_are_used_and_reaping_is_cached(syscalls):
    handle = owned()
    assert syscalls[:4] == [("dup", 10), ("inherit", 110, False),
                            ("dup", 11), ("inherit", 111, False)]
    result = handle.stop()
    assert result.status == "terminated"
    assert result.kill_requested and result.empty and result.reaped
    assert ("write", 110, b"1") in syscalls
    assert ("read", 111, 4097) in syscalls
    waits = [call for call in syscalls if call[0] == "wait"]
    assert waits == [("wait", module.os.P_PIDFD, fd, module.os.WEXITED | module.os.WNOHANG)
                     for fd in (112, 113)]
    assert handle.stop().status == "terminated"
    assert [call for call in syscalls if call[0] == "wait"] == waits
    handle.close()
    handle.close()
    assert handle.stop().status == "uncertain"
    assert [call for call in syscalls if call[0] == "close"] == [
        ("close", fd) for fd in (110, 111, 112, 113)
    ]


@pytest.mark.parametrize("raw", [
    b"", b"frozen 0\n", b"populated 0\npopulated 0\n", b"populated 2\n",
    b"\xff", b"populated\n", b"populated 0 extra\n", b"x" * 4097,
])
def test_bad_population_evidence_never_means_terminated(syscalls, monkeypatch, raw):
    monkeypatch.setattr(module.os, "read", lambda *args: raw)
    result = owned().stop()
    assert result.status == "uncertain"
    assert result.reaped


@pytest.mark.parametrize("populated,reaped", [(True, True), (True, False), (False, False)])
def test_delayed_exit_or_reaping_is_pending(syscalls, monkeypatch, populated, reaped):
    monkeypatch.setattr(module.os, "read", lambda *args: b"populated 1\n" if populated else b"populated 0\n")
    if not reaped:
        monkeypatch.setattr(module.os, "waitid", lambda *args: None)
    assert owned().stop().status == "pending"


@pytest.mark.parametrize("operation", ["write", "read", "lseek", "waitid"])
def test_independent_failures_do_not_skip_other_cleanup(syscalls, monkeypatch, operation):
    def failed(*args):
        syscalls.append(("failed", operation))
        raise OSError("Unavailable kernel operation.")

    monkeypatch.setattr(module.os, operation, failed)
    result = owned().stop()
    assert result.status == "uncertain"
    if operation != "write":
        assert result.kill_requested
    if operation != "waitid":
        assert result.reaped
    assert ("failed", operation) in syscalls


def test_short_kill_write_cannot_report_termination(syscalls, monkeypatch):
    monkeypatch.setattr(module.os, "write", lambda *args: 0)
    assert owned().stop().status == "uncertain"


def test_echild_and_unexpected_wait_results_are_not_termination(syscalls, monkeypatch):
    def no_child(*args):
        raise ChildProcessError()

    monkeypatch.setattr(module.os, "waitid", no_child)
    assert owned().stop().status == "uncertain"
    monkeypatch.setattr(module.os, "waitid", lambda *args: SimpleNamespace(si_pid=42, si_code=999))
    assert owned().stop().status == "pending"


@pytest.mark.parametrize("kill,events,children", [
    (True, 11, (12,)), (-1, 11, (12,)), ("path", 11, (12,)),
    (10, 10, (12,)), (10, 11, (10,)), (10, 11, (12, 12)),
    (10, 11, []), (10, 11, ()), (10, 11, (True,)),
])
def test_untrusted_selectors_reject_before_syscalls(syscalls, kill, events, children):
    with pytest.raises(ValueError):
        OwnedContainment(kill_fd=kill, events_fd=events, child_pidfds=children)
    assert syscalls == []


def test_partial_construction_closes_retained_handles(syscalls, monkeypatch):
    def duplicate(fd):
        if fd == 12:
            raise OSError("dup failed")
        return fd + 100

    monkeypatch.setattr(module.os, "dup", duplicate)
    with pytest.raises(OSError):
        owned()
    assert ("close", 110) in syscalls and ("close", 111) in syscalls


def test_missing_pidfd_interface_never_falls_back(syscalls, monkeypatch):
    monkeypatch.delattr(module.os, "P_PIDFD")
    result = owned().stop()
    assert result.status == "uncertain"
    assert result.kill_requested and result.empty and not result.reaped
    assert not any(call[0] == "wait" for call in syscalls)
