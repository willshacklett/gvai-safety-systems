import ctypes
import errno
import fcntl
import os
from pathlib import Path
import socket
import stat
import subprocess
import threading
from types import SimpleNamespace

import pytest

from gvai import linux_containment_identity as module
from gvai.linux_containment_identity import (
    ContainmentIdentity, ContainmentIdentityRejected, ValidatedContainmentDescriptors,
)


EXPECTED = ContainmentIdentity(50, 100)
_REAL_FILESYSTEM_TYPE = module._filesystem_type


def metadata(inode, *, directory=False, device=50, uid=1000, mode=None, links=1):
    return SimpleNamespace(
        st_dev=device, st_ino=inode, st_uid=uid, st_nlink=links,
        st_mode=mode if mode is not None else (stat.S_IFDIR | 0o700 if directory else stat.S_IFREG | 0o600),
    )


@pytest.fixture(autouse=True)
def no_workloads(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No real kernel, filesystem, network or worker operations.")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    for name in ("kill", "killpg", "waitid", "waitpid", "write", "read"):
        monkeypatch.setattr(os, name, prohibited)
    monkeypatch.setattr(module.ctypes, "CDLL", prohibited)


@pytest.fixture
def kernel(monkeypatch):
    state = {
        "objects": {
            10: (metadata(100, directory=True), os.O_RDONLY),
            11: (metadata(101), os.O_WRONLY),
            12: (metadata(102), os.O_RDONLY),
        },
        "types": {}, "calls": [], "next": 1000,
    }

    def filesystem(fd):
        assert fd in state["objects"]
        state["calls"].append(("filesystem", fd))
        return state["types"].get(fd, module._CGROUP2_SUPER_MAGIC)

    def control(fd, operation, *args):
        state["calls"].append(("fcntl", fd, operation, *args))
        assert fd in state["objects"]
        if operation == fcntl.F_DUPFD_CLOEXEC:
            assert args == (0,)
            state["next"] += 1
            duplicate = state["next"]
            state["objects"][duplicate] = state["objects"][fd]
            state["types"][duplicate] = state["types"].get(fd, module._CGROUP2_SUPER_MAGIC)
            return duplicate
        assert operation == fcntl.F_GETFL and not args
        return state["objects"][fd][1]

    def opened(name, flags, *, dir_fd):
        state["calls"].append(("open", name, flags, dir_fd))
        assert dir_fd == 1001
        assert name in ("cgroup.kill", "cgroup.events")
        access = os.O_WRONLY if name == "cgroup.kill" else os.O_RDONLY
        assert flags == access | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        state["next"] += 1
        reference = state["next"]
        index = 101 if name == "cgroup.kill" else 102
        state["objects"][reference] = (metadata(index), access)
        return reference

    def closed(fd):
        state["calls"].append(("close", fd))
        assert fd in state["objects"]
        del state["objects"][fd]

    monkeypatch.setattr(module, "_filesystem_type", filesystem)
    monkeypatch.setattr(module.fcntl, "fcntl", control)
    monkeypatch.setattr(module.os, "fstat", lambda fd: state["objects"][fd][0])
    monkeypatch.setattr(module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(module.os, "open", opened)
    monkeypatch.setattr(module.os, "close", closed)
    return state


def validate(**changes):
    arguments = dict(directory_fd=10, kill_fd=11, events_fd=12, expected=EXPECTED)
    arguments.update(changes)
    return ValidatedContainmentDescriptors(**arguments)


def retained(kernel):
    return set(kernel["objects"]) - {10, 11, 12}


def test_matching_cgroup_files_retained_and_references_closed(kernel):
    value = validate()
    assert value.identity == EXPECTED
    assert retained(kernel) == {1001, 1002, 1003}
    assert [(call[1], call[-1]) for call in kernel["calls"] if call[0] == "open"] == [
        ("cgroup.kill", 1001), ("cgroup.events", 1001),
    ]
    duplicates = [call for call in kernel["calls"] if call[0] == "fcntl" and call[2] == fcntl.F_DUPFD_CLOEXEC]
    assert [call[1] for call in duplicates] == [10, 11, 12]
    value.close()
    value.close()
    assert not retained(kernel)
    assert set(kernel["objects"]) == {10, 11, 12}
    with pytest.raises(ContainmentIdentityRejected):
        _ = value.identity


def test_original_close_and_numeric_reuse_cannot_retarget_validation(kernel):
    value = validate()
    for fd in (10, 11, 12):
        os.close(fd)
        kernel["objects"][fd] = (metadata(999, device=99), os.O_RDWR)
    assert value.identity == EXPECTED
    assert kernel["objects"][1002][0].st_ino == 101
    assert kernel["objects"][1003][0].st_ino == 102
    value.close()
    assert all(kernel["objects"][fd][0].st_ino == 999 for fd in (10, 11, 12))


def test_checks_use_retained_handles_even_if_originals_reused_after_duplication(kernel, monkeypatch):
    real_duplicate = module._duplicate

    def reuse_after_duplicate(fd):
        duplicate = real_duplicate(fd)
        kernel["objects"][fd] = metadata(999, device=99), os.O_RDWR
        return duplicate

    monkeypatch.setattr(module, "_duplicate", reuse_after_duplicate)
    value = validate()
    assert value.identity == EXPECTED
    value.close()
    assert set(kernel["objects"]) == {10, 11, 12}


@pytest.mark.parametrize("changes", [
    {"directory_fd": True}, {"kill_fd": -1}, {"events_fd": "/sys/fs/cgroup/foo"},
    {"kill_fd": 10}, {"events_fd": 11}, {"expected": None},
    {"expected": ContainmentIdentity(True, 100)}, {"expected": ContainmentIdentity(50, 0)},
])
def test_invalid_selectors_rejected_before_any_syscall(kernel, changes):
    with pytest.raises(ContainmentIdentityRejected):
        validate(**changes)
    assert kernel["calls"] == []


@pytest.mark.parametrize("expected", [ContainmentIdentity(99, 100), ContainmentIdentity(50, 999)])
def test_expected_directory_identity_required(kernel, expected):
    with pytest.raises(ContainmentIdentityRejected):
        validate(expected=expected)
    assert not retained(kernel)


@pytest.mark.parametrize("fd", [10, 11, 12])
@pytest.mark.parametrize("magic", [0x01021994, 0x27E0EB, 0])
def test_other_filesystems_including_cgroup_v1_rejected(kernel, fd, magic):
    kernel["types"][fd] = magic
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)


@pytest.mark.parametrize("fd,changed", [
    (10, metadata(100)), (11, metadata(101, mode=stat.S_IFIFO | 0o600)),
    (12, metadata(102, mode=stat.S_IFLNK | 0o600)),
    (11, metadata(101, uid=2000)), (10, metadata(100, directory=True, mode=stat.S_IFDIR | 0o777)),
    (12, metadata(102, mode=stat.S_IFREG | 0o666)), (11, metadata(101, links=0)),
    (11, metadata(101, device=99)), (12, metadata(101)), (12, metadata(999)),
])
def test_unsafe_or_substituted_handles_rejected(kernel, fd, changed):
    kernel["objects"][fd] = changed, kernel["objects"][fd][1]
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)


@pytest.mark.parametrize("fd,flags", [
    (10, os.O_PATH), (11, os.O_PATH | os.O_WRONLY), (12, os.O_PATH),
    (11, os.O_RDONLY), (12, os.O_WRONLY),
])
def test_access_mode_and_path_only_handles_rejected(kernel, fd, flags):
    kernel["objects"][fd] = kernel["objects"][fd][0], flags
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)


@pytest.mark.parametrize("operation", ["duplicate", "fstat", "filesystem", "access", "open"])
def test_unavailable_checks_fail_closed_and_close_partial_resources(kernel, monkeypatch, operation):
    def failed(*args, **kwargs):
        raise OSError(errno.ENOSYS, "Synthetic unsupported check.")

    if operation == "duplicate":
        real = module._duplicate
        monkeypatch.setattr(module, "_duplicate", lambda fd: failed() if fd == 12 else real(fd))
    elif operation == "fstat":
        monkeypatch.setattr(module.os, "fstat", failed)
    elif operation == "filesystem":
        monkeypatch.setattr(module, "_filesystem_type", failed)
    elif operation == "access":
        real = module.fcntl.fcntl
        monkeypatch.setattr(module.fcntl, "fcntl",
                            lambda fd, op, *args: failed() if op == fcntl.F_GETFL else real(fd, op, *args))
    else:
        monkeypatch.setattr(module.os, "open", failed)
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)
    assert set(kernel["objects"]) == {10, 11, 12}


@pytest.mark.parametrize("interruption", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("point", ["duplicate", "metadata", "reference"])
def test_interrupted_construction_releases_handles_and_preserves_cancellation(
    kernel, monkeypatch, interruption, point,
):
    signal = interruption("Synthetic interruption.")

    def interrupted(*args, **kwargs):
        raise signal

    if point == "duplicate":
        real_duplicate = module._duplicate
        monkeypatch.setattr(module, "_duplicate",
                            lambda fd: interrupted() if fd == 12 else real_duplicate(fd))
    elif point == "metadata":
        monkeypatch.setattr(os, "fstat", interrupted)
    else:
        real_metadata = module._metadata
        monkeypatch.setattr(module, "_metadata",
                            lambda fd, **kwargs: interrupted() if fd == 1004 else real_metadata(fd, **kwargs))
    with pytest.raises(interruption) as error:
        validate()
    assert error.value is signal
    assert not retained(kernel)


@pytest.mark.parametrize("reference_fault", ["inode", "device", "filesystem", "owner", "access"])
def test_reference_lookup_must_match_supplied_handle(kernel, monkeypatch, reference_fault):
    real_open = os.open

    def altered(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        if reference_fault == "filesystem":
            kernel["types"][fd] = 0
        else:
            meta, access = kernel["objects"][fd]
            if reference_fault == "inode":
                meta = metadata(999)
            elif reference_fault == "device":
                meta = metadata(meta.st_ino, device=99)
            elif reference_fault == "owner":
                meta = metadata(meta.st_ino, uid=2000)
            else:
                access = os.O_PATH
            kernel["objects"][fd] = meta, access
        return fd

    monkeypatch.setattr(os, "open", altered)
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)


def test_second_reference_failure_closes_first_reference_and_all_duplicates(kernel, monkeypatch):
    real_open = os.open

    def missing_events(name, *args, **kwargs):
        if name == "cgroup.events":
            raise FileNotFoundError("Synthetic missing interface.")
        return real_open(name, *args, **kwargs)

    monkeypatch.setattr(os, "open", missing_events)
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)
    assert ("close", 1004) in kernel["calls"]


def test_read_write_control_descriptors_are_accepted(kernel):
    for fd in (11, 12):
        kernel["objects"][fd] = kernel["objects"][fd][0], os.O_RDWR
    value = validate()
    assert value.identity == EXPECTED
    value.close()


def test_close_errors_do_not_skip_other_handles_or_retry_reused_numbers(kernel, monkeypatch):
    value = validate()
    real_close = os.close
    calls = []

    def interrupted(fd):
        calls.append(fd)
        real_close(fd)
        if fd == 1001:
            kernel["objects"][fd] = metadata(999), os.O_RDONLY
            raise OSError(errno.EINTR, "Ambiguous close.")

    monkeypatch.setattr(os, "close", interrupted)
    with pytest.raises(OSError, match="Ambiguous close"):
        value.close()
    value.close()
    assert calls == [1001, 1002, 1003]
    assert kernel["objects"][1001][0].st_ino == 999


def test_constructor_rollback_attempts_all_closes_and_preserves_validation_failure(
    kernel, monkeypatch,
):
    signal = OSError("Synthetic metadata failure.")

    def failed_fstat(fd):
        raise signal

    monkeypatch.setattr(module.os, "fstat", failed_fstat)
    original_close = module.os.close
    calls = []

    def close(fd):
        calls.append(fd)
        original_close(fd)
        if fd == 1001:
            raise OSError("First rollback close failed.")

    monkeypatch.setattr(module.os, "close", close)
    with pytest.raises(ContainmentIdentityRejected, match="Closing retained descriptors") as error:
        validate()
    assert error.value.__cause__ is signal
    assert calls == [1001, 1002, 1003]
    assert not retained(kernel)


@pytest.mark.parametrize("system,machine", [("darwin", "x86_64"), ("linux", "i686"), ("linux", "unknown")])
def test_unsupported_statfs_abi_rejects_without_loading_libc(monkeypatch, system, machine):
    monkeypatch.setattr(module.sys, "platform", system)
    monkeypatch.setattr(module.platform, "machine", lambda: machine)
    with pytest.raises(ContainmentIdentityRejected):
        module._filesystem_type(123)


@pytest.mark.parametrize("failed", [False, True])
def test_statfs_ctypes_boundary_without_real_syscall(monkeypatch, failed):
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    calls = []

    class FakeStatFS:
        def __call__(self, fd, pointer):
            calls.append(fd)
            if failed:
                ctypes.set_errno(errno.EBADF)
                return -1
            ctypes.cast(pointer, ctypes.POINTER(module._LinuxStatFS64)).contents.f_type = module._CGROUP2_SUPER_MAGIC
            return 0

    call = FakeStatFS()
    monkeypatch.setattr(module.ctypes, "CDLL", lambda name, **kwargs: SimpleNamespace(fstatfs=call))
    if failed:
        with pytest.raises(OSError) as error:
            module._filesystem_type(123)
        assert error.value.errno == errno.EBADF
    else:
        assert module._filesystem_type(123) == module._CGROUP2_SUPER_MAGIC
    assert calls == [123]
    assert call.argtypes == [ctypes.c_int, ctypes.POINTER(module._LinuxStatFS64)]
    assert call.restype is ctypes.c_int


def test_unsupported_pointer_width_rejects_before_libc(monkeypatch):
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    real_sizeof = ctypes.sizeof
    monkeypatch.setattr(module.ctypes, "sizeof",
                        lambda kind: 4 if kind is ctypes.c_void_p else real_sizeof(kind))
    with pytest.raises(ContainmentIdentityRejected):
        module._filesystem_type(123)


@pytest.mark.parametrize("missing", ["library", "symbol"])
def test_libc_unavailability_cannot_produce_a_validated_object(kernel, monkeypatch, missing):
    # Restore only the Python filesystem binding: all actual libc loading is fake.
    def unavailable(*args, **kwargs):
        if missing == "library":
            raise OSError("Synthetic loader failure.")
        return SimpleNamespace()

    monkeypatch.setattr(module, "_filesystem_type", _REAL_FILESYSTEM_TYPE)
    monkeypatch.setattr(module.sys, "platform", "linux")
    monkeypatch.setattr(module.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(module.ctypes, "CDLL", unavailable)
    with pytest.raises(ContainmentIdentityRejected):
        validate()
    assert not retained(kernel)


def test_no_operational_api_or_existing_callers():
    public = {name for name in vars(ValidatedContainmentDescriptors) if not name.startswith("_")}
    assert public == {"identity", "close", "bind_stop"}
    root = Path(__file__).resolve().parents[1]
    for directory in (root / "gvai", root / "scripts"):
        for path in directory.rglob("*.py"):
            if path.name != "linux_containment_identity.py":
                source = path.read_text(encoding="utf-8")
                if path.name == "systemd_worker_contract.py":
                    source = source.replace(
                        "from gvai.linux_containment_identity import ContainmentIdentity\n",
                        "",
                        1,
                    )
                assert "linux_containment_identity" not in source


@pytest.fixture
def binding_kernel(kernel, monkeypatch):
    kernel["objects"][13] = metadata(103), os.O_RDONLY
    kernel.update(populated=False, exited=True, kill_error=False, adapter_calls=[])
    real_duplicate = module._duplicate

    def duplicate(fd):
        kernel["adapter_calls"].append(("dup", fd))
        return real_duplicate(fd)

    def inherit(fd, flag):
        assert fd in kernel["objects"] and flag is False

    def write(fd, raw):
        kernel["adapter_calls"].append(("kill", fd, raw))
        assert kernel["objects"][fd][0].st_ino == 101
        assert raw == b"1"
        if kernel["kill_error"]:
            raise OSError("Synthetic kill failure.")
        return 1

    def seek(fd, offset, whence):
        assert kernel["objects"][fd][0].st_ino == 102
        assert offset == 0 and whence == os.SEEK_SET
        return 0

    def read(fd, size):
        kernel["adapter_calls"].append(("read", fd))
        assert kernel["objects"][fd][0].st_ino == 102 and size == 4097
        return b"populated 1\n" if kernel["populated"] else b"populated 0\n"

    def wait(kind, fd, flags):
        kernel["adapter_calls"].append(("wait", fd))
        assert kind == os.P_PIDFD
        assert kernel["objects"][fd][0].st_ino == 103
        assert flags == os.WEXITED | os.WNOHANG
        return SimpleNamespace(si_pid=42, si_code=os.CLD_EXITED) if kernel["exited"] else None

    monkeypatch.setattr(os, "dup", duplicate)
    monkeypatch.setattr(os, "set_inheritable", inherit)
    monkeypatch.setattr(os, "write", write)
    monkeypatch.setattr(os, "read", read)
    monkeypatch.setattr(os, "lseek", seek)
    monkeypatch.setattr(os, "waitid", wait)
    return kernel


def assert_only_originals(kernel):
    assert set(kernel["objects"]) == {10, 11, 12, 13}


def test_binding_constructs_without_cleanup_and_uses_retained_controls(binding_kernel):
    value = validate()
    for fd in (10, 11, 12):
        binding_kernel["objects"][fd] = metadata(999, device=99), os.O_RDWR
    binding = value.bind_stop(child_pidfds=(13,))
    assert [call[1] for call in binding_kernel["adapter_calls"]] == [1002, 1003, 13]
    assert all(call[0] == "dup" for call in binding_kernel["adapter_calls"])
    value.close()
    assert any(meta.st_ino == 100 for meta, _ in binding_kernel["objects"].values())
    result = binding.stop()
    assert result.status == "terminated"
    assert result.kill_requested and result.empty and result.reaped
    assert binding.stop().status == "terminated"
    assert sum(call[0] == "wait" for call in binding_kernel["adapter_calls"]) == 1
    binding.close()
    binding.close()
    assert binding.stop().status == "uncertain"
    assert_only_originals(binding_kernel)


def test_binding_close_attempts_directory_after_adapter_close_error(binding_kernel, monkeypatch):
    value = validate()
    binding = value.bind_stop(child_pidfds=(13,))
    owned = [*binding._adapter._fds, binding._directory]
    original_close = module.os.close
    calls = []

    def close(fd):
        calls.append(fd)
        original_close(fd)
        if fd == owned[0]:
            raise OSError("Adapter close failed after release.")

    monkeypatch.setattr(module.os, "close", close)
    with pytest.raises(OSError, match="Adapter close failed"):
        binding.close()
    assert calls == owned
    assert all(fd not in binding_kernel["objects"] for fd in owned)
    assert binding.stop().status == "uncertain"
    binding.close()
    assert calls == owned
    value.close()
    assert_only_originals(binding_kernel)


def test_binding_close_preserves_validator_and_sibling(binding_kernel):
    value = validate()
    first = value.bind_stop(child_pidfds=(13,))
    second = value.bind_stop(child_pidfds=(13,))
    first.close()
    assert value.identity == EXPECTED
    assert second.stop().status == "terminated"
    second.close()
    value.close()
    assert_only_originals(binding_kernel)


@pytest.mark.parametrize("children", [(), [], (True,), (-1,), (13, 13), (1001,), (1002,), (1003,)])
def test_bad_child_inputs_cannot_select_control_targets(binding_kernel, children):
    value = validate()
    before = set(binding_kernel["objects"])
    with pytest.raises(ContainmentIdentityRejected):
        value.bind_stop(child_pidfds=children)
    assert set(binding_kernel["objects"]) == before
    assert binding_kernel["adapter_calls"] == []
    value.close()
    assert_only_originals(binding_kernel)


def test_closed_or_failed_validator_cannot_bind(binding_kernel):
    value = validate()
    value.close()
    with pytest.raises(ContainmentIdentityRejected):
        value.bind_stop(child_pidfds=(13,))
    failed = ValidatedContainmentDescriptors.__new__(ValidatedContainmentDescriptors)
    with pytest.raises(ContainmentIdentityRejected):
        failed.__init__(directory_fd=10, kill_fd=11, events_fd=12,
                        expected=ContainmentIdentity(50, 999))
    with pytest.raises(ContainmentIdentityRejected):
        failed.bind_stop(child_pidfds=(13,))
    assert_only_originals(binding_kernel)


@pytest.mark.parametrize("exception", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("point", ["directory", "first_control", "second_control", "child", "inherit"])
def test_binding_construction_failures_release_only_owned_resources(
    binding_kernel, monkeypatch, exception, point,
):
    value = validate()
    before = set(binding_kernel["objects"])
    signal = exception("Synthetic binding interruption.")
    real_duplicate = module._duplicate
    real_dup = os.dup
    real_inherit = os.set_inheritable

    def directory(fd):
        raise signal

    def dup(fd):
        if (point == "first_control" and fd == 1002
                or point == "second_control" and fd == 1003
                or point == "child" and fd == 13):
            raise signal
        return real_dup(fd)

    def inherit(fd, flag):
        if point == "inherit":
            raise signal
        return real_inherit(fd, flag)

    with monkeypatch.context() as patch:
        if point == "directory":
            patch.setattr(module, "_duplicate", directory)
        else:
            patch.setattr(os, "dup", dup)
            patch.setattr(os, "set_inheritable", inherit)
        with pytest.raises(exception) as error:
            value.bind_stop(child_pidfds=(13,))
        assert error.value is signal
    assert set(binding_kernel["objects"]) == before
    assert value.identity == EXPECTED
    binding = value.bind_stop(child_pidfds=(13,))
    binding.close()
    value.close()
    assert_only_originals(binding_kernel)


@pytest.mark.parametrize("populated,exited,kill_error,status", [
    (True, True, False, "pending"), (False, False, False, "pending"),
    (True, False, False, "pending"), (False, True, True, "uncertain"),
])
def test_bound_adapter_keeps_restrictive_cleanup_semantics(
    binding_kernel, populated, exited, kill_error, status,
):
    value = validate()
    binding = value.bind_stop(child_pidfds=(13,))
    binding_kernel.update(populated=populated, exited=exited, kill_error=kill_error)
    assert binding.stop().status == status
    binding.close()
    value.close()
    assert_only_originals(binding_kernel)


def test_close_waits_for_binding_to_retain_all_controls(binding_kernel, monkeypatch):
    value = validate()
    entered = threading.Event()
    proceed = threading.Event()
    closed = threading.Event()
    result = []
    errors = []
    duplicate = module._duplicate

    def paused(fd):
        if fd == 1001:
            entered.set()
            if not proceed.wait(5):
                raise RuntimeError("Test release timed out.")
        return duplicate(fd)

    def bind():
        try:
            result.append(value.bind_stop(child_pidfds=(13,)))
        except BaseException as error:
            errors.append(error)

    def close():
        value.close()
        closed.set()

    monkeypatch.setattr(module, "_duplicate", paused)
    creator = threading.Thread(target=bind)
    closer = threading.Thread(target=close)
    creator.start()
    try:
        assert entered.wait(5)
        closer.start()
        assert not closed.is_set()
    finally:
        proceed.set()
        creator.join(5)
        if closer.ident is not None:
            closer.join(5)
    assert not creator.is_alive() and not closer.is_alive()
    assert not errors and len(result) == 1
    assert result[0].stop().status == "terminated"
    result[0].close()
    assert_only_originals(binding_kernel)


def test_binding_has_only_stop_and_close(binding_kernel):
    value = validate()
    binding = value.bind_stop(child_pidfds=(13,))
    assert {name for name in vars(type(binding)) if not name.startswith("_")} == {"stop", "close"}
    binding.close()
    value.close()
