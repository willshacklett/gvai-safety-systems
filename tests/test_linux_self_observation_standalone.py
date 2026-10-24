import ast
import errno
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest

import linux_self_observation as diagnostic


SELF_PID = os.getpid()


class FakeReader:
    def __init__(self, *, values=None, errors=None, sequences=None):
        self.values = values or {}
        self.errors = errors or {}
        self.sequences = {key: list(value) for key, value in (sequences or {}).items()}
        self.cgroup_pids = []

    def _value(self, name, default):
        if name in self.errors:
            raise self.errors[name]
        if name in self.sequences and self.sequences[name]:
            return self.sequences[name].pop(0)
        return self.values.get(name, default)

    def process_identity(self):
        return self._value("identity", {
            "pid": SELF_PID, "start_ticks": 42, "pidfd": "matched",
        })

    def status(self):
        return self._value("status", {
            "uid": (1000, 1000, 1000, 1000),
            "gid": (1000, 1000, 1000, 1000),
            "no_new_privs": True,
            "seccomp_mode": 2,
            "capabilities": {
                "CapEff": 0, "CapPrm": 0, "CapInh": 0, "CapBnd": 0, "CapAmb": 0,
            },
        })

    def id_maps(self):
        return self._value("maps", {
            "uid_map": ((0, 1000, 1),),
            "gid_map": ((0, 1000, 1),),
            "setgroups": "deny",
        })

    def apparmor_label(self):
        return self._value("apparmor", {"state": "UNCONFINED", "label": "unconfined"})

    def namespaces(self):
        return self._value("namespaces", {
            name: {"device": 7, "inode": number + 1}
            for number, name in enumerate(diagnostic.NAMESPACE_NAMES)
        })

    def cgroup(self, pid):
        self.cgroup_pids.append(pid)
        return self._value("cgroup", {
            "path_from_proc": "/",
            "device": 8,
            "inode": 9,
            "self_pid_listed": True,
        })

    def descriptors(self):
        return self._value("descriptors", (
            {"number": 0, "target": "pipe:[1]", "flags_octal": "0100000"},
        ))


def test_all_success_shaped_observations_remain_unverified_and_inert():
    reader = FakeReader()
    report = diagnostic.SelfObservationHarness().collect(reader)
    assert report.state == "UNVERIFIED"
    assert report.facts["process_identity"]["pid"] == SELF_PID
    assert reader.cgroup_pids == [SELF_PID, SELF_PID]
    assert report.authenticated is False
    assert report.runtime_verified is False
    assert report.execution_authorized is False
    assert report.publication_authorized is False
    assert not report


@pytest.mark.parametrize("identity", [
    {"pid": SELF_PID + 1, "start_ticks": 42, "pidfd": "matched"},
    {"pid": SELF_PID, "start_ticks": -1, "pidfd": "matched"},
    {"pid": SELF_PID, "start_ticks": 42, "pidfd": "unknown"},
    None,
])
def test_nonself_or_malformed_identity_denies_cgroup_observation(identity):
    reader = FakeReader(values={"identity": identity})
    report = diagnostic.SelfObservationHarness().collect(reader)
    assert report.checks["process_identity"] == "UNVERIFIED"
    assert reader.cgroup_pids == []
    assert "cgroup_v2" not in report.facts
    assert_non_authorizing(report)


@pytest.mark.parametrize("name,value", [
    ("status", {"uid": (1,), "gid": (1, 1, 1, 1)}),
    ("maps", {"uid_map": (), "gid_map": (), "setgroups": "deny"}),
    ("apparmor", ""),
    ("namespaces", {"pid": {"device": 0, "inode": 1}}),
    ("descriptors", tuple(
        {"number": n, "target": "x", "flags_octal": "0"}
        for n in range(diagnostic.MAX_FD_COUNT + 1)
    )),
    ("cgroup", {
        "path_from_proc": "/", "device": 1, "inode": 1, "self_pid_listed": False,
    }),
])
def test_missing_malformed_or_oversized_data_is_unverified(name, value):
    report = diagnostic.SelfObservationHarness().collect(FakeReader(values={name: value}))
    check_name = {
        "maps": "uid_gid_maps",
        "cgroup": "cgroup_v2",
    }.get(name, name)
    assert report.checks[check_name] == "UNVERIFIED"
    assert_non_authorizing(report)


def test_reader_errors_fail_closed():
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(errors={"status": OSError("unavailable")}),
    )
    assert report.checks["status"] == "UNVERIFIED"
    assert "status" not in report.facts
    assert report.errors
    assert_non_authorizing(report)


@pytest.mark.parametrize("name,first,second", [
    (
        "identity",
        {"pid": SELF_PID, "start_ticks": 42, "pidfd": "matched"},
        {"pid": SELF_PID, "start_ticks": 43, "pidfd": "matched"},
    ),
    ("status", {"uid": (1,)}, {"uid": (1, 1, 1, 1)}),
    ("maps", {"uid_map": ((0, 1, 1),)}, {"uid_map": ((0, 2, 1),)}),
    ("apparmor", {"state": "ENFORCING", "label": "gvai"},
     {"state": "COMPLAIN", "label": "gvai"}),
    ("namespaces", {"pid": {"device": 1, "inode": 2}}, {"pid": {"device": 1, "inode": 3}}),
    ("descriptors", (), ({"number": 1, "target": "x", "flags_octal": "0"},)),
    ("cgroup", {"self_pid_listed": True}, {"self_pid_listed": False}),
])
def test_inconsistent_repeated_observations_are_unverified(name, first, second):
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(sequences={name: [first, second]}),
    )
    check_name = {
        "identity": "process_identity",
        "maps": "uid_gid_maps",
        "cgroup": "cgroup_v2",
    }.get(name, name)
    assert report.checks[check_name] == "UNVERIFIED"
    assert_non_authorizing(report)


def test_descriptor_relative_open_rejects_arbitrary_components(monkeypatch):
    monkeypatch.setattr(diagnostic.os, "dup", lambda fd: 99)
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)

    def prohibited(*args, **kwargs):
        pytest.fail("Invalid component must be rejected before openat.")

    monkeypatch.setattr(diagnostic.os, "open", prohibited)
    for components in (("/etc/passwd",), ("..", "secret"), ("proc/self",), ("",)):
        with pytest.raises(ValueError):
            diagnostic._open_beneath(10, components)


def test_descriptor_relative_walk_is_no_follow_and_bounded_to_components(monkeypatch):
    observed = []
    next_fd = iter((101, 102))
    monkeypatch.setattr(diagnostic.os, "dup", lambda fd: 100)
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)

    def fake_open(name, flags, *, dir_fd):
        observed.append((name, flags, dir_fd))
        return next(next_fd)

    monkeypatch.setattr(diagnostic.os, "open", fake_open)
    result = diagnostic._open_beneath(10, ("fdinfo", "7"))
    assert result == 102
    assert [item[0] for item in observed] == ["fdinfo", "7"]
    assert all(item[1] & diagnostic.os.O_NOFOLLOW for item in observed)


@pytest.mark.parametrize("name", diagnostic.NAMESPACE_NAMES)
def test_namespace_link_walk_follows_only_exact_allowlisted_final_links(monkeypatch, name):
    observed = []
    next_fd = iter((101, 102))
    monkeypatch.setattr(diagnostic.os, "dup", lambda fd: 100)
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)

    def fake_open(name, flags, *, dir_fd):
        observed.append((name, flags, dir_fd))
        return next(next_fd)

    monkeypatch.setattr(diagnostic.os, "open", fake_open)
    assert diagnostic._open_beneath(
        10, ("ns", name), follow_final_kernel_link=True,
    ) == 102
    assert [item[0] for item in observed] == ["ns", name]
    assert observed[0][1] & diagnostic.os.O_NOFOLLOW
    assert observed[1][1] & diagnostic.os.O_NOFOLLOW == 0


@pytest.mark.parametrize("components", [
    ("ns", "unknown"),
    ("ns", "pid", "extra"),
    ("proc", "self", "ns", "pid"),
    ("ns",),
])
def test_namespace_link_walk_rejects_non_allowlisted_paths_before_open(monkeypatch, components):
    monkeypatch.setattr(diagnostic.os, "dup", lambda fd: 99)
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)
    monkeypatch.setattr(
        diagnostic.os, "open",
        lambda *args, **kwargs: pytest.fail("Non-allowlisted path reached openat."),
    )
    with pytest.raises(ValueError, match="allowlisted"):
        diagnostic._open_beneath(
            10, components, follow_final_kernel_link=True,
        )


def test_namespace_inspection_rejects_non_nsfs_final_link(monkeypatch):
    reader = SimpleNamespace(_self_fd=10)
    monkeypatch.setattr(diagnostic, "_open_beneath", lambda *args, **kwargs: 11)
    monkeypatch.setattr(diagnostic, "_filesystem_type", lambda fd: 0)
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)
    with pytest.raises(OSError, match="not nsfs"):
        diagnostic.LinuxSelfReader.namespaces(reader)


@pytest.mark.parametrize(("raw", "expected"), [
    (b"gvai-diagnostic (enforce)\n", {"state": "ENFORCING", "label": "gvai-diagnostic"}),
    (b"unconfined\n", {"state": "UNCONFINED", "label": "unconfined"}),
    (b"gvai-diagnostic (complain)\n", {"state": "COMPLAIN", "label": "gvai-diagnostic"}),
])
def test_apparmor_states_are_observed_without_worker_protection_claim(raw, expected):
    assert diagnostic._parse_apparmor_label(raw) == expected
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(values={"apparmor": expected}),
    )
    assert report.checks["apparmor"] == "OBSERVED_UNAUTHENTICATED"
    assert report.facts["apparmor"] == expected
    assert_non_authorizing(report)


@pytest.mark.parametrize("raw", [
    b"",
    b"gvai-diagnostic",
    b"gvai-diagnostic (unknown)",
    b" (enforce)",
    b"gvai-diagnostic\x00 (enforce)",
    b"\xff (enforce)",
])
def test_missing_or_malformed_apparmor_label_is_unverified(raw):
    with pytest.raises((ValueError, UnicodeError)):
        diagnostic._parse_apparmor_label(raw)
    observation = diagnostic.SelfObservationHarness().collect(
        FakeReader(errors={"apparmor": OSError("AppArmor interface unavailable")}),
    )
    assert observation.checks["apparmor"] == "UNVERIFIED"
    assert "apparmor" not in observation.facts
    assert_non_authorizing(observation)


@pytest.mark.parametrize("value", [
    {"state": "UNKNOWN", "label": "gvai"},
    {"state": "ENFORCING", "label": "unconfined"},
    {"state": "COMPLAIN", "label": ""},
    {"state": "UNCONFINED", "label": "gvai"},
])
def test_malformed_apparmor_report_values_remain_unverified(value):
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(values={"apparmor": value}),
    )
    assert report.checks["apparmor"] == "UNVERIFIED"
    assert "apparmor" not in report.facts
    assert_non_authorizing(report)


def _fake_descriptor_scan(monkeypatch, names, *, readlink, open_beneath=None):
    reader = SimpleNamespace(_self_fd=10)

    class Entries:
        def __enter__(self):
            return (SimpleNamespace(name=name) for name in names)

        def __exit__(self, exc_type, exc, traceback):
            return False

    def default_open_beneath(directory_fd, components):
        if components == ("fd",):
            return 20
        if components[0] == "fdinfo":
            return 21
        raise AssertionError(f"Unexpected path: {components!r}")

    monkeypatch.setattr(
        diagnostic, "_open_beneath", open_beneath or default_open_beneath,
    )
    monkeypatch.setattr(diagnostic.os, "scandir", lambda fd: Entries())
    monkeypatch.setattr(diagnostic.os, "close", lambda fd: None)
    monkeypatch.setattr(
        diagnostic.os, "fstat",
        lambda fd: SimpleNamespace(st_mode=stat.S_IFREG | 0o600),
    )
    monkeypatch.setattr(diagnostic, "_read_bounded", lambda fd, maximum: b"flags: 0100000\n")
    monkeypatch.setattr(diagnostic, "_readlink_bounded", readlink)
    return reader


@pytest.mark.parametrize("race", ["readlinkat", "fdinfo_open", "after_partial_inventory"])
def test_disappearing_descriptors_abort_entire_inventory(monkeypatch, race):
    calls = []

    def readlink(fd, name):
        calls.append(name)
        if race == "readlinkat" or (race == "after_partial_inventory" and name == "4"):
            raise OSError(errno.ENOENT, "descriptor disappeared")
        return "pipe:[1]"

    def open_beneath(directory_fd, components):
        if components == ("fd",):
            return 20
        raise OSError(errno.ENOENT, "fdinfo entry disappeared")

    names = ["3", "4"] if race == "after_partial_inventory" else ["3"]
    reader = _fake_descriptor_scan(
        monkeypatch, names, readlink=readlink,
        open_beneath=open_beneath if race == "fdinfo_open" else None,
    )
    with pytest.raises(OSError) as error:
        diagnostic.LinuxSelfReader.descriptors(reader)
    assert error.value.errno == errno.ENOENT
    if race == "after_partial_inventory":
        assert calls == ["3", "3", "4"]


def test_iterator_owned_descriptor_remains_open_while_entries_are_inspected(monkeypatch):
    active = False

    class Entries:
        def __enter__(self):
            nonlocal active
            active = True

            class Iterator:
                def __init__(self):
                    self.names = iter(("3", "9"))

                def __iter__(self):
                    return self

                def __next__(self):
                    nonlocal active
                    try:
                        name = next(self.names)
                    except StopIteration:
                        active = False
                        raise
                    return SimpleNamespace(name=name)

            return Iterator()

        def __exit__(self, exc_type, exc, traceback):
            nonlocal active
            active = False
            return False

    def readlink(fd, name):
        assert active, "Descriptor inspection must finish before scandir closes."
        return "pipe:[1]" if name == "3" else "anon_inode:[eventpoll]"

    reader = _fake_descriptor_scan(
        monkeypatch, (), readlink=readlink,
    )
    monkeypatch.setattr(diagnostic.os, "scandir", lambda fd: Entries())
    records = diagnostic.LinuxSelfReader.descriptors(reader)
    assert [record["number"] for record in records] == [3, 9]
    assert active is False


def test_unrelated_disappearing_descriptor_still_invalidates_partial_scan(monkeypatch):
    active = False

    class Entries:
        def __enter__(self):
            nonlocal active
            active = True

            class Iterator:
                def __init__(self):
                    self.names = iter(("3", "4"))

                def __iter__(self):
                    return self

                def __next__(self):
                    nonlocal active
                    try:
                        name = next(self.names)
                    except StopIteration:
                        active = False
                        raise
                    return SimpleNamespace(name=name)

            return Iterator()

        def __exit__(self, exc_type, exc, traceback):
            nonlocal active
            active = False
            return False

    def readlink(fd, name):
        assert active
        if name == "4":
            raise OSError(errno.ENOENT, "unrelated descriptor disappeared")
        return "pipe:[1]"

    reader = _fake_descriptor_scan(
        monkeypatch, (), readlink=readlink,
    )
    monkeypatch.setattr(diagnostic.os, "scandir", lambda fd: Entries())
    with pytest.raises(OSError) as error:
        diagnostic.LinuxSelfReader.descriptors(reader)
    assert error.value.errno == errno.ENOENT
    assert active is False


def test_descriptor_reuse_between_target_and_fdinfo_is_unverified(monkeypatch):
    targets = iter(("pipe:[1]", "pipe:[2]"))
    reader = _fake_descriptor_scan(
        monkeypatch, ["3"], readlink=lambda fd, name: next(targets),
    )
    with pytest.raises(InterruptedError, match="reused"):
        diagnostic.LinuxSelfReader.descriptors(reader)


def test_descriptor_reuse_or_inconsistent_repeated_inventory_is_unverified():
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(sequences={"descriptors": [
            ({"number": 3, "target": "pipe:[1]", "flags_octal": "0100000"},),
            ({"number": 3, "target": "pipe:[2]", "flags_octal": "0100000"},),
        ]}),
    )
    assert report.checks["descriptors"] == "UNVERIFIED"
    assert "descriptors" not in report.facts
    assert_non_authorizing(report)


def test_inconsistent_descriptor_flags_between_inventory_reads_fail_closed():
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(sequences={"descriptors": [
            ({"number": 3, "target": "pipe:[1]", "flags_octal": "0100000"},),
            ({"number": 3, "target": "pipe:[1]", "flags_octal": "0200000"},),
        ]}),
    )
    assert report.checks["descriptors"] == "UNVERIFIED"
    assert "descriptors" not in report.facts
    assert_non_authorizing(report)


def test_disappearing_descriptor_report_has_no_partial_inventory():
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(errors={"descriptors": OSError(errno.ENOENT, "descriptor disappeared")}),
    )
    assert report.checks["descriptors"] == "UNVERIFIED"
    assert "descriptors" not in report.facts
    assert_non_authorizing(report)


def test_readlinkat_enoent_is_preserved_as_a_race(monkeypatch):
    class FailedReadlink:
        argtypes = None
        restype = None

        def __call__(self, *args):
            import ctypes

            ctypes.set_errno(errno.ENOENT)
            return -1

    class FakeLibrary:
        readlinkat = FailedReadlink()

    monkeypatch.setattr("ctypes.CDLL", lambda *args, **kwargs: FakeLibrary())
    with pytest.raises(OSError) as error:
        diagnostic._readlink_bounded(10, "3")
    assert error.value.errno == errno.ENOENT


def test_bounded_read_rejects_data_over_limit(monkeypatch):
    monkeypatch.setattr(diagnostic.os, "read", lambda fd, size: b"12345")
    with pytest.raises(ValueError, match="bound"):
        diagnostic._read_bounded(10, 4)


def test_import_closure_is_standalone_and_has_no_authority_or_network_imports():
    source = Path(diagnostic.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    assert imports <= {
        "__future__", "dataclasses", "json", "os", "select", "stat", "sys",
        "time", "typing", "ctypes", "platform",
    }
    assert not imports.intersection({
        "gvai", "socket", "subprocess", "urllib", "http", "ftplib", "ssl",
    })
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "system", "popen", "fork", "forkpty", "execv", "execve",
                "spawnv", "spawnve", "setns", "unshare",
            }
    assert sys.version_info >= (3, 9)


def assert_non_authorizing(report):
    assert report.authenticated is False
    assert report.runtime_verified is False
    assert report.execution_authorized is False
    assert report.publication_authorized is False
