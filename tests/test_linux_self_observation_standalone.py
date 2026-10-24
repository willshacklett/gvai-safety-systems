import ast
import os
from pathlib import Path
import sys

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
        return self._value("apparmor", "unconfined")

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
    assert not report.execution_authorized
    assert not report.publication_authorized


def test_reader_errors_fail_closed():
    report = diagnostic.SelfObservationHarness().collect(
        FakeReader(errors={"status": OSError("unavailable")}),
    )
    assert report.checks["status"] == "UNVERIFIED"
    assert "status" not in report.facts
    assert report.errors


@pytest.mark.parametrize("name,first,second", [
    (
        "identity",
        {"pid": SELF_PID, "start_ticks": 42, "pidfd": "matched"},
        {"pid": SELF_PID, "start_ticks": 43, "pidfd": "matched"},
    ),
    ("status", {"uid": (1,)}, {"uid": (1, 1, 1, 1)}),
    ("maps", {"uid_map": ((0, 1, 1),)}, {"uid_map": ((0, 2, 1),)}),
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
    assert not report.execution_authorized
    assert not report.publication_authorized


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
