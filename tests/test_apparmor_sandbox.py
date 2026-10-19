"""Unit contracts run everywhere; opt-in acceptance must run on the target host."""

import errno
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from types import SimpleNamespace

import pytest

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.os_sandbox import GVOSSandboxExecutor, _runtime_mounts, bwrap_path
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.seccomp_filter import build_no_spawn_filter
from gvai.sentinel import GVSentinel


POLICY = (
    Path(__file__).resolve().parents[1]
    / "security/apparmor/usr.bin.bwrap.gvai"
)
HOST = pytest.mark.skipif(
    os.environ.get("GVAI_APPARMOR_ACCEPTANCE") != "1",
    reason="explicit supported-host AppArmor acceptance not requested",
)


def test_policy_has_mandatory_stacked_worker_and_no_escape():
    policy = POLICY.read_text()
    assert "profile gvai-bwrap /usr/bin/bwrap flags=(enforce)" in policy
    assert "/usr/bin/python3.12 rPx -> &gvai-worker," in policy
    worker = policy.split("profile gvai-worker flags=(enforce) {")[1]
    for rule in (
        "capability", "userns", "network", "mount", "remount",
        "umount", "pivot_root",
    ):
        assert f"audit deny {rule}," in worker
    assert "audit deny ptrace (read, trace, tracedby)," in worker
    assert "ptrace (readby) peer=unconfined," in worker
    for path in ("/proc/**", "/sys/**", "/safety/**"):
        assert f"audit deny {path} w," in worker
    assert "change_profile" not in policy
    assert "unconfined)" not in policy
    assert " ix" not in policy
    assert " ux" not in policy
    assert " pix" not in policy
    assert " pux" not in policy
    assert "capability," not in policy.split("profile gvai-worker")[0]


def test_loopback_socket_permission_is_launcher_only_and_create_only():
    policy = "\n".join(
        line.split("#", 1)[0] for line in POLICY.read_text().splitlines()
    )
    launcher, worker = policy.split("profile gvai-worker flags=(enforce) {")
    assert re.findall(r"^[ \t]*(unix\b[^,]*,)", launcher, re.MULTILINE) == [
        "unix (create) type=dgram,",
    ]
    assert re.findall(r"^[ \t]*(network\b[^,]*,)", launcher, re.MULTILINE) == [
        "network netlink raw,",
    ]
    assert not re.search(r"^\s*(?:unix|network)\b", worker, re.MULTILINE)
    assert "audit deny network," in worker
    assert "attach_disconnected" not in policy
    assert "/proc/filesystems" not in policy
    assert not re.search(r"/proc/[^\n]*\bmounts\b", policy)


def test_profiles_do_not_relabel_disconnected_or_deleted_objects():
    policy = "\n".join(
        line.split("#", 1)[0] for line in POLICY.read_text().splitlines()
    )
    for flag in (
        "attach_disconnected", "chroot_relative", "mediate_deleted",
    ):
        assert flag not in policy
    assert re.findall(r"^profile [^{]+", policy, re.MULTILINE) == [
        "profile gvai-bwrap /usr/bin/bwrap flags=(enforce) ",
        "profile gvai-worker flags=(enforce) ",
    ]


def test_launcher_procfs_writes_remain_limited_to_mapping_and_setup_fds():
    launcher = POLICY.read_text().split("profile gvai-worker flags=(enforce) {")[0]
    rules = re.findall(
        r"^[ \t]*(?:(?:allow|audit|owner)[ \t]+)*(/proc/\S+)[ \t]+([a-z]+),",
        launcher, re.MULTILINE,
    )
    assert {(path, mode) for path, mode in rules if "w" in mode} == {
        ("/proc/{self,[0-9]*}/{uid_map,gid_map,setgroups}", "rw"),
        ("/proc/{self,[0-9]*}/fd/*", "rw"),
    }


def test_python_interpreter_is_the_only_execution_transition():
    policy = "\n".join(
        line.split("#", 1)[0] for line in POLICY.read_text().splitlines()
    )
    exec_rules = re.findall(
        r"^\s*(/\S+)\s+([a-zA-Z]*x)\s*(?:->\s*(\S+))?,",
        policy, re.MULTILINE,
    )
    assert exec_rules == [("/usr/bin/python3.12", "rPx", "&gvai-worker")]
    assert "change_profile" not in policy


def test_executor_keeps_fixed_worker_and_namespace_boundary(tmp_path, monkeypatch):
    import gvai.os_sandbox as sandbox

    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    captured = {}

    def run(command, **kwargs):
        captured.update(command=command, **kwargs)
        return subprocess.CompletedProcess(
            command, 0, '{"completed": true, "events": [], "error": null}', "",
        )

    monkeypatch.setattr(sandbox.subprocess, "run", run)
    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate([])))
    executor = GVOSSandboxExecutor(guard, tmp_path / "committed")
    result = executor.execute("safe_work", guard.observe([1.0] * 4))
    assert result.completed
    command = captured["command"]
    assert command[0] == "/usr/bin/bwrap"
    assert command[-4:] == [
        "/usr/bin/python3", "/runner.py", "--action", "safe_work",
    ]
    assert "-c" not in command
    worker = str(Path(sandbox.__file__).resolve().with_name("os_sandbox_worker.py"))
    assert any(
        command[i:i + 3] == ["--ro-bind", worker, "/runner.py"]
        for i in range(len(command) - 2)
    )
    for namespace in ("user", "pid", "net", "uts", "ipc"):
        assert f"--unshare-{namespace}" in command
    for option, path in (("--proc", "/proc"), ("--dev", "/dev")):
        assert command.count(option) == 1
        assert command[command.index(option) + 1] == path
    for option in ("--userns", "--userns2", "--userns-block-fd", "--uid", "--gid"):
        assert option not in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert captured["pass_fds"] == (int(command[command.index("--seccomp") + 1]),)
    assert captured["env"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONNOUSERSITE": "1",
    }


def test_bwrap_ignores_path_shadow(tmp_path, monkeypatch):
    shadow = tmp_path / "bwrap"
    shadow.write_text("#!/bin/sh\nexit 0\n")
    shadow.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert bwrap_path() in {None, "/usr/bin/bwrap"}


@pytest.mark.parametrize("mode,uid", [
    (stat.S_IFREG | 0o4755, 0),
    (stat.S_IFREG | 0o2755, 0),
    (stat.S_IFREG | 0o777, 0),
    (stat.S_IFREG | 0o755, 1000),
    (stat.S_IFDIR | 0o755, 0),
    (stat.S_IFLNK | 0o777, 0),
])
def test_bwrap_rejects_unsafe_binary(monkeypatch, mode, uid):
    monkeypatch.setattr(
        Path, "stat",
        lambda self, **kwargs: SimpleNamespace(st_mode=mode, st_uid=uid),
    )
    assert bwrap_path() is None


def test_bwrap_rejects_file_capabilities(monkeypatch):
    monkeypatch.setattr(
        Path, "stat",
        lambda self, **kwargs: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o755, st_uid=0,
        ),
    )
    monkeypatch.setattr(os, "access", lambda *args: True)
    monkeypatch.setattr(os, "getxattr", lambda *args, **kwargs: b"capabilities")
    assert bwrap_path() is None


def test_socket_creation_denial_is_a_blocked_network_event(monkeypatch, capsys):
    import socket
    import sys

    from gvai.os_sandbox_worker import main

    def denied_socket():
        raise PermissionError(errno.EACCES, "AppArmor denied socket")

    monkeypatch.setattr(socket, "socket", denied_socket)
    monkeypatch.setattr(sys, "argv", ["runner.py", "--action", "network_attack"])
    assert main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["completed"] is True
    assert result["error"] is None
    assert result["events"][0]["event"] == "external_network_blocked"


@pytest.mark.parametrize("returncode,stdout", [
    (1, ""),
    (1, '{"completed": true, "events": []}'),
    (0, ""),
    (0, "not json"),
    (0, "[]"),
    (0, '{"completed": "true", "events": []}'),
    (0, '{"completed": true, "events": [null]}'),
    (0, '{"completed": true, "events": [], "error": "failed"}'),
])
def test_setup_or_result_failure_never_authorizes_or_commits(
    tmp_path, monkeypatch, returncode, stdout,
):
    import gvai.os_sandbox as sandbox

    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate([])))
    observation = guard.observe([1.0] * 4)
    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")

    def failed_run(command, **kwargs):
        work = Path(command[command.index("--bind") + 1])
        (work / "must-not-commit").write_text("untrusted")
        return subprocess.CompletedProcess(command, returncode, stdout, "denied")

    monkeypatch.setattr(sandbox.subprocess, "run", failed_run)
    executor = GVOSSandboxExecutor(guard, tmp_path / "committed")
    result = executor.execute("safe_work", observation)
    assert not result.allowed
    assert not result.completed
    assert not result.committed
    assert result.error
    assert "os_boundary_failure" in result.observed_effects
    assert not list((tmp_path / "committed").iterdir())


def test_unavailable_sandbox_never_falls_back(tmp_path, monkeypatch):
    import gvai.os_sandbox as sandbox

    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: False)
    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate([])))
    with pytest.raises(sandbox.OSSandboxUnavailable, match="Refusing to fall back"):
        GVOSSandboxExecutor(guard, tmp_path / "committed")


MAPPING_FAILURES = (
    "bwrap: Can't open /proc: Permission denied\n",
    "bwrap: open /proc/self failed: Permission denied\n",
    "bwrap: setting up uid map: Permission denied\n",
    "bwrap: error writing to setgroups: Permission denied\n",
    "bwrap: setting up gid map: Permission denied\n",
)


@pytest.mark.parametrize("stderr", MAPPING_FAILURES)
def test_mapping_setup_failure_makes_sandbox_unavailable(tmp_path, monkeypatch, stderr):
    import gvai.os_sandbox as sandbox

    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox, "libseccomp_available", lambda: True)
    calls = []

    def failed_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 1, "ok\n", stderr)

    monkeypatch.setattr(sandbox.subprocess, "run", failed_run)
    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate([])))
    with pytest.raises(sandbox.OSSandboxUnavailable, match="Refusing to fall back"):
        GVOSSandboxExecutor(guard, tmp_path / "committed")
    assert len(calls) == 1
    assert calls[0][0] == "/usr/bin/bwrap"
    for namespace in ("user", "pid", "net", "uts", "ipc"):
        assert f"--unshare-{namespace}" in calls[0]
    assert not list((tmp_path / "committed").iterdir())


@pytest.mark.parametrize("stderr", MAPPING_FAILURES)
def test_mapping_failure_after_availability_check_preserves_evidence_and_denies_commit(
    tmp_path, monkeypatch, stderr,
):
    import gvai.os_sandbox as sandbox

    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    calls = []
    closed = []
    monkeypatch.setattr(
        sandbox, "build_no_spawn_filter",
        lambda: SimpleNamespace(fd=77, close=lambda: closed.append(77)),
    )

    def failed_run(command, **kwargs):
        calls.append((command, kwargs))
        work = Path(command[command.index("--bind") + 1])
        (work / "must-not-commit").write_text("untrusted")
        return subprocess.CompletedProcess(
            command, 1, '{"completed": true, "events": [], "error": null}', stderr,
        )

    monkeypatch.setattr(sandbox.subprocess, "run", failed_run)
    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate([])))
    executor = GVOSSandboxExecutor(guard, tmp_path / "committed")
    result = executor.execute("safe_work", guard.observe([1.0] * 4))
    assert result.returncode == 1
    assert result.stderr == stderr
    assert result.error
    assert not result.completed
    assert not result.allowed
    assert not result.committed
    assert "os_boundary_failure" in result.observed_effects
    assert not list((tmp_path / "committed").iterdir())
    assert len(calls) == 1
    assert calls[0][1]["pass_fds"] == (77,)
    assert closed == [77]
    for namespace in ("user", "pid", "net", "uts", "ipc"):
        assert f"--unshare-{namespace}" in calls[0][0]


PROBE = r"""
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import subprocess

def denied(call):
    try:
        call()
    except OSError as exc:
        return exc.errno
    return 0

libc = ctypes.CDLL(None, use_errno=True)
def syscall_result(call):
    ctypes.set_errno(0)
    return 0 if call() == 0 else ctypes.get_errno()

def socket_creation(family, kind):
    def create():
        with socket.socket(family, kind):
            pass
    return denied(create)

status = dict(
    line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines()
    if ":" in line
)
class Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class Data(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]
header = Header(0x20080522, 0)
caps = (Data * 2)()
caps[0].effective = caps[0].permitted = 1 << 12

result = {
    "uid": os.getuid(),
    "gid": os.getgid(),
    "pid": os.getpid(),
    "label": Path("/proc/self/attr/current").read_text().strip(),
    "status": {k: status[k].strip() for k in (
        "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"
    )},
    "namespaces": {
        name: os.readlink("/proc/self/ns/" + name)
        for name in ("user", "pid", "mnt", "net", "uts", "ipc")
    },
    "uid_map": Path("/proc/self/uid_map").read_text().split(),
    "gid_map": Path("/proc/self/gid_map").read_text().split(),
    "route": Path("/proc/net/route").read_text(),
    "host_file": denied(lambda: Path(HOST_SECRET).read_bytes()),
    "policy_write": denied(lambda: Path("/safety/policy.json").write_text("off")),
    "apparmor_write": denied(
        lambda: Path("/sys/kernel/security/apparmor/.remove").write_text("gvai-worker")
    ),
    "profile_change": denied(
        lambda: Path("/proc/self/attr/current").write_text("changeprofile gvai-bwrap")
    ),
    "profile_change_worker": denied(
        lambda: Path("/proc/self/attr/current").write_text("changeprofile gvai-worker")
    ),
    "profile_change_unconfined": denied(
        lambda: Path("/proc/self/attr/current").write_text("changeprofile unconfined")
    ),
    "uid_map_write": denied(
        lambda: Path("/proc/self/uid_map").write_text("0 0 1\n")
    ),
    "gid_map_write": denied(
        lambda: Path("/proc/self/gid_map").write_text("0 0 1\n")
    ),
    "setgroups_write": denied(
        lambda: Path("/proc/self/setgroups").write_text("allow\n")
    ),
    "network": denied(lambda: socket.create_connection(("1.1.1.1", 443), timeout=1)),
    "socket_creation": {
        "unix_dgram": socket_creation(socket.AF_UNIX, socket.SOCK_DGRAM),
        "unix_stream": socket_creation(socket.AF_UNIX, socket.SOCK_STREAM),
        "inet_dgram": socket_creation(socket.AF_INET, socket.SOCK_DGRAM),
        "inet6_dgram": socket_creation(socket.AF_INET6, socket.SOCK_DGRAM),
        "netlink_raw": socket_creation(socket.AF_NETLINK, socket.SOCK_RAW),
    },
    "spawn": denied(lambda: subprocess.run(["/usr/bin/true"], check=True)),
    "unshare": syscall_result(lambda: libc.unshare(0x10000000)),
    "mount": syscall_result(lambda: libc.mount(b"tmpfs", b"/tmp", b"tmpfs", 0, None)),
    "remount": syscall_result(lambda: libc.mount(None, b"/work", None, 32, None)),
    "umount": syscall_result(lambda: libc.umount2(b"/work", 0)),
    "capset": syscall_result(lambda: libc.capset(ctypes.byref(header), caps)),
    "clear_nnp": syscall_result(lambda: libc.prctl(38, 0, 0, 0, 0)),
    "bwrap_exec": denied(lambda: os.execv("/usr/bin/bwrap", ["bwrap", "--version"])),
}
result["label_after_attempts"] = Path("/proc/self/attr/current").read_text().strip()
Path("/work/probe.txt").write_text("safe output\n")
print(json.dumps(result))
"""


def test_host_probe_compiles_without_host_acceptance():
    compile(
        "HOST_SECRET = '/unmounted-host-secret'\n" + PROBE,
        "<apparmor-host-probe>", "exec",
    )


@pytest.fixture
def host_requirements():
    assert os.getuid() == 1000, "run as unprivileged gvaitest, never root"
    assert os.getgid() == 1000
    assert Path("/sys/module/apparmor/parameters/enabled").read_text().strip() == "Y"
    assert Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").read_text().strip() == "1"
    assert Path("/proc/sys/kernel/unprivileged_userns_clone").read_text().strip() == "1"
    assert Path("/proc/sys/user/max_user_namespaces").read_text().strip() == "3692"
    assert Path("/sys/kernel/security/apparmor/features/domain/stack").read_text().strip() == "yes"
    assert bwrap_path() == "/usr/bin/bwrap"
    assert subprocess.check_output(["/usr/bin/bwrap", "--version"], text=True).strip() == "bubblewrap 0.9.0"
    assert Path("/usr/bin/python3").resolve() == Path("/usr/bin/python3.12")


@pytest.mark.parametrize("mismatch", [
    None, "enabled", "restriction", "clone", "limit", "stack",
])
def test_host_preflight_requires_reproduction_baseline(monkeypatch, request, mismatch):
    import gvai.os_sandbox as sandbox

    values = {
        "/sys/module/apparmor/parameters/enabled": ("enabled", "Y"),
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": ("restriction", "1"),
        "/proc/sys/kernel/unprivileged_userns_clone": ("clone", "1"),
        "/proc/sys/user/max_user_namespaces": ("limit", "3692"),
        "/sys/kernel/security/apparmor/features/domain/stack": ("stack", "yes"),
    }

    def read_text(path):
        key, value = values[str(path)]
        return "0\n" if key == mismatch else value + "\n"

    def version(command, **kwargs):
        assert command == ["/usr/bin/bwrap", "--version"]
        assert kwargs == {"text": True}
        return "bubblewrap 0.9.0\n"

    original_resolve = Path.resolve
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setattr(os, "getgid", lambda: 1000)
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(
        Path, "resolve",
        lambda path: (
            Path("/usr/bin/python3.12") if path == Path("/usr/bin/python3")
            else original_resolve(path)
        ),
    )
    monkeypatch.setattr(sandbox.subprocess, "check_output", version)
    monkeypatch.setattr(__name__ + ".bwrap_path", lambda: "/usr/bin/bwrap")
    if mismatch is None:
        request.getfixturevalue("host_requirements")
    else:
        with pytest.raises(AssertionError):
            request.getfixturevalue("host_requirements")


@pytest.fixture
def host_probe(tmp_path, host_requirements):
    secret = tmp_path / "host-secret"
    secret.write_text("must not cross boundary")
    # Use the same launcher-authorized temporary tree as the executor.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="gv-os-sandbox-", dir="/tmp") as root:
        root = Path(root)
        (root / "safety").mkdir()
        (root / "safety/policy.json").write_text("enabled\n")
        (root / "work").mkdir()
        seccomp = build_no_spawn_filter()
        try:
            command = [
                "/usr/bin/bwrap", "--unshare-user", "--unshare-pid",
                "--unshare-net", "--unshare-uts", "--unshare-ipc",
                "--die-with-parent", "--new-session", *_runtime_mounts(),
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
                "--bind", str(root / "work"), "/work",
                "--ro-bind", str(root / "safety"), "/safety",
                "--chdir", "/work", "--cap-drop", "ALL",
                "--seccomp", str(seccomp.fd),
                "/usr/bin/python3", "-I", "-c",
                "HOST_SECRET = " + repr(str(secret)) + "\n" + PROBE,
            ]
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=10,
                pass_fds=(seccomp.fd,), close_fds=True,
                env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONNOUSERSITE": "1"},
            )
        finally:
            seccomp.close()
        assert process.returncode == 0, process.stderr
        result = json.loads(process.stdout)
        assert (root / "work/probe.txt").read_text() == "safe output\n"
        assert (root / "safety/policy.json").read_text() == "enabled\n"
    assert secret.read_text() == "must not cross boundary"
    return result


@HOST
def test_supported_host_namespaces_and_enforcing_stack(host_probe):
    result = host_probe
    assert result["uid"] == result["gid"] == 1000
    assert result["pid"] in {1, 2}
    assert set(result["label"].removesuffix(" (enforce)").split("//&")) == {
        "gvai-bwrap", "gvai-worker",
    }
    assert result["label"].endswith(" (enforce)")
    assert set(result["namespaces"]) == {"user", "pid", "mnt", "net", "uts", "ipc"}
    for name, namespace in result["namespaces"].items():
        assert namespace != os.readlink(f"/proc/self/ns/{name}")
    assert result["uid_map"] == ["1000", "0", "1"]
    assert result["gid_map"] == ["1000", "0", "1"]
    assert len(result["route"].splitlines()) == 1


@HOST
def test_supported_host_worker_cannot_recover_launcher_privileges(host_probe):
    status = host_probe["status"]
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        assert int(status[field], 16) == 0, (field, status)
    assert status["NoNewPrivs"] == "1"
    assert status["Seccomp"] == "2"
    for operation in (
        "unshare", "mount", "remount", "umount", "capset",
        "bwrap_exec", "profile_change", "profile_change_worker",
        "profile_change_unconfined",
    ):
        assert host_probe[operation] in {errno.EPERM, errno.EACCES}, (operation, host_probe)
    assert host_probe["label_after_attempts"] == host_probe["label"]
    assert host_probe["clear_nnp"] in {errno.EPERM, errno.EINVAL}


@HOST
def test_supported_host_files_network_and_processes_are_blocked(host_probe):
    for operation in ("host_file", "apparmor_write"):
        assert host_probe[operation] in {errno.ENOENT, errno.EACCES, errno.EPERM}
    for operation in (
        "policy_write", "uid_map_write", "gid_map_write", "setgroups_write",
    ):
        assert host_probe[operation] in {errno.EROFS, errno.EACCES, errno.EPERM}
    assert host_probe["network"] in {errno.EACCES, errno.EPERM, errno.ENETUNREACH}
    for family, error in host_probe["socket_creation"].items():
        assert error in {errno.EACCES, errno.EPERM}, (family, host_probe)
    assert host_probe["spawn"] in {errno.EACCES, errno.EPERM}


@HOST
@pytest.mark.parametrize("action,effect", [
    ("safe_work", None),
    ("protected_file_attack", "protected_file_write_attempt"),
    ("network_attack", "unapproved_network_egress_attempt"),
    ("process_attack", "unauthorized_process_spawn_attempt"),
])
def test_supported_host_fixed_worker_executor(tmp_path, host_requirements, action, effect):
    invariant = make_effect_invariant(
        name="host_worker_boundary",
        description="The fixed worker must not cross the OS boundary.",
        forbidden_effects={
            "os_boundary_failure", "protected_file_write_attempt",
            "unapproved_network_egress_attempt", "unauthorized_process_spawn_attempt",
        },
    )
    guard = GVRuntimeGuardV2(
        GVSentinel(), GVRuntimePolicy(GVEffectGate([invariant])),
    )
    executor = GVOSSandboxExecutor(guard, tmp_path / "committed")
    result = executor.execute(action, guard.observe([1.0] * 4))
    assert result.returncode == 0, result.stderr
    assert result.completed, (result.error, result.stderr)
    assert result.error is None
    assert "os_boundary_failure" not in result.observed_effects
    if effect is None:
        assert result.allowed and result.committed
        assert (tmp_path / "committed/result.txt").read_text() == "safe work\n"
    else:
        assert effect in result.observed_effects
        assert not result.allowed and not result.committed
        assert not list((tmp_path / "committed").iterdir())


@HOST
def test_supported_host_bwrap_cannot_execute_unapproved_payload(host_requirements):
    process = subprocess.run(
        [
            "/usr/bin/bwrap", "--unshare-user", "--unshare-pid",
            "--unshare-net", "--cap-drop", "ALL",
            *_runtime_mounts(), "/usr/bin/true",
        ],
        capture_output=True, text=True, timeout=10,
        env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"},
    )
    assert process.returncode != 0
    assert "execvp /usr/bin/true: Permission denied" in process.stderr
