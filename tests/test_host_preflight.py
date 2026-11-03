import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def preflight():
    spec = importlib.util.spec_from_file_location(
        "test_gvai_host_preflight", ROOT / "deploy/private_https/host_preflight.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("text,prepared,expected", [
    ("", False, True), ("", True, False), (None, False, False),
    ("LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*", False, False),
    ("LISTEN 0 128 [::]:5432 [::]:*", True, False),
    ("LISTEN 0 128 127.0.0.1:8443 0.0.0.0:*", False, False),
    ("LISTEN 0 128 127.0.0.1:22 0.0.0.0:*", False, True),
    ("malformed secret-password", True, False),
    ("\n".join(f"LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*" for port in (5432, 8080, 8443)), True, True),
])
def test_listener_inventory_collision_and_public_bind_denial(preflight, text, prepared, expected):
    assert preflight.listener_check(text, prepared) is expected


def test_observation_commands_are_fixed_readonly_and_redacted(preflight, monkeypatch):
    calls = []

    def run(arguments, **kwargs):
        calls.append(arguments)
        assert kwargs["timeout"] == 10
        assert "shell" not in kwargs
        assert "secret" not in kwargs["env"]
        return SimpleNamespace(returncode=0, stdout=b"Status: active\n", stderr=b"secret")

    monkeypatch.setattr(preflight.subprocess, "run", run)
    assert preflight.command("firewall") == "Status: active\n"
    assert calls == [("ufw", "status", "verbose")]
    for arguments in preflight.COMMANDS.values():
        assert not set(arguments) & {"start", "stop", "restart", "reload", "enable", "disable", "install", "apply"}


@pytest.mark.parametrize("failure", ["exit", "timeout", "missing", "decode"])
def test_observer_failures_never_disclose_details(preflight, monkeypatch, failure):
    def run(*_args, **_kwargs):
        if failure == "timeout":
            raise preflight.subprocess.TimeoutExpired("secret", 10, stderr="secret")
        if failure == "missing":
            raise OSError("secret-password")
        return SimpleNamespace(returncode=1 if failure == "exit" else 0, stdout=b"\xff", stderr=b"secret")

    monkeypatch.setattr(preflight.subprocess, "run", run)
    assert preflight.command("worker") is None


def test_regular_reads_refuse_links_oversize_and_fifo(preflight, tmp_path):
    file = tmp_path / "input"
    file.write_bytes(b"safe")
    assert preflight.read_regular(file, 4) == b"safe"
    with pytest.raises(ValueError):
        preflight.read_regular(file, 3)
    link = tmp_path / "link"
    link.symlink_to(file)
    with pytest.raises(OSError):
        preflight.read_regular(link)
    fifo = tmp_path / "pipe"
    preflight.os.mkfifo(fifo)
    with pytest.raises(ValueError):
        preflight.read_regular(fifo)


def test_unit_state_fingerprint_detects_code_and_pid_drift(preflight, monkeypatch):
    states = {"MainPID": "100", "content": b"original"}

    def observe(_name):
        return (
            "LoadState=loaded\nActiveState=active\nSubState=running\nMainPID=" + states["MainPID"]
            + "\nFragmentPath=/etc/systemd/system/gvai-worker.service\nDropInPaths=\n"
        )

    monkeypatch.setattr(preflight, "required_command", observe)
    monkeypatch.setattr(Path, "lstat", lambda _path: SimpleNamespace(st_uid=0, st_mode=0o100644))
    monkeypatch.setattr(preflight, "read_regular", lambda _path: states["content"])
    first = preflight.unit_fingerprint("worker")
    states["content"] = b"changed"
    assert preflight.unit_fingerprint("worker") != first
    states["content"] = b"original"
    states["MainPID"] = "101"
    assert preflight.unit_fingerprint("worker") != first


def test_policy_fingerprint_tracks_internal_links_and_bytes_without_following_external_links(
    preflight, monkeypatch, tmp_path,
):
    root = tmp_path / "apparmor"
    root.mkdir(mode=0o700)
    policy = root / "gvai-worker"
    policy.write_text("original policy")
    policy.chmod(0o644)
    link = root / "enabled"
    link.symlink_to("gvai-worker")
    original_stat, original_lstat = Path.stat, Path.lstat

    def as_root(result):
        values = list(result)
        values[4] = 0
        return preflight.os.stat_result(values)

    monkeypatch.setattr(Path, "stat", lambda path, **kwargs: as_root(original_stat(path, **kwargs)))
    monkeypatch.setattr(Path, "lstat", lambda path: as_root(original_lstat(path)))
    first = preflight.policy_fingerprint(root)
    policy.write_text("changed policy")
    assert preflight.policy_fingerprint(root) != first
    link.unlink()
    link.symlink_to(tmp_path)
    with pytest.raises(ValueError):
        preflight.policy_fingerprint(root)


def test_custody_refuses_writable_ancestor_and_symlink(preflight, tmp_path):
    file = tmp_path / "secret"
    file.write_text("never read me")
    file.chmod(0o400)
    assert preflight.path_check(file, 0o400) is False
    link = tmp_path / "link"
    link.symlink_to(file)
    assert preflight.path_check(link, 0o400) is False


@pytest.fixture
def healthy_inventory(preflight, monkeypatch):
    baseline = {name: "a" * 64 for name in (
        "policy_tree_sha256", "loaded_profiles_sha256", "worker_state_sha256", "bwrap_state_sha256",
    )}
    files = {
        "/etc/hostname": b"gvai-safety-test-01\n",
        "/usr/lib/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n',
        "/proc/1/comm": b"systemd\n",
        "/proc/meminfo": b"MemAvailable: 3145728 kB\n",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns": b"1\n",
    }
    commands = {"systemd": "systemd 255\n", "apparmor": "", "firewall": "Status: active\n", "listeners": ""}
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)
    monkeypatch.setattr(preflight, "read_regular", lambda path, *_args: files[str(path)])
    monkeypatch.setattr(preflight, "command", lambda name: commands.get(name))
    monkeypatch.setattr(Path, "read_text", lambda _path: "gvai-worker (enforce)\ngvai-bwrap (enforce)\n")
    monkeypatch.setattr(Path, "is_file", lambda _path: True)
    monkeypatch.setattr(preflight, "protected_snapshot", lambda _profiles: baseline.copy())
    monkeypatch.setattr(preflight, "load_baseline", lambda _path: baseline.copy())
    monkeypatch.setattr(preflight.shutil, "disk_usage", lambda _path: SimpleNamespace(free=6 * 1024**3))
    monkeypatch.setattr(preflight.shutil, "which", lambda name, **_kwargs: "/usr/bin/" + name)
    monkeypatch.setattr(preflight, "account_check", lambda _name: True)
    monkeypatch.setattr(preflight.pwd, "getpwnam", lambda name: SimpleNamespace(
        pw_uid=1001 if name == "gvai-api" else 1002,
        pw_gid=1001 if name == "gvai-api" else 1002,
    ))
    return preflight, files, commands, baseline


def test_no_baseline_is_always_no_go_and_no_deployment_grant(healthy_inventory):
    module, *_ = healthy_inventory
    report = module.collect()
    assert report["checks"]["protected_baseline_matches"] is False
    assert report["automated_checks_pass"] is False
    assert report["deployment_authorized"] is False


def test_complete_inventory_remains_manual_approval_gated(healthy_inventory):
    module, *_ = healthy_inventory
    report = module.collect(baseline="/reviewed")
    assert report["automated_checks_pass"] is True
    assert report["deployment_authorized"] is False
    assert "active_systemd_sandbox_and_credentials" in report["manual_gates_required"]


def test_shared_service_identity_is_no_go(healthy_inventory, monkeypatch):
    module, *_ = healthy_inventory
    monkeypatch.setattr(module.pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    report = module.collect(baseline="/reviewed")
    assert report["checks"]["service_account_separation"] is False
    assert report["automated_checks_pass"] is False


def test_prepared_secret_metadata_failure_is_no_go(healthy_inventory, monkeypatch):
    module, files, commands, _ = healthy_inventory
    commands["listeners"] = "\n".join(
        f"LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*" for port in (5432, 8080, 8443)
    )
    monkeypatch.setattr(module.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1002))
    monkeypatch.setattr(module, "path_check", lambda path, *_args, **_kwargs:
                        str(path) != "/etc/gvai-runtime/runtime.json")
    report = module.collect(prepared=True, baseline="/reviewed")
    assert report["checks"]["custody_runtime.json"] is False
    assert report["automated_checks_pass"] is False
    assert "private" not in json.dumps(report["evidence"])

@pytest.mark.parametrize("condition", ["host", "os", "pid1", "firewall", "listener", "policy", "memory", "account"])
def test_each_uncertain_boundary_fails_closed(healthy_inventory, monkeypatch, condition):
    module, files, commands, baseline = healthy_inventory
    if condition in {"host", "os", "pid1"}:
        files[{"host": "/etc/hostname", "os": "/usr/lib/os-release", "pid1": "/proc/1/comm"}[condition]] = b"unexpected"
    elif condition == "firewall":
        commands["firewall"] = None
    elif condition == "listener":
        commands["listeners"] = "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*"
    elif condition == "policy":
        monkeypatch.setattr(module, "load_baseline", lambda _path: {**baseline, "policy_tree_sha256": "b" * 64})
    elif condition == "memory":
        files["/proc/meminfo"] = b"MemAvailable: 1 kB"
    elif condition == "account":
        monkeypatch.setattr(module, "account_check", lambda _name: False)
    report = module.collect(baseline="/reviewed")
    assert report["automated_checks_pass"] is False
    assert report["deployment_authorized"] is False
    assert "unexpected" not in json.dumps(report)


def test_unexpected_top_level_failure_is_redacted(preflight, monkeypatch, capsys):
    def fail(**_kwargs):
        raise RuntimeError("private-host-password")

    monkeypatch.setattr(preflight, "collect", fail)
    assert preflight.main([]) == 1
    assert json.loads(capsys.readouterr().out) == {
        "error": "host_preflight_unavailable", "deployment_authorized": False,
    }


def test_lab_inventory_preserves_policy_without_inventing_test_profiles(healthy_inventory, monkeypatch):
    module, files, _, _ = healthy_inventory
    files["/etc/hostname"] = b"gvai-safety-lab-01\n"
    monkeypatch.setattr(Path, "read_text", lambda _path: "ubuntu-existing-profile (enforce)\n")
    report = module.collect(target=module.LAB_TARGET, baseline="/lab-reviewed")
    assert report["automated_checks_pass"] is True
    assert report["target"] == module.LAB_TARGET
    assert "protected_profiles_enforcing" not in report["checks"]
    assert report["checks"]["restricted_unprivileged_userns"] is True
    assert report["checks"]["protected_baseline_matches"] is True
    assert report["deployment_authorized"] is False
    assert "cloud_firewall_review" in report["manual_gates_required"]
    test_report = module.collect(baseline="/test-reviewed")
    assert test_report["checks"]["protected_profiles_enforcing"] is False
    assert test_report["checks"]["target_hostname"] is False


@pytest.mark.parametrize("condition", ["hostname", "userns", "missing_userns", "firewall", "baseline", "profiles"])
def test_lab_uncertain_host_boundaries_remain_no_go(healthy_inventory, monkeypatch, condition):
    module, files, commands, baseline = healthy_inventory
    files["/etc/hostname"] = b"gvai-safety-lab-01\n"
    if condition == "hostname":
        files["/etc/hostname"] = b"gvai-safety-test-01\n"
    elif condition == "userns":
        files["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"] = b"0\n"
    elif condition == "missing_userns":
        del files["/proc/sys/kernel/apparmor_restrict_unprivileged_userns"]
    elif condition == "firewall":
        commands["firewall"] = "Status: inactive\n"
    elif condition == "baseline":
        monkeypatch.setattr(module, "load_baseline", lambda _path: {**baseline, "loaded_profiles_sha256": "b" * 64})
    elif condition == "profiles":
        def unavailable(_path):
            raise OSError("private policy details")
        monkeypatch.setattr(Path, "read_text", unavailable)
    report = module.collect(target=module.LAB_TARGET, baseline="/lab-reviewed")
    assert report["automated_checks_pass"] is False
    assert report["deployment_authorized"] is False
    assert "private policy details" not in json.dumps(report)


def test_lab_missing_packages_are_inventory_evidence_not_discovery_blockers(healthy_inventory, monkeypatch):
    module, files, commands, _ = healthy_inventory
    files["/etc/hostname"] = b"gvai-safety-lab-01\n"
    monkeypatch.setattr(module.shutil, "which", lambda _name, **_kwargs: None)
    report = module.collect(target=module.LAB_TARGET, baseline="/lab-reviewed")
    assert report["automated_checks_pass"] is True
    assert report["evidence"]["packages_available"] == {"nginx": False, "psql": False, "openssl": False}
    commands["listeners"] = "\n".join(
        f"LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*" for port in (5432, 8080, 8443)
    )
    report = module.collect(target=module.LAB_TARGET, prepared=True, baseline="/lab-reviewed")
    assert report["checks"]["staging_packages_available"] is False
    assert report["automated_checks_pass"] is False


def test_target_selection_is_explicit_and_defaults_to_test01(preflight, monkeypatch, capsys):
    calls = []
    def collect(**kwargs):
        calls.append(kwargs)
        return {"automated_checks_pass": False, "deployment_authorized": False}
    monkeypatch.setattr(preflight, "collect", collect)
    assert preflight.main([]) == 1
    assert preflight.main(["--target", preflight.LAB_TARGET, "--baseline", "/lab-reviewed"]) == 1
    assert calls[0]["target"] == preflight.TARGET
    assert calls[1]["target"] == preflight.LAB_TARGET
    with pytest.raises(SystemExit) as error:
        preflight.main(["--target", "unapproved"])
    assert error.value.code == 2
    capsys.readouterr()


def test_collect_rejects_unapproved_target(preflight):
    with pytest.raises(ValueError, match="Unsupported target"):
        preflight.collect(target="unapproved")


def test_lab_prepared_success_still_requires_manual_gates(healthy_inventory, monkeypatch):
    module, files, commands, _ = healthy_inventory
    files["/etc/hostname"] = b"gvai-safety-lab-01\n"
    commands["listeners"] = "\n".join(
        f"LISTEN 0 128 127.0.0.1:{port} 0.0.0.0:*" for port in (5432, 8080, 8443)
    )
    monkeypatch.setattr(module.grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=1002))
    monkeypatch.setattr(module, "path_check", lambda *_args, **_kwargs: True)
    report = module.collect(target=module.LAB_TARGET, prepared=True, baseline="/lab-reviewed")
    assert report["phase"] == "prepared"
    assert report["automated_checks_pass"] is True
    assert report["deployment_authorized"] is False
    assert "operator_custody_and_acl_review" in report["manual_gates_required"]
    assert "private_mtls_and_failure_drills" in report["manual_gates_required"]
    assert module.collect(target=module.LAB_TARGET, prepared=True)["automated_checks_pass"] is False


@pytest.mark.parametrize("resource,delta,expected", [
    ("disk", -1, False), ("disk", 0, True),
    ("memory", -1, False), ("memory", 0, True),
])
def test_lab_exact_resource_headroom_boundaries(healthy_inventory, monkeypatch, resource, delta, expected):
    module, files, _, _ = healthy_inventory
    files["/etc/hostname"] = b"gvai-safety-lab-01\n"
    if resource == "disk":
        monkeypatch.setattr(module.shutil, "disk_usage", lambda _path: SimpleNamespace(free=5 * 1024**3 + delta))
    else:
        files["/proc/meminfo"] = f"MemAvailable: {2 * 1024**2 + delta} kB\n".encode()
    report = module.collect(target=module.LAB_TARGET, baseline="/lab-reviewed")
    assert report["checks"][resource + "_headroom"] is expected
    assert report["automated_checks_pass"] is expected


def test_package_observations_use_only_system_search_path(healthy_inventory, monkeypatch):
    module, *_ = healthy_inventory
    calls = []
    def which(name, *, path):
        calls.append((name, path))
        return "/usr/bin/" + name
    monkeypatch.setattr(module.shutil, "which", which)
    module.collect()
    assert calls == [
        (name, "/usr/sbin:/usr/bin:/sbin:/bin") for name in ("nginx", "psql", "openssl")
    ]


def test_absent_experiment_units_are_fingerprinted_without_reading_files(preflight, monkeypatch):
    monkeypatch.setattr(preflight, "required_command", lambda _name:
        "LoadState=not-found\nActiveState=inactive\nSubState=dead\nMainPID=0\nFragmentPath=\nDropInPaths=\n")
    def unexpected_read(_path):
        pytest.fail("Absent units must not invent files.")
    monkeypatch.setattr(preflight, "read_regular", unexpected_read)
    assert len(preflight.unit_fingerprint("worker")) == 64
    assert preflight.unit_fingerprint("worker") == preflight.unit_fingerprint("bwrap")
