"""Read-only Ubuntu staging checks; output fixed labels and non-secret evidence."""

import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess


TARGET = "gvai-safety-test-01"
COMMANDS = {
    "systemd": ("systemd-analyze", "--version"),
    "apparmor": ("aa-status", "--enabled"),
    "firewall": ("ufw", "status", "verbose"),
    "listeners": ("ss", "-H", "-lnt"),
    "worker": ("systemctl", "show", "gvai-worker.service", "--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths"),
    "bwrap": ("systemctl", "show", "gvai-bwrap.service", "--property=LoadState,ActiveState,SubState,MainPID,FragmentPath,DropInPaths"),
}
MAX_BYTES = 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=MAX_BYTES):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Unsupported file.")
        chunks = []
        size = 0
        while size <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise ValueError("File exceeds bound.")
        return data
    finally:
        os.close(descriptor)


def command(name):
    """Only fixed observation commands; never relay command output or exceptions."""
    try:
        result = subprocess.run(
            COMMANDS[name], capture_output=True, timeout=10,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": "cat"},
        )
        if result.returncode or len(result.stdout) > MAX_BYTES:
            return None
        return result.stdout.decode("utf-8", errors="strict")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def policy_fingerprint(root=Path("/etc/apparmor.d")):
    """Hash all policy/include bytes and metadata; no policy text in output."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Policy tree unavailable.")
    info = root.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("Policy directory custody invalid.")
    entries = []
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        relative = str(path.relative_to(root))
        if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
            raise ValueError("Policy custody unverified.")
        if path.is_symlink():
            # Enabled/disabled links are fingerprinted, but never followed.
            if not path.resolve(strict=True).is_relative_to(root.resolve()):
                raise ValueError("External policy link needs separate review.")
            data = os.readlink(path).encode()
        elif stat.S_ISREG(info.st_mode):
            data = read_regular(path)
        elif stat.S_ISDIR(info.st_mode):
            data = b"directory"
        else:
            raise ValueError("Unexpected policy entry.")
        entries.append((relative, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), digest(data)))
    if not entries:
        raise ValueError("Empty policy tree.")
    return digest(json.dumps(entries, separators=(",", ":")).encode())


def listener_check(text, prepared):
    if text is None:
        return False
    staging = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            return False
        endpoint = fields[3]
        host, separator, port = endpoint.rpartition(":")
        if not separator or not port.isdecimal():
            return False
        if port in {"5432", "8080", "8443"}:
            if host not in {"127.0.0.1", "[::1]", "::1"}:
                return False
            staging.setdefault(port, []).append(host)
    if prepared:
        return set(staging) == {"5432", "8080", "8443"}
    # Do not take over an occupied port, even if it already binds loopback.
    return not staging


def account_check(name):
    try:
        account = pwd.getpwnam(name)
        group = grp.getgrgid(account.pw_gid)
        supplementary = [entry.gr_name for entry in grp.getgrall() if name in entry.gr_mem]
        return (
            account.pw_uid > 0 and group.gr_name == name
            and account.pw_shell in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}
            and set(supplementary) <= {name}
        )
    except KeyError:
        return False


def path_check(path, mode, uid=0, gid=0, directory=False):
    try:
        path = Path(path)
        for parent in (path, *path.parents):
            if parent.is_symlink():
                return False
            info = parent.lstat()
            if parent != path and (info.st_uid != 0 or info.st_mode & 0o022):
                return False
        info = path.lstat()
        return (
            info.st_uid == uid and info.st_gid == gid and stat.S_IMODE(info.st_mode) == mode
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        )
    except (OSError, ValueError):
        return False


def protected_snapshot(profiles):
    return {
        "policy_tree_sha256": policy_fingerprint(),
        "loaded_profiles_sha256": digest("\n".join(sorted(profiles.splitlines())).encode()),
        "worker_state_sha256": unit_fingerprint("worker"),
        "bwrap_state_sha256": unit_fingerprint("bwrap"),
    }


def unit_fingerprint(name):
    output = required_command(name)
    properties = dict(line.split("=", 1) for line in output.splitlines())
    if set(properties) != {"LoadState", "ActiveState", "SubState", "MainPID", "FragmentPath", "DropInPaths"}:
        raise ValueError("Unit evidence incomplete.")
    contents = []
    for path in (properties["FragmentPath"] + " " + properties["DropInPaths"]).split():
        info = Path(path).lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Unit custody invalid.")
        contents.append((path, digest(read_regular(path))))
    return digest(json.dumps((sorted(properties.items()), contents), separators=(",", ":")).encode())


def required_command(name):
    output = command(name)
    if output is None:
        raise ValueError("Observation unavailable.")
    return output


def load_baseline(path):
    info = Path(path).lstat()
    if not path_check(path, 0o600, uid=info.st_uid, gid=info.st_gid) or info.st_uid != 0:
        raise ValueError("Baseline custody invalid.")
    data = json.loads(read_regular(path, 16384))
    required = {"policy_tree_sha256", "loaded_profiles_sha256", "worker_state_sha256", "bwrap_state_sha256"}
    if (
        type(data) is not dict or set(data) != required
        or any(type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None for value in data.values())
    ):
        raise ValueError("Baseline schema invalid.")
    return data


def collect(*, prepared=False, baseline=None):
    checks = {}
    evidence = {}

    def check(label, operation):
        try:
            checks[label] = operation() is True
        except (OSError, ValueError, KeyError, TypeError):
            checks[label] = False

    check("root_observer", lambda: os.geteuid() == 0)
    check("target_hostname", lambda: read_regular("/etc/hostname", 256).decode().strip() == TARGET)
    check("ubuntu_24_04", lambda: {"ID=ubuntu", 'VERSION_ID="24.04"'} <= set(
        read_regular("/usr/lib/os-release", 16384).decode().splitlines()))
    check("systemd_pid1", lambda: read_regular("/proc/1/comm", 256).strip() == b"systemd")
    check("systemd_version", lambda: int(required_command("systemd").split()[1]) >= 255)
    check("apparmor_enabled", lambda: command("apparmor") is not None)
    profiles = None
    try:
        profiles = Path("/sys/kernel/security/apparmor/profiles").read_text()
        check("protected_profiles_enforcing", lambda: all(
            name + " (enforce)" in profiles.splitlines() for name in ("gvai-worker", "gvai-bwrap")))
        evidence["protected"] = protected_snapshot(profiles)
        checks["protected_snapshot_available"] = True
    except (OSError, ValueError):
        checks["protected_snapshot_available"] = False
        checks["protected_profiles_enforcing"] = False
    check("protected_baseline_matches", lambda: baseline is not None
          and evidence.get("protected") == load_baseline(baseline))
    firewall = command("firewall")
    checks["host_firewall_active"] = firewall is not None and firewall.startswith("Status: active\n")
    if firewall is not None:
        evidence["firewall_sha256"] = digest(firewall.encode())
    listeners = command("listeners")
    check("staging_listener_topology", lambda: listener_check(listeners, prepared))
    if listeners is not None:
        evidence["listeners_sha256"] = digest(listeners.encode())
    check("disk_headroom", lambda: shutil.disk_usage("/").free >= 5 * 1024**3)
    check("memory_headroom", lambda: int(dict(
        line.split(":", 1) for line in read_regular("/proc/meminfo", 16384).decode().splitlines()
    )["MemAvailable"].split()[0]) >= 2 * 1024**2)
    check("cgroup_v2", lambda: Path("/sys/fs/cgroup/cgroup.controllers").is_file())
    for name in ("gvai-api", "gvai-proxy"):
        check(name + "_account", lambda name=name: account_check(name))
    check("service_account_separation", lambda:
          pwd.getpwnam("gvai-api").pw_uid != pwd.getpwnam("gvai-proxy").pw_uid
          and pwd.getpwnam("gvai-api").pw_gid != pwd.getpwnam("gvai-proxy").pw_gid)
    if prepared:
        for path, mode, directory in (
            ("/etc/gvai-runtime", 0o700, True),
            ("/etc/gvai-runtime/runtime.json", 0o400, False),
            ("/etc/systemd/system/gvai-advisory.service", 0o644, False),
            ("/etc/systemd/system/gvai-ingress.service", 0o644, False),
        ):
            check("custody_" + Path(path).name, lambda path=path, mode=mode, directory=directory:
                  path_check(path, mode, directory=directory))
        try:
            proxy_gid = grp.getgrnam("gvai-proxy").gr_gid
            check("proxy_secret_directory", lambda: path_check(
                "/etc/gvai-ingress", 0o750, gid=proxy_gid, directory=True))
            for name in ("server-chain.pem", "server-key.pem", "client-ca.pem"):
                check("proxy_custody_" + name, lambda name=name: path_check(
                    "/etc/gvai-ingress/" + name, 0o640, gid=proxy_gid))
        except KeyError:
            checks["proxy_secret_directory"] = False
    # Never grant deployment readiness based on metadata alone.
    return {
        "version": 1, "phase": "prepared" if prepared else "inventory",
        "automated_checks_pass": all(checks.values()),
        "deployment_authorized": False,
        "checks": checks, "evidence": evidence,
        "manual_gates_required": [
            "founder_approval", "experiment_idle_window", "cloud_firewall_review",
            "operator_custody_and_acl_review", "postgres_identity_and_integrity",
            "active_systemd_sandbox_and_credentials", "private_mtls_and_failure_drills",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only redacted GVAI test-host inventory; never deployment authorization.")
    parser.add_argument("--prepared", action="store_true", help="Check installed staging metadata and loopback listeners.")
    parser.add_argument("--baseline", help="Founder-reviewed root-owned mode0600 protected fingerprint JSON.")
    args = parser.parse_args(argv)
    try:
        report = collect(prepared=args.prepared, baseline=args.baseline)
        print(json.dumps(report, sort_keys=True))
        return 0 if report["automated_checks_pass"] else 1
    except Exception:
        print('{"error":"host_preflight_unavailable","deployment_authorized":false}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
