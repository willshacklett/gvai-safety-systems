"""Host-isolation acceptance checks for the external STOP gate deployment.

Run as root on the target host (or in a disposable harness). It executes
probes AS the commercial API user and verifies that user cannot read authority
keys, change anchor/store state, signal the gate or backend, reach the control
or notice sockets, or obtain the protected downstream credential, and that the
gate/backend processes carry the expected hardening.

Write probes only attempt O_APPEND opens, creation of a probe-named file in a
protected directory, and rename of the anchor; each is expected to fail. If a
probe ever succeeds the check fails (the probe's own file is removed, but a
successful anchor rename must be repaired by the operator: treat as a breach).

Passing in a Cloud container proves UID/DAC separation and the process
attributes that harness sets. It does NOT prove systemd sandboxing, AppArmor,
cgroup/network confinement, or any property of Lab-01. Only a run on the host
with its real layout is evidence about that host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import subprocess
import sys
from typing import Mapping, Optional

_PROBE = r'''
import errno, hashlib, json, os, socket, sys

L = json.loads(sys.argv[1])
out = []

def rec(cid, ok, detail):
    out.append({"id": cid, "ok": bool(ok), "detail": detail})

def denied(cid, fn):
    try:
        fn()
    except OSError as exc:
        name = errno.errorcode.get(exc.errno, str(exc.errno))
        if name in ("EACCES", "EPERM"):
            rec(cid, True, name)
        else:
            rec(cid, False, "unexpected_errno_" + name)
        return
    rec(cid, False, "operation_succeeded")

F = L["files"]
for key in ("gate_seed", "anchor", "store"):
    p = F[key]
    denied("read_" + key, lambda p=p: open(p, "rb").read(1))
    denied("append_" + key, lambda p=p: os.close(os.open(p, os.O_WRONLY | os.O_APPEND)))
denied("read_backend_credential", lambda: open(F["backend_credential"], "rb").read(1))

def create_in(d):
    path = os.path.join(d, ".gvai-acceptance-probe")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.unlink(path)

def replace_anchor():
    d = os.path.dirname(F["anchor"])
    os.rename(F["anchor"], os.path.join(d, "anchor.json.moved"))

denied("create_in_gate_state_dir", lambda: create_in(L["dirs"]["gate_state"]))
denied("rename_anchor", replace_anchor)
denied("list_gate_state_dir", lambda: os.listdir(L["dirs"]["gate_state"]))
denied("list_backend_credential_dir", lambda: os.listdir(L["dirs"]["backend_credential"]))

def connect(path):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    try:
        s.connect(path)
    finally:
        s.close()

denied("connect_gate_control_socket", lambda: connect(L["sockets"]["gate_control"]))
denied("connect_backend_notice_socket", lambda: connect(L["sockets"]["backend_notice"]))

for role in ("gate", "backend"):
    pid = L["pids"][role]
    denied("signal0_" + role, lambda pid=pid: os.kill(pid, 0))
    denied("read_mem_" + role, lambda pid=pid: open("/proc/%d/mem" % pid, "rb").read(1))
    denied("read_environ_" + role, lambda pid=pid: open("/proc/%d/environ" % pid, "rb").read(1))
    denied("list_fds_" + role, lambda pid=pid: os.listdir("/proc/%d/fd" % pid))

def exchange(path, message):
    from multiprocessing.connection import Client
    c = Client(path, family="AF_UNIX")
    try:
        c.send_bytes(json.dumps(message).encode())
        if not c.poll(3):
            return None
        return json.loads(c.recv_bytes(65536).decode())
    finally:
        c.close()

try:
    r = exchange(L["sockets"]["gate_service"], {"type": "status"})
    rec("positive_gate_service_reachable", isinstance(r, dict) and r.get("ok") is True, "reply")
    r = exchange(L["sockets"]["gate_service"], {"type": "command", "envelope": {}})
    rec("gate_service_refuses_command", isinstance(r, dict) and r.get("reason") == "request_not_permitted", str(r and r.get("reason")))
    r = exchange(L["sockets"]["backend_service"], {"type": "notice"})
    rec("backend_service_refuses_notice", isinstance(r, dict) and r.get("reason") == "request_not_permitted", str(r and r.get("reason")))
except Exception as exc:
    rec("positive_gate_service_reachable", False, type(exc).__name__)

hashes = set(L.get("secret_sha256", []))
leaked = []
budget = [4000]
def scan(root, depth):
    if depth > 6 or budget[0] <= 0:
        return
    try:
        entries = os.listdir(root)
    except OSError:
        return
    for name in entries:
        p = os.path.join(root, name)
        budget[0] -= 1
        if os.path.islink(p):
            continue
        if os.path.isdir(p):
            scan(p, depth + 1)
        else:
            try:
                with open(p, "rb") as fh:
                    data = fh.read(1 << 20)
            except OSError:
                continue
            if hashlib.sha256(data).hexdigest() in hashes:
                leaked.append(p)
for root in L.get("scan_roots", []):
    scan(root, 0)
rec("no_protected_secret_readable_by_api_user", not leaked, "readable_copy_found" if leaked else "none_found")

uid = os.getuid()
rec("api_user_not_root", uid != 0, "uid_nonzero" if uid else "root")
rec("api_user_matches_layout", uid == L["api_uid"], "uid_match")
groups = set(os.getgroups()) | {os.getgid()}
rec("api_user_not_in_gate_or_backend_groups", not (groups & set(L["forbidden_gids"])), "group_check")
print(json.dumps(out))
'''

_STATUS_FIELDS = ("NoNewPrivs", "CapEff", "CapBnd", "Uid", "Groups")


def parse_proc_status(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in _STATUS_FIELDS:
            out[key] = value.strip()
    return out


def evaluate_process_hardening(
    status: Mapping[str, str],
    expected_uid: int,
    apparmor: Optional[str] = None,
    expected_apparmor: Optional[str] = None,
) -> list:
    """Pure evaluation of /proc/<pid>/status fields (unit-testable)."""
    checks = []

    def add(cid, ok, detail):
        checks.append({"id": cid, "ok": bool(ok), "detail": detail})

    uids = status.get("Uid", "").split()
    add(
        "uid_all_equal_expected",
        bool(uids) and all(u == str(expected_uid) for u in uids) and expected_uid != 0,
        "Uid",
    )
    add("no_new_privs", status.get("NoNewPrivs") == "1", status.get("NoNewPrivs", "missing"))
    add("effective_caps_empty", "CapEff" in status and status["CapEff"].strip("0") == "", "CapEff")
    add("bounding_caps_empty", "CapBnd" in status and status["CapBnd"].strip("0") == "", "CapBnd")
    add("no_supplementary_groups", not status.get("Groups", "").split(), "Groups")
    if expected_apparmor is not None:
        add(
            "apparmor_profile_enforced",
            apparmor is not None and apparmor.startswith(expected_apparmor + " (enforce)"),
            "attr_current",
        )
    return checks


def _resolve_pid(spec) -> int:
    if isinstance(spec, int):
        return spec
    out = subprocess.run(
        ["systemctl", "show", "-p", "MainPID", "--value", str(spec)],
        capture_output=True, text=True, timeout=10,
    )
    pid = int(out.stdout.strip() or "0")
    if pid <= 0:
        raise RuntimeError("no_main_pid_for_" + str(spec))
    return pid


def _sha256_file(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read(1 << 20)).hexdigest()


def _run_as(user: str, argv: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["runuser", "-u", user, "--"] + argv, capture_output=True, text=True, timeout=60
    )


def run_acceptance(layout: Mapping[str, object], python: str = "/usr/bin/python3") -> dict:
    users = layout["users"]
    api, gate, backend = users["api"], users["gate"], users["backend"]
    api_uid = pwd.getpwnam(api).pw_uid
    gate_uid, backend_uid = pwd.getpwnam(gate).pw_uid, pwd.getpwnam(backend).pw_uid
    results = []

    def add(cid, ok, detail):
        results.append({"id": cid, "ok": bool(ok), "detail": detail})

    add("running_as_root", os.geteuid() == 0, "euid")
    add(
        "three_distinct_nonzero_uids",
        len({api_uid, gate_uid, backend_uid}) == 3 and 0 not in {api_uid, gate_uid, backend_uid},
        "uids",
    )
    for u in (api, gate, backend):
        add("nologin_shell_" + u, pwd.getpwnam(u).pw_shell.endswith(("nologin", "false")), "shell")

    files = layout["files"]
    secrets = []
    try:
        # Controls: the owner CAN read, so "denied" for the API user is meaningful.
        for key, owner in (
            ("gate_seed", gate), ("anchor", gate), ("store", gate), ("backend_credential", backend),
        ):
            r = _run_as(owner, [python, "-c", "import sys;open(sys.argv[1],'rb').read(1)", files[key]])
            add("control_owner_can_read_" + key, r.returncode == 0, "owner_read")
        secrets = [_sha256_file(files["gate_seed"]), _sha256_file(files["backend_credential"])]
    except Exception as exc:
        add("control_setup", False, type(exc).__name__)

    pids = {
        "gate": _resolve_pid(layout["pids"]["gate"]),
        "backend": _resolve_pid(layout["pids"]["backend"]),
    }
    probe_layout = {
        "files": files, "dirs": layout["dirs"], "sockets": layout["sockets"], "pids": pids,
        "secret_sha256": secrets, "scan_roots": layout.get("scan_roots", []),
        "api_uid": api_uid,
        "forbidden_gids": [pwd.getpwnam(gate).pw_gid, pwd.getpwnam(backend).pw_gid],
    }
    probe = _run_as(api, [python, "-I", "-c", _PROBE, json.dumps(probe_layout)])
    if probe.returncode != 0:
        add("api_probe_executed", False, "probe_failed:" + probe.stderr.strip()[-200:])
    else:
        results.extend(json.loads(probe.stdout))

    hardening = layout.get("hardening", {})
    for role, uid in (("gate", gate_uid), ("backend", backend_uid)):
        with open(f"/proc/{pids[role]}/status", "r", encoding="ascii") as fh:
            status = parse_proc_status(fh.read())
        aa = None
        try:
            with open(f"/proc/{pids[role]}/attr/current", "r") as fh:
                aa = fh.read().strip()
        except OSError:
            pass
        expected_aa = hardening.get("apparmor", {}).get(role)
        for c in evaluate_process_hardening(status, uid, apparmor=aa, expected_apparmor=expected_aa):
            results.append({"id": f"{role}_{c['id']}", "ok": c["ok"], "detail": c["detail"]})

    failed = [r["id"] for r in results if not r["ok"]]
    return {
        "passed": len(results) - len(failed),
        "failed": len(failed),
        "failed_ids": failed,
        "results": results,
        "all_passed": not failed,
        "scope": "uid_dac_and_process_attributes_only_unless_run_on_target_host",
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="STOP gate host-isolation acceptance")
    parser.add_argument("--layout", required=True)
    args = parser.parse_args(argv)
    with open(args.layout, "r", encoding="utf-8") as fh:
        report = run_acceptance(json.load(fh))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
