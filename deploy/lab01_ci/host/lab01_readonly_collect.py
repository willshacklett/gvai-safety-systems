#!/usr/bin/env python3
"""Lab-01 READ-ONLY evidence collector (stdlib only).

Install once, root-owned and not writable by the runner user (see bootstrap_lab01_ci.sh).
It runs as the unprivileged CI user and:

* never writes anywhere except the single --output file,
* never opens, reads, lists or executes anything under the protected STOP-authority paths
  (it only asks the kernel whether the CI user is *denied* access, via os.access),
* runs only fixed, allow-listed argv (no shell) with timeouts,
* fails closed: it exits non-zero if it runs as root/with capabilities/in a privileged group,
  or if the CI user can touch any protected path,
* never claims host-level security is validated: checks needing root are "not_collected".
"""

import argparse
import grp
import hashlib
import json
import os
import subprocess
import sys
import time

SCHEMA = "gvai.lab01.readonly_evidence.v1"

# STOP-authority and protected-workload paths. The CI user must have NO access to any of them.
PROTECTED_PATHS = (
    "/etc/gvai-stop-gate",
    "/var/lib/gvai-stop-gate",
    "/etc/gvai-backend",
    "/etc/gvai-runtime",
    "/etc/gvai-operator",
    "/var/lib/gvai-operator",
    "/etc/gvai-ingress",
    "/run/gvai-stop-gate",
    "/run/gvai-protected-backend",
)
FORBIDDEN_GROUPS = ("root", "sudo", "adm", "docker", "lxd", "disk", "shadow",
                    "gvai-gate", "gvai-backend", "gvai-operator", "gvai-api", "gvai-proxy")
UNITS = ("gvai-advisory", "gvai-ingress", "gvai-stop-gate", "gvai-protected-backend")
UNIT_PROPS = ("LoadState", "ActiveState", "SubState", "User", "NoNewPrivileges",
              "CapabilityBoundingSet", "ProtectSystem", "RestrictAddressFamilies")
STAGED_FILES = (
    "/etc/systemd/system/gvai-stop-gate.service",
    "/etc/systemd/system/gvai-protected-backend.service",
    "/etc/apparmor.d/gvai-stop-gate.staged",
    "/etc/apparmor.d/gvai-protected-backend.staged",
)
ALLOWED_PUBLIC_PORTS = {22, 80, 443}
LOOPBACK_HEX = ("0100007F", "00000000000000000000000001000000",
                "0000000000000000FFFF00000100007F")
COMMAND_TIMEOUT = 10
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "SYSTEMD_PAGER": ""}


def check(cid, status, detail):
    return {"id": cid, "status": status, "detail": detail}


def run_fixed(argv):
    """Run a fixed argv with a scrubbed environment; return (rc, stdout) or (None, reason)."""
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
                              env=SAFE_ENV, shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, type(exc).__name__
    return done.returncode, done.stdout[:20000]


def proc_status(root):
    fields = {}
    try:
        with open(os.path.join(root, "proc/self/status")) as fh:
            for line in fh:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
    except OSError:
        pass
    return fields


def _group_names():
    names = set()
    for gid in os.getgroups() + [os.getegid()]:
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            names.add(f"gid:{gid}")
    return names


def check_identity(root, euid=None, group_names=None):
    euid = os.geteuid() if euid is None else euid
    out = [check("identity.non_root", "pass" if euid != 0 else "fail", f"euid={euid}")]
    names = _group_names() if group_names is None else set(group_names)
    bad = sorted(names & set(FORBIDDEN_GROUPS))
    out.append(check("identity.no_privileged_groups", "fail" if bad else "pass",
                     "forbidden groups: " + ",".join(bad) if bad else "none"))
    st = proc_status(root)
    cap = st.get("CapEff")
    if cap is None:
        out.append(check("identity.no_capabilities", "fail", "CapEff unreadable (fail closed)"))
    else:
        out.append(check("identity.no_capabilities", "pass" if int(cap, 16) == 0 else "fail",
                         f"CapEff={cap}"))
    nnp = st.get("NoNewPrivs")
    out.append(check("identity.no_new_privs", "pass" if nnp == "1" else "fail",
                     f"NoNewPrivs={nnp}"))
    return out


def check_protected_paths(root):
    """The CI user must be denied on every protected path. Never opens or lists them."""
    out = []
    for path in PROTECTED_PATHS:
        real = os.path.join(root, path.lstrip("/"))
        if not os.path.lexists(real):
            out.append(check(f"protected.denied:{path}", "pass", "absent_or_not_traversable"))
            continue
        reachable = [name for name, flag in (("read", os.R_OK), ("write", os.W_OK),
                                             ("traverse", os.X_OK)) if os.access(real, flag)]
        out.append(check(f"protected.denied:{path}", "fail" if reachable else "pass",
                         "CI user has access: " + ",".join(reachable) if reachable else "denied"))
    return out


def check_os(root):
    values = {}
    try:
        with open(os.path.join(root, "etc/os-release")) as fh:
            for line in fh:
                k, _, v = line.strip().partition("=")
                values[k] = v.strip('"')
    except OSError:
        return [check("host.ubuntu_2404", "fail", "os-release unreadable")]
    ok = values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04"
    return [check("host.ubuntu_2404", "pass" if ok else "fail",
                  f"{values.get('ID')} {values.get('VERSION_ID')}")]


def parse_systemctl(text):
    props = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in UNIT_PROPS:
            props[key] = value
    return props


def check_units(runner=run_fixed):
    out = []
    for unit in UNITS:
        rc, text = runner(["systemctl", "show", f"{unit}.service",
                           "-p", ",".join(UNIT_PROPS), "--no-pager"])
        if rc != 0:
            out.append(check(f"unit.state:{unit}", "not_collected", f"systemctl rc={rc}"))
            continue
        # Report only: an unstaged/inactive STOP-gate unit is expected pre-activation.
        out.append(check(f"unit.state:{unit}", "pass",
                         json.dumps(parse_systemctl(text), sort_keys=True)))
    return out


def check_staged_files(root):
    out = []
    for path in STAGED_FILES:
        try:
            st = os.stat(os.path.join(root, path.lstrip("/")))
            out.append(check(f"staged.file:{path}", "pass",
                             f"mode={oct(st.st_mode & 0o7777)} uid={st.st_uid} size={st.st_size}"))
        except OSError:
            out.append(check(f"staged.file:{path}", "pass", "absent"))
    return out


def parse_listeners(text):
    """Parse /proc/net/tcp{,6}: sorted (address_hex, port) in LISTEN state."""
    found = set()
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) > 3 and parts[3] == "0A":
            addr, _, port = parts[1].rpartition(":")
            found.add((addr.upper(), int(port, 16)))
    return sorted(found)


def check_listeners(root):
    listeners = []
    for name in ("proc/net/tcp", "proc/net/tcp6"):
        try:
            with open(os.path.join(root, name)) as fh:
                listeners += parse_listeners(fh.read())
        except OSError:
            return [check("network.unexpected_public_listeners", "not_collected",
                          f"{name} unreadable")]
    unexpected = sorted({p for a, p in listeners if a not in LOOPBACK_HEX} - ALLOWED_PUBLIC_PORTS)
    return [check("network.unexpected_public_listeners", "fail" if unexpected else "pass",
                  f"non-loopback ports outside {sorted(ALLOWED_PUBLIC_PORTS)}: {unexpected}"
                  if unexpected else "none")]


def check_housekeeping(root):
    out = [check("host.reboot_required", "pass",
                 "yes" if os.path.exists(os.path.join(root, "var/run/reboot-required")) else "no")]
    try:
        st = os.statvfs(os.path.join(root, "var"))
        free_pct = round(100 * st.f_bavail / max(st.f_blocks, 1), 1)
        out.append(check("host.disk_free_percent", "pass" if free_pct >= 10 else "fail",
                         f"{free_pct}% free on /var"))
    except OSError:
        out.append(check("host.disk_free_percent", "not_collected", "statvfs failed"))
    return out


NOT_COLLECTED = (
    ("host.firewall_ufw_and_do_cloud_firewall", "requires root / DigitalOcean API; not collected"),
    ("host.apparmor_loaded_profiles_and_enforce_state", "requires root; not collected"),
    ("host.stop_gate_acceptance_run", "requires root; separate approved host-validation stage"),
    ("host.sshd_effective_config", "requires root; not collected"),
)


def collect(root="/", runner=run_fixed, euid=None, group_names=None, now=None):
    checks = []
    checks += check_identity(root, euid, group_names)
    checks += check_protected_paths(root)
    checks += check_os(root)
    checks += check_units(runner)
    checks += check_staged_files(root)
    checks += check_listeners(root)
    checks += check_housekeeping(root)
    checks += [check(cid, "not_collected", detail) for cid, detail in NOT_COLLECTED]
    failed = [c["id"] for c in checks if c["status"] == "fail"]
    return {
        "schema": SCHEMA,
        "collected_at_epoch": int(time.time() if now is None else now),
        "collector": "lab01_readonly_collect.py",
        "mutated_host": False,
        "host_level_security_validated": False,
        "overall": "fail" if failed else "partial_pass",
        "failed_ids": failed,
        "checks": checks,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", required=True, help="single evidence file to create (0600)")
    ap.add_argument("--root", default="/", help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    evidence = collect(root=args.root)
    body = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    print(f"overall={evidence['overall']} sha256={hashlib.sha256(body.encode()).hexdigest()}")
    return 1 if evidence["failed_ids"] else 0


if __name__ == "__main__":
    sys.exit(main())
