#!/usr/bin/env python3
"""Idempotent, reversible STAGING of STOP-gate files for Lab-01 (files only).

This tool only copies files and creates directories. It never starts or enables a
service, never runs systemctl/useradd/apparmor_parser, never touches existing
gvai-api/proxy/operator files except to ADD the API drop-in, and never handles
secret material (the downstream credential and key seeds are provisioned by hand).

Subcommands: plan | apply | verify | backup-verify | rollback
Default is a dry run; `apply` and `rollback` require --execute. --root prefixes all
target paths (used for Cloud tests with a temporary root).
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_REL = "var/lib/gvai-stage/stop_gate_manifest.json"

# (source relative to deploy/stop_gate, target absolute path, mode)
FILES = [
    ("gvai-stop-gate.service", "/etc/systemd/system/gvai-stop-gate.service", 0o644),
    ("gvai-stop-gate.socket", "/etc/systemd/system/gvai-stop-gate.socket", 0o644),
    ("gvai-protected-backend.service", "/etc/systemd/system/gvai-protected-backend.service", 0o644),
    ("gvai-protected-backend.socket", "/etc/systemd/system/gvai-protected-backend.socket", 0o644),
    ("gvai-stop-gate.sysusers", "/etc/sysusers.d/gvai-stop-gate.conf", 0o644),
    ("gvai-advisory-stop-gate.conf", "/etc/systemd/system/gvai-advisory.service.d/stop-gate.conf", 0o644),
    ("apparmor/gvai-stop-gate", "/etc/apparmor.d/gvai-stop-gate.staged", 0o644),
    ("apparmor/gvai-protected-backend", "/etc/apparmor.d/gvai-protected-backend.staged", 0o644),
    ("gate.json.example", "/etc/gvai-stop-gate/gate.json.example", 0o640),
    ("backend.json.example", "/etc/gvai-backend/backend.json.example", 0o640),
]
# Directories created (never removed unless empty and created by us).
DIRS = [
    ("/etc/systemd", 0o755),
    ("/etc/systemd/system", 0o755),
    ("/etc/sysusers.d", 0o755),
    ("/etc/apparmor.d", 0o755),
    ("/etc/gvai-stop-gate", 0o750),
    ("/etc/gvai-backend", 0o750),
    ("/etc/systemd/system/gvai-advisory.service.d", 0o755),
]
# Never overwritten or removed by this tool.
FORBIDDEN_TARGETS = ("/etc/gvai-runtime", "/etc/gvai-operator", "/etc/gvai-ingress",
                     "/var/lib/gvai-operator", "/etc/gvai-backend/downstream.cred",
                     "/var/lib/gvai-stop-gate/gate_key.seed")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        h.update(fh.read())
    return h.hexdigest()


def target(root, path):
    assert path not in FORBIDDEN_TARGETS and not path.startswith(FORBIDDEN_TARGETS[:4])
    return os.path.join(root, path.lstrip("/"))


def load_manifest(root):
    path = os.path.join(root, MANIFEST_REL)
    if os.path.exists(path):
        with open(path) as fh:
            return json.load(fh)
    return {"version": 1, "created_dirs": [], "files": {}}


def save_manifest(root, manifest):
    path = os.path.join(root, MANIFEST_REL)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def backup_dir(root):
    return os.path.join(root, "var/lib/gvai-stage/stop_gate_backup")


def plan(root):
    actions = []
    for rel, dest, _ in FILES:
        src = os.path.join(HERE, rel)
        want = sha256(src)
        dst = target(root, dest)
        if not os.path.exists(dst):
            actions.append({"action": "create", "path": dest})
        elif sha256(dst) == want:
            actions.append({"action": "unchanged", "path": dest})
        else:
            actions.append({"action": "replace_with_backup", "path": dest})
    return actions


def apply(root, execute):
    actions = plan(root)
    if not execute:
        return actions
    manifest = load_manifest(root)
    for path, mode in DIRS:
        real = target(root, path)
        if not os.path.isdir(real):
            os.makedirs(real, mode=mode)
            os.chmod(real, mode)
            if path not in manifest["created_dirs"]:
                manifest["created_dirs"].append(path)
            save_manifest(root, manifest)
    for rel, dest, mode in FILES:
        src, dst = os.path.join(HERE, rel), target(root, dest)
        want = sha256(src)
        if os.path.exists(dst) and sha256(dst) == want:
            continue
        entry = manifest["files"].get(dest, {})
        if os.path.exists(dst) and "backup" not in entry and not entry.get("created"):
            bpath = os.path.join(backup_dir(root), dest.lstrip("/").replace("/", "__"))
            os.makedirs(backup_dir(root), mode=0o700, exist_ok=True)
            shutil.copy2(dst, bpath)
            entry = {"created": False, "backup": bpath, "backup_sha256": sha256(bpath)}
        elif not os.path.exists(dst):
            entry = {"created": True}
        manifest["files"][dest] = entry
        save_manifest(root, manifest)  # record intent before touching the target
        tmp = dst + ".stage-tmp"
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        os.replace(tmp, dst)
        entry["sha256"] = want
        save_manifest(root, manifest)
    manifest["applied_at"] = int(time.time())
    save_manifest(root, manifest)
    return actions


def verify(root):
    results = []
    for rel, dest, mode in FILES:
        dst = target(root, dest)
        ok = os.path.exists(dst) and sha256(dst) == sha256(os.path.join(HERE, rel))
        ok = ok and (os.stat(dst).st_mode & 0o777) == mode
        results.append({"id": f"staged:{dest}", "ok": bool(ok)})
    for path, _ in DIRS:
        results.append({"id": f"dir:{path}", "ok": os.path.isdir(target(root, path))})
    return results


def backup_verify(root):
    manifest = load_manifest(root)
    results = []
    for dest, entry in manifest["files"].items():
        if entry.get("backup"):
            ok = os.path.exists(entry["backup"]) and sha256(entry["backup"]) == entry["backup_sha256"]
            results.append({"id": f"backup:{dest}", "ok": bool(ok)})
    return results


def rollback(root, execute):
    manifest = load_manifest(root)
    actions = []
    for dest, entry in sorted(manifest["files"].items()):
        dst = target(root, dest)
        if entry.get("created"):
            actions.append({"action": "remove", "path": dest})
            if execute and os.path.exists(dst):
                os.remove(dst)
        elif entry.get("backup"):
            if execute and sha256(entry["backup"]) != entry["backup_sha256"]:
                raise SystemExit(f"backup for {dest} fails its hash check; refusing to roll back")
            actions.append({"action": "restore", "path": dest})
            if execute:
                shutil.copy2(entry["backup"], dst)
    for path in sorted(manifest["created_dirs"], reverse=True):
        real = target(root, path)
        if os.path.isdir(real) and not os.listdir(real):
            actions.append({"action": "rmdir", "path": path})
            if execute:
                os.rmdir(real)
    if execute:
        mpath = os.path.join(root, MANIFEST_REL)
        if os.path.exists(mpath):
            os.remove(mpath)
    return actions


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "apply", "verify", "backup-verify", "rollback"))
    parser.add_argument("--root", default="/")
    parser.add_argument("--execute", action="store_true", help="actually change files (default: dry run)")
    args = parser.parse_args(argv)
    if args.command == "plan":
        out = plan(args.root)
    elif args.command == "apply":
        out = apply(args.root, args.execute)
    elif args.command == "rollback":
        out = rollback(args.root, args.execute)
    elif args.command == "verify":
        out = verify(args.root)
    else:
        out = backup_verify(args.root)
    print(json.dumps(out, indent=2))
    if args.command in ("verify", "backup-verify"):
        return 0 if all(r["ok"] for r in out) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
