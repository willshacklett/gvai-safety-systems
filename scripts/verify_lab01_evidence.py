#!/usr/bin/env python3
"""Verify Lab-01 read-only evidence on a GitHub-hosted runner (never on Lab-01).

Fail closed: any schema violation, secret-looking content, mutation claim, security-validation
claim, or failed check exits non-zero. Prints a Markdown summary for the job summary.
"""

import argparse
import hashlib
import json
import re
import sys

SCHEMA = "gvai.lab01.readonly_evidence.v1"
MAX_BYTES = 256 * 1024
REQUIRED_CHECKS = (
    "identity.non_root", "identity.no_privileged_groups", "identity.no_capabilities",
    "identity.no_new_privs", "host.ubuntu_2404", "network.unexpected_public_listeners",
    "protected.denied:/etc/gvai-stop-gate", "protected.denied:/var/lib/gvai-stop-gate",
    "protected.denied:/etc/gvai-backend", "protected.denied:/etc/gvai-operator",
    "host.firewall_ufw_and_do_cloud_firewall", "host.apparmor_loaded_profiles_and_enforce_state",
)
STATUSES = {"pass", "fail", "not_collected"}
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{16,}\b"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key|seed)\s*[:=]\s*\S{6,}"),
)


class EvidenceError(Exception):
    pass


def verify(raw):
    if len(raw) > MAX_BYTES:
        raise EvidenceError("evidence too large")
    text = raw.decode("utf-8")
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise EvidenceError("secret-looking content in evidence")
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise EvidenceError(f"invalid JSON: {exc}")
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise EvidenceError("wrong schema")
    if data.get("mutated_host") is not False:
        raise EvidenceError("evidence must assert mutated_host=false")
    if data.get("host_level_security_validated") is not False:
        raise EvidenceError("evidence must not claim host-level security validated")
    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise EvidenceError("no checks")
    by_id = {}
    for item in checks:
        if not isinstance(item, dict) or set(item) != {"id", "status", "detail"}:
            raise EvidenceError("malformed check entry")
        if item["status"] not in STATUSES:
            raise EvidenceError(f"bad status for {item['id']}")
        if item["id"] in by_id:
            raise EvidenceError(f"duplicate check {item['id']}")
        by_id[item["id"]] = item
    missing = [c for c in REQUIRED_CHECKS if c not in by_id]
    if missing:
        raise EvidenceError("missing required checks: " + ", ".join(missing))
    failed = sorted(i for i, c in by_id.items() if c["status"] == "fail")
    if failed or data.get("overall") != "partial_pass" or data.get("failed_ids") != []:
        raise EvidenceError("failed checks: " + ", ".join(failed or ["overall!=partial_pass"]))
    for cid in REQUIRED_CHECKS:
        if cid.startswith(("identity.", "protected.", "host.ubuntu")) and by_id[cid]["status"] != "pass":
            raise EvidenceError(f"required check not passing: {cid}")
    return data


def summary(data, digest):
    counts = {s: sum(1 for c in data["checks"] if c["status"] == s) for s in sorted(STATUSES)}
    lines = ["## Lab-01 read-only validation", "",
             f"- evidence sha256: `{digest}`", f"- overall: **{data['overall']}**",
             f"- counts: {counts}", "- host-level security validated: **NO**",
             "- host mutated: **no**", "", "| check | status |", "|---|---|"]
    lines += [f"| `{c['id']}` | {c['status']} |" for c in data["checks"]]
    lines += ["", "`not_collected` rows need root or the DigitalOcean API and are NOT evidence of safety."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("--summary", help="write Markdown summary here")
    args = ap.parse_args(argv)
    with open(args.evidence, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)
    try:
        data = verify(raw)
    except (EvidenceError, UnicodeDecodeError) as exc:
        print(f"::error::Lab-01 evidence rejected: {exc}")
        return 1
    text = summary(data, hashlib.sha256(raw).hexdigest())
    if args.summary:
        with open(args.summary, "a") as fh:
            fh.write(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
