#!/usr/bin/env python3
"""Static security policy for the Lab-01 deployment pipeline. Fails closed (exit 1) on violations.

Scans .github/workflows/*.yml and deploy/lab01_ci/workflows_inactive/*.yml.inactive.
Legacy workflows (not lab01-*/pipeline-security) get warnings for hygiene gaps only; the
STOP-authority, self-hosted, and activation rules apply to every file.
"""

import glob
import os
import re
import sys

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACTIVE_GLOB = ".github/workflows/*.yml"
INACTIVE_GLOB = "deploy/lab01_ci/workflows_inactive/*.yml.inactive"
STRICT_RE = re.compile(r"(^|/)(lab01-[^/]*|pipeline-security)\.yml(\.inactive)?$")

STOP_AUTHORITY_TOKENS = (
    "/etc/gvai-stop-gate", "/var/lib/gvai-stop-gate", "/etc/gvai-backend", "/etc/gvai-runtime",
    "/etc/gvai-operator", "/var/lib/gvai-operator", "/etc/gvai-ingress", "gate_key", "downstream.cred",
    "trusted_anchor", "trusted-anchor", "stop_key", "arm_key", "gate.json", ".seed",
)
FORBIDDEN_ON_HOST = (
    re.compile(r"\bsudo\b"), re.compile(r"\bdocker\b"), re.compile(r"\bssh\b"),
    re.compile(r"\bsu\s+-"), re.compile(r"\bchmod\s+[0-7]*[67][0-7]{0,2}\s"),
    re.compile(r"\bsystemctl\b"), re.compile(r"\bcurl\b[^\n|]*\|\s*(ba)?sh"), re.compile(r"\beval\b"),
    re.compile(r"\bapt(-get)?\b"), re.compile(r"\bpip\b"),
)
FORBIDDEN_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment", "pull_request",
                      "pull_request_review", "push", "schedule", "repository_dispatch", "workflow_call"}
SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def load(path):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return text, yaml.safe_load(text)


def triggers(doc):
    on = doc.get("on", doc.get(True))
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {k: None for k in on}
    return on or {}


def self_hosted(job):
    runs = job.get("runs-on")
    labels = [runs] if isinstance(runs, str) else list(runs or [])
    return any(str(x) == "self-hosted" for x in labels) or not isinstance(runs, (str, list))


def check_file(path, text, doc, inactive):
    errors, warnings = [], []
    strict = bool(STRICT_RE.search(path))
    lab01 = os.path.basename(path).startswith("lab01-")
    name = os.path.relpath(path, ROOT)
    bucket = errors if strict else warnings

    if "permissions" not in doc:
        bucket.append(f"{name}: top-level permissions missing")
    if lab01 and doc.get("permissions") != {}:
        errors.append(f"{name}: lab01 workflows must set top-level `permissions: {{}}`")
    for tok in STOP_AUTHORITY_TOKENS:
        if tok in text:
            errors.append(f"{name}: references STOP-authority material `{tok}`")
    if re.search(r"\$\{\{\s*secrets\.", text) and lab01:
        errors.append(f"{name}: lab01 workflows must not use secrets")

    trig = triggers(doc)
    if lab01 and set(trig) != {"workflow_dispatch"}:
        errors.append(f"{name}: lab01 workflows must be workflow_dispatch only, got {sorted(trig)}")
    if inactive and os.sep + ".github" + os.sep in path:
        errors.append(f"{name}: inactive template must not live under .github")

    if lab01 and not isinstance(doc.get("concurrency"), dict):
        errors.append(f"{name}: concurrency missing")
    elif lab01 and doc["concurrency"].get("cancel-in-progress") is not False:
        errors.append(f"{name}: host-access concurrency must not cancel in progress")

    for jid, job in (doc.get("jobs") or {}).items():
        where = f"{name}:{jid}"
        if "timeout-minutes" not in job:
            bucket.append(f"{where}: timeout-minutes missing")
        elif lab01 and job["timeout-minutes"] > 20:
            errors.append(f"{where}: timeout too long")
        if "permissions" not in job and strict:
            errors.append(f"{where}: job permissions missing")
        steps = job.get("steps") or []
        for step in steps:
            uses = step.get("uses")
            if uses and not uses.startswith("./") and not SHA_RE.match(uses):
                bucket.append(f"{where}: action not pinned to a full commit SHA: {uses}")
            run = step.get("run", "")
            if strict and "${{" in run:
                errors.append(f"{where}: expression inside run script (pass via env): {step.get('name')}")
        if self_hosted(job):
            if not lab01 or "timeout-minutes" not in job:
                errors.append(f"{where}: self-hosted allowed only in lab01 workflows with timeouts")
            if not job.get("environment"):
                errors.append(f"{where}: self-hosted job requires a protected `environment`")
            if job.get("permissions") != {}:
                errors.append(f"{where}: self-hosted job must have `permissions: {{}}`")
            if job.get("container") or job.get("services"):
                errors.append(f"{where}: self-hosted job must not use containers/services")
            for step in steps:
                uses = step.get("uses", "")
                if uses.startswith("actions/checkout"):
                    errors.append(f"{where}: self-hosted job must not check out repository code")
                for pat in FORBIDDEN_ON_HOST:
                    if pat.search(step.get("run", "")):
                        errors.append(f"{where}: forbidden command on host ({pat.pattern})")
                if re.search(r"/usr/local/libexec/gvai-ci/", step.get("run", "")) is None and "run" in step:
                    errors.append(f"{where}: self-hosted may only run installed gvai-ci helpers")
    if not inactive and lab01:
        if "vars.LAB01_" not in text:
            errors.append(f"{name}: missing fail-closed LAB01_* repository-variable gate")
    if inactive:
        if "ACTIVATED" not in text:
            errors.append(f"{name}: inactive template missing ACTIVATED gate")
    return errors, warnings


def run():
    errors, warnings, seen = [], [], 0
    for pattern, inactive in ((ACTIVE_GLOB, False), (INACTIVE_GLOB, True)):
        for path in sorted(glob.glob(os.path.join(ROOT, pattern))):
            seen += 1
            text, doc = load(path)
            if not isinstance(doc, dict):
                errors.append(f"{path}: not a mapping")
                continue
            e, w = check_file(path, text, doc, inactive)
            errors += e
            warnings += w
    active_lab01 = glob.glob(os.path.join(ROOT, ".github/workflows/lab01-*.yml"))
    for path in active_lab01:
        if os.path.basename(path) != "lab01-readonly-validate.yml":
            errors.append(f"{os.path.relpath(path, ROOT)}: only the read-only validator may be active")
    if seen == 0:
        errors.append("no workflows found (fail closed)")
    return errors, warnings


def main():
    errors, warnings = run()
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"::error::{e}")
    print(f"pipeline security check: {len(errors)} error(s), {len(warnings)} warning(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
