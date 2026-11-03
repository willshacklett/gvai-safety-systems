#!/usr/bin/env python3
"""Tamper-evidence manifest for the files that control Lab-01 access.

`check` (default) fails if any control file differs from deploy/lab01_ci/INTEGRITY.sha256 or if the
set of control files changed. `write` regenerates the manifest (a deliberate, reviewable act).

This is NOT an independent security boundary: anyone who can edit a control file can regenerate
the manifest in the same commit. Its value is making every such change explicit in review and in
the audit summary (the manifest's own digest is printed so an approver can compare it with the
value they reviewed). The real boundaries are branch rulesets/CODEOWNERS, Environment reviewers,
and the host-side unprivileged runner user.
"""

import glob
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = "deploy/lab01_ci/INTEGRITY.sha256"
PATTERNS = (
    ".github/CODEOWNERS",
    ".github/workflows/lab01-*.yml",
    ".github/workflows/pipeline-security.yml",
    "deploy/lab01_ci/host/*",
    "deploy/lab01_ci/workflows_inactive/*",
    "deploy/stop_gate/**",
    "scripts/pipeline_*.py",
    "scripts/verify_lab01_*.py",
    "tests/test_lab01_ci_pipeline.py",
)


def sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def control_files():
    found = set()
    for pattern in PATTERNS:
        for path in glob.glob(os.path.join(ROOT, pattern), recursive=True):
            if os.path.isfile(path) and not os.path.islink(path):
                found.add(os.path.relpath(path, ROOT).replace(os.sep, "/"))
    return sorted(found - {MANIFEST})


def render():
    return "".join(f"{sha256(os.path.join(ROOT, rel))}  {rel}\n" for rel in control_files())


def check():
    path = os.path.join(ROOT, MANIFEST)
    if not os.path.isfile(path):
        return ["integrity manifest missing"], None
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    expected = render()
    errors = []
    if text != expected:
        want = dict(reversed(l.split("  ", 1)) for l in text.splitlines())
        have = dict(reversed(l.split("  ", 1)) for l in expected.splitlines())
        for rel in sorted(set(want) | set(have)):
            if rel not in have:
                errors.append(f"in manifest but not a control file/missing: {rel}")
            elif rel not in want:
                errors.append(f"control file not in manifest: {rel}")
            elif want[rel] != have[rel]:
                errors.append(f"digest mismatch: {rel}")
        errors = errors or ["manifest formatting differs"]
    return errors, hashlib.sha256(text.encode()).hexdigest()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["write"]:
        with open(os.path.join(ROOT, MANIFEST), "w", encoding="utf-8") as fh:
            fh.write(render())
        print("manifest written; review the diff, it is a security-relevant change")
        return 0
    if argv not in ([], ["check"]):
        print("usage: pipeline_integrity.py [check|write]", file=sys.stderr)
        return 2
    errors, digest = check()
    for err in errors:
        print(f"::error::{err}")
    if errors:
        return 1
    print(f"integrity manifest OK; manifest sha256={digest}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"- control-file manifest sha256: `{digest}` (tamper-evidence only)\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
