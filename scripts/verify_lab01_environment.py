#!/usr/bin/env python3
"""Fail-closed check that a GitHub Environment really enforces founder approval.

GitHub silently creates a missing Environment, with NO protection rules, the first time a job
references it. This script runs in the GitHub-hosted gate job (before any Lab-01 job) and exits
non-zero unless the Environment exists and has: at least one required reviewer, no administrator
bypass, and a deployment-branch policy limited to explicitly allowed branches.

Limits (do not over-trust): it reads settings through the API at gate time (a later change is not
seen), needs `actions: read`, and any API error is treated as failure. It is a tripwire; the
manual verification checklist in docs/lab01_secure_deployment_pipeline_v1.md remains required.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_BRANCHES = ("main", "integration/advisory-launch-base")
TIMEOUT = 15


def evaluate(env, policies, allowed=ALLOWED_BRANCHES):
    """Return a list of problems (empty means acceptable). Pure function for testing."""
    problems = []
    if not isinstance(env, dict) or "name" not in env:
        return ["environment response malformed"]
    rules = env.get("protection_rules") or []
    reviewers = [r for r in rules if r.get("type") == "required_reviewers"]
    if not reviewers or not any(r.get("reviewers") for r in reviewers):
        problems.append("no required reviewers configured")
    if env.get("can_admins_bypass") is not False:
        problems.append("administrators can bypass protection rules")
    policy = env.get("deployment_branch_policy")
    if not isinstance(policy, dict) or policy.get("custom_branch_policies") is not True:
        problems.append("deployment branches are not restricted to a custom allow-list")
    else:
        names = [p.get("name") for p in (policies or {}).get("branch_policies", [])
                 if p.get("type", "branch") == "branch"]
        if not names:
            problems.append("custom branch policy list is empty")
        extra = sorted(n for n in names if n not in allowed)
        if extra:
            problems.append("branch policies outside the allow-list: " + ", ".join(map(str, extra)))
    return problems


def fetch(url, token):
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
        return json.loads(resp.read(1 << 20).decode("utf-8"))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: verify_lab01_environment.py <environment-name>", file=sys.stderr)
        return 2
    name = argv[0]
    token = os.environ.get("GH_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not token or not repo or not api.startswith("https://"):
        print("::error::missing GH_TOKEN/GITHUB_REPOSITORY or non-https API URL (fail closed)")
        return 1
    base = f"{api}/repos/{repo}/environments/{urllib.parse.quote(name, safe='')}"
    try:
        env = fetch(base, token)
        policies = fetch(base + "/deployment-branch-policies", token)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        reason = getattr(exc, "code", type(exc).__name__)
        print(f"::error::cannot verify environment '{name}' ({reason}); "
              "a missing environment is auto-created WITHOUT approval rules (fail closed)")
        return 1
    problems = evaluate(env, policies)
    for problem in problems:
        print(f"::error::environment '{name}': {problem}")
    if problems:
        return 1
    print(f"environment '{name}': required reviewers, no admin bypass, branch allow-list OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
