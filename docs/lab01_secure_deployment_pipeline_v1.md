# Lab-01 secure deployment pipeline v1

Status: **design + inert/gated tooling.** Nothing here has been run against Lab-01, and **host-level
security has not been validated.** Principle: *never let the thing behind the switch own the switch.*

## 1. Architecture

```
iPhone (GitHub mobile app / Safari)
   │  founder dispatches + approves
   ▼
GitHub-hosted jobs ──► gate (fail closed) ──► [Environment approval] ──► Lab-01 runner job ──► evidence artifact ──► GitHub-hosted verify
                                                      (unprivileged `gvai-ci`, no repo code, no token)
```

| Layer | Mechanism | Why |
|---|---|---|
| Trigger | `workflow_dispatch` only; owner-only actor check; allowed refs | no PR/fork/`workflow_run`/schedule path can reach Lab-01 |
| Gate | GitHub-hosted job; variables `LAB01_VALIDATION_ENABLED` and `LAB01_ENV_VERIFIED_BY_FOUNDER` both `'true'`; policy + integrity checks; API check that the Environment has reviewers (section 2) | off by default; fails closed |
| Approval | Environment `lab01-readonly` with required reviewer + branch policy | founder taps *Approve* on iPhone |
| Execution | Self-hosted runner as user `gvai-ci`, unit hardened (`NoNewPrivileges`, empty capability set, `InaccessiblePaths` for every STOP/protected path and Docker socket) | runner cannot gain root, Docker, or STOP authority |
| Code on host | **No `actions/checkout` on Lab-01.** Only the root-owned `/usr/local/libexec/gvai-ci/lab01-readonly-collect` runs | PR/branch code never executes on the host |
| Evidence | `$RUNNER_TEMP` JSON → artifact (14 days) → verified on a GitHub-hosted runner (schema, secret scan, no mutation / no "validated" claims) | untrusted host output is never trusted blindly |
| Concurrency | single group `lab01-host-access`, `cancel-in-progress: false` | one host operation at a time, never killed midway |

### Workflows

| File | State | Purpose |
|---|---|---|
| `.github/workflows/lab01-readonly-validate.yml` | **Active file, off until variable set and merged to the default branch** | Stage 1, read-only evidence |
| `.github/workflows/pipeline-security.yml` | Active, GitHub-hosted, no secrets | Policy check, tests, shellcheck |
| `deploy/lab01_ci/workflows_inactive/lab01-staging-deploy.yml.inactive` | **Inactive** | Stage 2: `lab01_stage.py` plan/apply/verify (files only) |
| `deploy/lab01_ci/workflows_inactive/lab01-rollback.yml.inactive` | **Inactive** | `lab01_stage.py` rollback + backup-verify |
| `deploy/lab01_ci/workflows_inactive/lab01-host-validation.yml.inactive` | **Inactive** | Stage 3: root-requiring read-only host validation |

Inactive templates live outside `.github/workflows`, so GitHub never loads them. They additionally
require `LAB01_*_ACTIVATED=='true'`, `main` only, owner-only, typed confirmation (stage 2 also a
40-hex SHA), and call root-owned wrappers (`stage-wrapper`, `hostval-wrapper`) **that do not exist**,
so they fail closed even if copied. `scripts/pipeline_security_check.py` enforces that only the
read-only validator may exist under `.github/workflows/lab01-*`.

### STOP-authority isolation (requirement 6)

- STOP/ARM private keys are off-host (existing design); the runner has no path to them.
- `gvai-ci` is a separate user with no supplementary groups; the bootstrap refuses if it is in any
  `gvai-*` group, and the collector fails if the user is root, has capabilities, lacks `NoNewPrivs`,
  or is in `root/sudo/adm/docker/lxd/disk/shadow/gvai-*`.
- The collector only asks the kernel (`os.access`) whether `gvai-ci` is **denied** on
  `/etc/gvai-stop-gate`, `/var/lib/gvai-stop-gate`, `/etc/gvai-backend`, `/etc/gvai-runtime`,
  `/etc/gvai-operator`, `/var/lib/gvai-operator`, `/etc/gvai-ingress`, and the STOP-gate/backend socket
  directories `/run/gvai-stop-gate` and `/run/gvai-protected-backend`; it never opens or lists them. If any is
  accessible the run **fails**. The runner unit also lists all of them in `InaccessiblePaths`.
- The runner unit has no `Requires/Wants/BindsTo/PartOf/After` on any `gvai-*` workload unit, and
  nothing in the pipeline starts, stops, or reconfigures STOP-gate units.
- No workflow uses `secrets.*`; CI files containing STOP-authority path/key tokens fail the policy check.
- Copilot agent / commercial services: no token or credential is created or shared with them.
  `copilot` environment exists with no protection rules and no secrets; do not add Lab-01 secrets to it.

## 2. GitHub Environments: verified facts and gaps

Verified via the REST API from this session (read-only):

- Repository is **public, user-owned** (`willshacklett`). Environment `github-pages` already has a
  `required_reviewers` rule (reviewer `willshacklett`) and a custom branch policy, so
  required-reviewer approvals **are available** on this repository/plan.
- `prevent_self_review` is `false` there. With a single-owner repo, self-approval must be allowed or
  nothing can ever be approved; the approval is therefore a deliberate-action gate (phone tap), not
  two-person control. Add a second reviewer if one exists.
- Environments `lab01-readonly`, `lab01-staging`, `lab01-rollback`, `lab01-host-validation` do **not**
  exist; this session's token could not (and did not) create them. Create them by hand (section 4).
- Not verifiable with this token (HTTP 403): Actions permissions, fork-PR approval policy, existing
  self-hosted runners, branch protection details. `integration/advisory-launch-base` reports `protected: false`.
- **Public-repo risk:** a self-hosted runner on a public repo must never run fork/PR code. This
  design is dispatch-only, owner-only, environment-gated, and runs no checked-out code on the host.
  Still set *Settings → Actions → Fork pull request workflows → Require approval for all outside
  collaborators*, and keep the runner out of any runner group used by other workflows.

## 3. Audit of existing assets (findings)

| # | Finding | Severity | Action |
|---|---|---|---|
| 1 | `deploy/stop_gate/apparmor/*` are explicitly **NOT LOADED** drafts; enforcement unverified | High (unvalidated) | Host validation stage; complain mode first |
| 2 | STOP-gate/backend units are hardened but **not staged/enabled** on Lab-01 | Info | Existing runbook phases 1-2, founder-run |
| 3 | DigitalOcean cloud-firewall state unknown (existing blocker); UFW/cloud firewall not collectable without root/API | High (unknown) | Collector reports `not_collected`, never pass |
| 4 | `tests.yml`: no `permissions`, no timeout, actions not SHA-pinned | Medium | Not changed (out of scope); policy check warns |
| 5 | `deploy-public-site.yml`: jobs lack `timeout-minutes`; line 69 sends the literal header `Authorization: ******` so the Pages-source check likely cannot authenticate | Medium | Not changed; fix separately |
| 6 | `integration-tests.yml` is validation-only, read-only, pinned (good model) | Info | Reused patterns |
| 7 | `lab01_stage.py` is file-only, dry-run default, hash-checked rollback, forbids authority paths (good) | Info | Stage 2 wraps it unchanged |
| 8 | No existing mechanism for founder approval from a phone | Gap | This pipeline |
| 9 | Root-level evidence (aa-status, acceptance run) cannot come from an unprivileged runner | Design limit | Stage 3, needs separate review |

## 4. One-time setup (founder; no PowerShell)

Everything is doable from a browser/iPhone. Use the **DigitalOcean web Droplet Console** (Droplet →
Access → *Launch Droplet Console*) instead of PowerShell/SSH. This is the only time a shell is needed.

**A. GitHub (iPhone Safari → github.com → repo → Settings)**
1. *Environments → New environment* `lab01-readonly` (**do this before step 4; GitHub auto-creates a
   missing environment with no approval rules**): *Required reviewers* = yourself; *Allow
   administrators to bypass* = **off**; *Deployment branches* = selected branches, exactly `main` and
   `integration/advisory-launch-base`; no secrets. Then complete the manual checklist in section 8.
2. Settings → Actions → General: fork PR workflows = require approval for all outside collaborators;
   default `GITHUB_TOKEN` = read-only.
3. *Settings → Actions → Runners → New self-hosted runner* (Linux x64): copy the one-time
   registration token **only into the console in step B** (it expires in ~1 hour; never paste it in
   chat, issues, or a file in the repo). Use label `gvai-lab01-readonly`, and `--ephemeral`.
4. Only when ready to run stage 1 (and after section 8 is complete): Settings → Variables →
   `LAB01_ENV_VERIFIED_BY_FOUNDER` = `true` **and** `LAB01_VALIDATION_ENABLED` = `true`.
   Set `LAB01_VALIDATION_ENABLED` back to `false` (or delete it) to switch the pipeline off instantly.

**B. Lab-01 (Droplet Console, as root) - touches only `gvai-ci`, `/var/lib/gvai-ci`, `/usr/local/libexec/gvai-ci`, one unit file**
```
git clone --depth 1 --branch <reviewed-branch> https://github.com/willshacklett/gvai-safety-systems /tmp/gvai-review
cd /tmp/gvai-review && git rev-parse HEAD            # must equal the SHA in the merged PR
bash deploy/lab01_ci/host/bootstrap_lab01_ci.sh      # dry run: read the output
bash deploy/lab01_ci/host/bootstrap_lab01_ci.sh --execute
# download the runner tarball from the GitHub "New self-hosted runner" page into /var/lib/gvai-ci/runner,
# extract as gvai-ci, then (as gvai-ci):
#   ./config.sh --url <repo> --token <ONE-TIME> --labels gvai-lab01-readonly --ephemeral --disableupdate --unattended --work /run/gvai-ci/work
systemctl enable --now gvai-ci-runner      # only when ready
```
The `gvai-ci` runner has no sudo, no Docker, no `gvai-*` group membership, and an empty capability set.
Do **not** add it to `sudo`, `docker`, `adm`, or any `gvai-*` group.

**Runner state.** The job workspace and temp live in `/run/gvai-ci` (a runtime directory deleted when the
unit stops); `--disableupdate` stops the runner replacing its own binaries; `--ephemeral` makes it take
one job and deregister, so `systemctl restart` alone will not run another job. After **every** job (and
before re-registering) reset persistent state: `systemctl stop gvai-ci-runner; rm -rf /var/lib/gvai-ci/runner/*`,
then extract a fresh tarball (verify its published SHA-256) and register with a new one-time token. The
files the runner owns in `/var/lib/gvai-ci` are still writable by a malicious job while it runs; this is
reduced (ephemeral, reset, unprivileged, no secrets on the host for it to steal), not eliminated.

Remove with: `systemctl disable --now gvai-ci-runner; rm /etc/systemd/system/gvai-ci-runner.service; rm -r /usr/local/libexec/gvai-ci; userdel gvai-ci`
(and delete the runner in GitHub Settings).

## 5. Evidence and audit logging

- Job summary: actor, event, ref, SHA, run id, evidence SHA-256, per-check table.
- Approval trail: Environment deployment record (who approved, when) in the repo *Deployments* log.
- Artifact: `lab01-readonly-evidence` (14 days). Contains check IDs/statuses and bounded details only:
  no file contents, environment variables, keys, or credentials. The verifier rejects secret-looking text.
- Host side: collector exits non-zero on any failed check; runner stdout/stderr go to journald.

## 6. Activating stage 2 / rollback / host validation (not done here)

Required before copying any template into `.github/workflows`: (1) a reviewed root-owned wrapper
that accepts only the fixed subcommands, a 40-hex SHA verified as an ancestor of the approved
branch, never a path/args from the workflow, and refuses all `FORBIDDEN_TARGETS` of `lab01_stage.py`;
(2) a separate runner user/label (`gvai-lab01-deploy`) distinct from the read-only runner, with a
single exact-command sudo rule (no wildcards, no shell, no Docker) or equivalent; (3) its own
environment with required reviewer; (4) a fresh security review. Activation, the privileged wrapper, and
AppArmor/STOP-gate activation remain explicit founder decisions.

## 7. What this does **not** prove

Collector `not_collected` items (firewall, AppArmor enforce state, sshd config, STOP acceptance run)
need root or provider APIs. A green stage-1 run is readiness evidence for the unprivileged view only.

## 8. Environment approval: manual verification (required, workflow stays disabled until done)

GitHub creates an Environment with **no rules** if a job names one that does not exist, so approval
could silently fail open. The gate job calls `scripts/verify_lab01_environment.py`, which fails the run
unless the Environment exists with ≥1 required reviewer, administrator bypass off, and a custom branch
allow-list limited to `main` / `integration/advisory-launch-base`. That check is a tripwire, **not a
guarantee**: it needs `actions: read` on `GITHUB_TOKEN` (untested against a real `lab01-readonly`),
reads settings only at gate time, and cannot see later edits. So the founder must also verify by hand,
then set `LAB01_ENV_VERIFIED_BY_FOUNDER=true` (the gate refuses without it):

1. Settings → Environments → `lab01-readonly` exists and was created by you, not auto-created.
2. *Required reviewers* lists you (and a second person if available); *Allow administrators to bypass*
   is off; *Deployment branches* = selected branches, exactly the two above; no secrets/variables on it.
3. Run a first test with the Lab-01 runner **offline**: the `collect` job must pause at "Review
   deployments"; Reject it. A job that starts without prompting means the environment is wrong; stop.
4. Re-verify after any change to environments, collaborators, or the repository owner.

Note `prevent_self_review` cannot be satisfied by a single-owner repo; approval is a deliberate-action
gate, not two-person control, unless a second reviewer exists.

## 9. Workflow integrity and required repository settings

The threat: whoever can change the workflow, the policy checker, or the runner scripts on an allowed
branch can make the Lab-01 job run different commands as `gvai-ci`. **CI cannot defend against that,
because the attacker edits CI too. Nothing in CI is an independent security boundary.** What exists:

| Control | Type | Independent of the author? |
|---|---|---|
| `.github/CODEOWNERS` (control files owned by `@willshacklett`) | Review routing | Only if a ruleset requires code-owner review |
| `scripts/pipeline_security_check.py` (policy) | Lint / regression guard | No |
| `deploy/lab01_ci/INTEGRITY.sha256` + `scripts/pipeline_integrity.py` | Tamper-evidence; digest printed in the run summary to compare with what you reviewed | No |
| `pipeline-security` job summary listing changed control files | Reviewer aid | No |
| Branch ruleset / protection (below) | GitHub-enforced | **Yes** |
| Environment reviewers + branch allow-list | GitHub-enforced | **Yes** (if you review the SHA) |
| Unprivileged `gvai-ci` user, DAC on STOP paths | Host-enforced | **Yes** |

**Required founder configuration (not done by this PR):** Settings → Rules → Rulesets (or branch
protection) for `main` and `integration/**`:
- require a pull request, with **review from Code Owners** and dismissal of stale approvals;
- require status checks `policy` (pipeline-security) and `test` (integration-tests) to pass, branch up to date;
- block force pushes and deletions; restrict who can push; **do not allow bypass** (an admin bypass voids this);
- optionally require signed commits.

Limits you must accept or fix: GitHub does not let an author approve their own PR, so with a single
owner, code-owner review needs a **second trusted account** (recommended) or a ruleset bypass, which
reduces this to trust in one account. A compromised owner account defeats every GitHub-side control;
use a hardware key/passkey and review the exact SHA in "Review deployments" before approving.

## 10. Dependency pinning

`PyYAML==6.0.2` is pinned exactly in `requirements-dev.txt` and every workflow `pip install`; actions are
pinned to full commit SHAs. Not done: pip hash-pinning (`--require-hashes`) and pinning of the
pre-existing unpinned dependencies; GitHub-hosted jobs install from PyPI. The Lab-01 host runs no
`pip`; the collector is stdlib-only and installed from a reviewed file whose SHA-256 the bootstrap prints.
