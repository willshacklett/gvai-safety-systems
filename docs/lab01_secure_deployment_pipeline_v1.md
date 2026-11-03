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
| Gate | GitHub-hosted job; repo variable `LAB01_VALIDATION_ENABLED=='true'`; policy check | off by default; fails closed |
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
  `/etc/gvai-operator`, `/var/lib/gvai-operator`, `/etc/gvai-ingress`; it never opens or lists them. If any is
  accessible the run **fails**.
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
1. *Environments → New environment* `lab01-readonly`: *Required reviewers* = yourself; *Deployment
   branches* = selected branches `main` and `integration/advisory-launch-base`; no secrets.
2. Settings → Actions → General: fork PR workflows = require approval for all outside collaborators;
   default `GITHUB_TOKEN` = read-only.
3. *Settings → Actions → Runners → New self-hosted runner* (Linux x64): copy the one-time
   registration token **only into the console in step B** (it expires in ~1 hour; never paste it in
   chat, issues, or a file in the repo). Use label `gvai-lab01-readonly`, and `--ephemeral`.
4. Only when ready to run stage 1: Settings → Variables → `LAB01_VALIDATION_ENABLED` = `true`.
   Set it back to `false` (or delete it) to switch the pipeline off instantly.

**B. Lab-01 (Droplet Console, as root) - touches only `gvai-ci`, `/var/lib/gvai-ci`, `/usr/local/libexec/gvai-ci`, one unit file**
```
git clone --depth 1 --branch <reviewed-branch> https://github.com/willshacklett/gvai-safety-systems /tmp/gvai-review
cd /tmp/gvai-review && git rev-parse HEAD            # must equal the SHA in the merged PR
bash deploy/lab01_ci/host/bootstrap_lab01_ci.sh      # dry run: read the output
bash deploy/lab01_ci/host/bootstrap_lab01_ci.sh --execute
# download the runner tarball from the GitHub "New self-hosted runner" page into /var/lib/gvai-ci/runner,
# extract as gvai-ci, then (as gvai-ci):  ./config.sh --url <repo> --token <ONE-TIME> --labels gvai-lab01-readonly --ephemeral --unattended
systemctl enable --now gvai-ci-runner      # only when ready
```
The `gvai-ci` runner has no sudo, no Docker, no `gvai-*` group membership, and an empty capability set.
Do **not** add it to `sudo`, `docker`, `adm`, or any `gvai-*` group. Ephemeral runners deregister after
each job, so restart the unit to run again (or script re-registration later in a reviewed change).

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
