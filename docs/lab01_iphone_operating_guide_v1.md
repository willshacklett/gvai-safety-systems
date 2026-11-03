# Lab-01 iPhone operating guide v1

You never need PowerShell or SSH for routine checks. Stage 1 is **read-only**.

## Run a read-only validation
1. GitHub app → repo `gvai-safety-systems` → **Actions** → **lab01-readonly-validate** → **Run workflow**
   (branch `main`; if it is greyed out, the pipeline is not merged/enabled yet).
2. The `gate` job runs. If it fails with *"LAB01_VALIDATION_ENABLED is not 'true'"*, that is the
   safety switch working. Enable only when you intend to run (Settings → Variables).
3. You get a **"Review deployments"** prompt/notification for `lab01-readonly`. Check the
   actor is you, the branch/SHA is what you expect, then **Approve and deploy**. If anything is
   unexpected, tap **Reject**.
4. Open the run summary: overall must read `partial_pass`, *host-level security validated: NO*.
   Any `fail` row, or a red `verify` job = stop and investigate; change nothing.
5. Afterwards set `LAB01_VALIDATION_ENABLED` back to `false`.

## Read the result
| Row status | Meaning |
|---|---|
| `pass` | Checked from the unprivileged view and fine |
| `fail` | Real problem (e.g. runner can read a STOP path, public listener on odd port) |
| `not_collected` | Needs root/DigitalOcean API. **Not** a pass |

## Hard rules
- Never paste registration tokens, keys, or credentials into GitHub, chat, or a Copilot prompt.
- Approve only runs **you** started. An unexpected approval request = Reject.
- Stage 2 (staging), rollback, and host validation are **inactive**; do not look for them in Actions.
- STOP authority is never reachable from this pipeline. If a run ever asks for it, Reject.
- If the runner misbehaves: GitHub → Settings → Actions → Runners → remove it. Or Droplet Console:
  `systemctl disable --now gvai-ci-runner`.
