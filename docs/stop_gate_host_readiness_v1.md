# STOP gate host readiness v1

Status: experimental, **not deployed, not activated**. Builds on PR #43 (external gate).
Principle: never let the thing behind the switch own the switch.

## What this milestone adds

- Split sockets by privilege: `service` (authorize/status or execute/audit), `control` (signed
  commands, operator only), `notice` (gate → backend only). Wrong request type → `request_not_permitted`.
- systemd socket activation (`LISTEN_FDS`/`LISTEN_FDNAMES`) and the entrypoint
  `python -m gvai.external_gate_service {gate,backend,gate-pubkey}`.
- In-flight cancellation, stale-notice watchdog, uncooperative-operation hard exit (code 70).
- Permits carry `issued_at`; the backend rejects permits older than its own start (its nonce memory is volatile).
- `gvai/host_isolation_acceptance.py`: root-run probes executed as the API user.
- `deploy/stop_gate/`: separate identities, hardened units, AppArmor drafts, API drop-in, and
  `lab01_stage.py` (files-only staging with rollback). Nothing is loaded or started.

## Interruption targets (defined; Cloud-simulation values measured, host values NOT measured)

| ID | Definition | Bound | Cloud-sim measured |
|----|-----------|-------|--------------------|
| T1 | new `authorize` denied after STOP acknowledged | next request | 0.0003 s |
| T2 | cooperative in-flight op interrupted after STOP ack (8 concurrent too) | ≤ 0.5 s | ~0 s (8 concurrent 0.0008 s) |
| T3 | gate silent/lost → in-flight op interrupted | ≤ 1.1 s (`notice_max_age` 0.6 + 0.5) | 0.5947 s |
| T4 | op ignoring cancel → backend process exit | ≤ 2.0 s (deadline 1.0 + 1.0 slack) | 1.0062 s |

These are single-run values on a Cloud sandbox with a 0.6 s notice age; they are not
satisfaction of the bound on Lab-01. Production defaults (`notice_max_age` 3 s) give
T3 ≈ 3.5 s unless changed; the host runbook must record the configured values. Measurements are
written to JSON when `GVAI_LATENCY_REPORT` is set.

## Fail-closed behaviour (tested)

DENY on: missing/invalid/replayed/rolled-back authority, gate unreachable, socket missing,
timeouts, torn or garbage anchor/store files, wrong epoch, expired or pre-restart permit,
and wrong socket for the request type. Gate loss cancels in-flight work. Gate restart resumes
only from durable state; an anchor/store disagreement is a sticky `fault`.

## What the Cloud harness proves, and what it does not

`tests/test_stop_gate_host_isolation_cloud.py` (root only, throwaway users `gvsim-*`) launches the real
entrypoints under `setpriv --no-new-privs --bounding-set=-all` with emulated socket activation and
runs the acceptance probes: 47 checks, 0 failed. It proves **UID/DAC separation** only: the API uid
cannot read keys/anchor/credential, write or rename in protected dirs, connect to control/notice
sockets, signal gate/backend, read `/proc/<pid>/mem|environ|fd`, and finds no secret by hash scan.
It also proves the checks fail when permissions are weakened.

It does **not** prove: systemd sandboxing directives, AppArmor confinement, cgroup limits,
`IPAddressDeny`, `InaccessiblePaths`, `LoadCredential` behaviour, root/kernel compromise, or anything
about Lab-01. Those need the host session in the runbook.

## Known limitations / open findings

- A same-UID attacker can rewrite anchor/store files; this is detected and fails closed, not prevented.
- A crash between anchor advance and store write leaves a `fault` needing re-provisioning (safe).
- If the notice channel fails, an issued permit remains usable until TTL (5 s) or notice staleness.
- Root compromise of the host defeats all of this; an off-host enforcement point is still needed.
- AppArmor profiles are drafts, never parsed (no `apparmor_parser` in Cloud).
- Cloud CI does not run for PRs whose base is not `main` (`tests.yml` triggers on main only).
