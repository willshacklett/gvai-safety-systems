# Lab-01 STOP gate validation runbook v1

**Do not run without explicit founder authorization for a Lab-01 session.** Nothing here has been
executed on Lab-01. Steps are read-only or file-staging unless marked ACTIVATE. Never print, copy,
or log key seeds or the downstream credential.

## Prerequisites

- Founder authorization recorded for this session; maintenance window; ingress closed
  (follow the existing Lab-01 rollback rule: close ingress first).
- Existing `gvai-advisory` healthy baseline captured; no `autoremove`, no `pg_dropcluster`.
- Branch `feature/stop-gate-host-readiness-v1` checked out at the recorded SHA under `/opt/gvai/current`.
- Python venv with `cryptography` at `/opt/gvai/venv`.
- DigitalOcean cloud-firewall state is unknown (existing blocker). Not required here: all new sockets are AF_UNIX.

## Phase 0: read-only baseline (idempotent)

```
ssh <lab01-admin>
sudo systemctl is-active gvai-advisory gvai-ingress
id gvai-api gvai-proxy gvai-operator
sudo aa-status | head -20
sudo systemd-analyze verify /opt/gvai/current/deploy/stop_gate/*.service
sudo apparmor_parser -Q /opt/gvai/current/deploy/stop_gate/apparmor/gvai-stop-gate
sudo apparmor_parser -Q /opt/gvai/current/deploy/stop_gate/apparmor/gvai-protected-backend
```
PASS: advisory active; the three identities exist, no gvai-gate/gvai-backend yet (or already
correct); both profiles parse with exit 0; `systemd-analyze verify` has no errors other than
not-yet-staged units. FAIL: any other result → stop, change nothing.

## Phase 1: stage files (reversible)

```
cd /opt/gvai/current
python3 deploy/stop_gate/lab01_stage.py plan
sudo python3 deploy/stop_gate/lab01_stage.py apply --execute
sudo python3 deploy/stop_gate/lab01_stage.py verify
sudo python3 deploy/stop_gate/lab01_stage.py backup-verify
```
PASS: `plan` lists only create/unchanged/replace_with_backup; `verify` and `backup-verify` exit 0;
re-running `apply --execute` changes nothing. The tool never starts a service or creates users.

## Phase 2: ACTIVATE (second explicit authorization required)

1. `sudo systemd-sysusers /etc/sysusers.d/gvai-stop-gate.conf`
2. `sudo install -d -o gvai-gate -g gvai-gate -m 0700 /var/lib/gvai-stop-gate`
3. Provision by hand (founder only, never via chat/log): `/etc/gvai-stop-gate/gate.json` from the
   example with real *public* STOP/ARM keys (private keys stay off-host), and
   `/etc/gvai-backend/downstream.cred` (0600 root; test-only value for validation).
4. `sudo systemctl daemon-reload && sudo systemctl start gvai-stop-gate.socket gvai-protected-backend.socket`
5. Generate the gate public key: `sudo -u gvai-gate /opt/gvai/venv/bin/python -m gvai.external_gate_service gate-pubkey --config /etc/gvai-stop-gate/gate.json`, put it in `backend.json`.
6. Install AppArmor profiles in **complain** mode first; review denials; then enforce.
7. Install the API drop-in (staged), `daemon-reload`, restart `gvai-advisory`.

## Phase 3: acceptance (as root, read-only probes)

```
sudo /opt/gvai/venv/bin/python -c "import json,sys; from gvai import host_isolation_acceptance as h; \
r=h.run_acceptance(json.load(open('/etc/gvai-stop-gate/acceptance_layout.json'))); \
print(r['passed'],r['failed'],r['failed_ids']); sys.exit(1 if r['failed'] else 0)"
systemctl show gvai-stop-gate -p User,NoNewPrivileges,CapabilityBoundingSet
systemd-analyze security gvai-stop-gate gvai-protected-backend
```
The layout JSON (written by the operator for the session, mode 0600 root, no secrets) has the keys
`users`, `files`, `dirs`, `sockets`, `pids` (from `systemctl show -p MainPID`), `scan_roots`, and
`hardening.apparmor.{gate,backend}` with the expected profile names (see
`tests/test_stop_gate_host_isolation_cloud.py::Sim.layout` for the shape). PASS criteria (all required):

1. Acceptance: `failed == 0` (Cloud baseline 47/0; Lab-01 count recorded in the session log).
2. `evaluate_process_hardening` for both processes: NoNewPrivs=1, CapEff/CapBnd empty, no
   supplementary groups, AppArmor label enforce.
3. `gvai-api` cannot connect to control/notice sockets or read anything under `/etc/gvai-stop-gate`,
   `/var/lib/gvai-stop-gate`, `/etc/gvai-backend`.
4. Armed: an authorized call returns a MAC and no credential bytes anywhere in output/journal.
5. After a signed STOP: new authorize is DENY (T1) and an in-flight slow op is interrupted (T2 ≤ 0.5 s).
6. Stop the gate: in-flight op interrupted within T3 (≤ notice_max_age + 0.5 s).
7. Stubborn op: backend process exits within T4 (≤ 2.0 s) and restarts clean.
Record measured values; a bound is "satisfied" only if measured here. Any FAIL → Rollback.

## Rollback (also safe to run at any phase)

```
sudo systemctl stop gvai-stop-gate.socket gvai-stop-gate.service gvai-protected-backend.socket gvai-protected-backend.service
sudo rm -f /etc/systemd/system/gvai-advisory.service.d/stop-gate.conf   # only if staged by this tool
sudo python3 /opt/gvai/current/deploy/stop_gate/lab01_stage.py rollback --execute
sudo systemctl daemon-reload && sudo systemctl restart gvai-advisory
sudo systemctl is-active gvai-advisory
```
Rollback restores backed-up files (hash-checked, refuses on mismatch), removes only files and empty
directories it created, and keeps backups and `/var/lib/gvai-stop-gate` as records. Users are not
deleted. PASS: advisory active and baseline from Phase 0 reproduced.

## Next controlled session: exact commands

```
git fetch origin && git checkout feature/stop-gate-host-readiness-v1   # laptop: confirm SHA matches the PR
ssh <lab01-admin>      # host alias/user per existing Lab-01 access
sudo -i
cd /opt/gvai/current && git fetch && git checkout <recorded-SHA>
```
then run Phase 0 and Phase 1 only until Phase 2 is authorized.
