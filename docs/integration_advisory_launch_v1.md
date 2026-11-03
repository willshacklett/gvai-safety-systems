# Advisory launch candidate: integration status (v1)

Branch `integration/advisory-launch-candidate` combines, without altering either side's code:

- the commercial/PostgreSQL stack (PRs #27–#41, including #33), and
- the independent STOP-gate stack (PRs #42–#44).

Both merged cleanly (no textual conflicts). The branch is a **validation candidate**. It is not
merged to `main`, nothing is deployed, and no commercial API or STOP gate is activated.

Governing principle: *Never let the thing behind the switch own the switch.*

## Key finding: the commercial service is advisory-only and not wired to the gate

`CommercialEvaluationService` never executes or authorizes anything. The gate protects *protected
operations* executed by the separate backend. This integration therefore proves **separation**
(the commercial side has no path to gate keys, latch, or anchor, and cannot mint authority), not a
functional coupling. A future paid feature that performs a controlled action must go through
`GatedService` (gate permit → backend); that wiring does not exist yet.

## CI

`.github/workflows/integration-tests.yml` runs the full suite on pushes and pull requests for
`integration/**` branches only: read-only permissions, no secrets, no Pages or deploy steps, never
triggers on `main`. `deploy-public-site.yml` still deploys only from `main` (or manual dispatch on
`main`). The draft PR targets `integration/advisory-launch-base`, a non-deploying branch.

## What the integration tests show (`tests/test_integration_commercial_stop_gate.py`)

Static (inspects inactive deployment files and source; proves nothing about a live host):

- Commercial/PostgreSQL/staging/evaluation modules do not import or mention gate internals, and the
  gate modules do not import commercial code.
- `gvai-advisory.service` plus the required `gvai-advisory-stop-gate.conf` drop-in hides gate and
  backend state, config and the control/notice sockets. The base unit alone does **not**; the
  drop-in is a mandatory install step.
- API, gate and backend run as three distinct identities; only `gvai-operator` owns the control
  socket unit.

Runtime (**simulated** separation: child processes, same UID/kernel):

- Service-facing sockets reveal no key or seed material and reject command, notice and other
  control-plane messages, including attacker-signed STOP/ARM; state files are byte-identical after.
- Never-armed, stopped, stale (gate dead past `notice_max_age`), unavailable gate, unavailable
  backend, forged/mutated/replayed/expired tokens, and tokens signed by non-gate keys all deny and
  leave the backend execution log empty.
- A successful advisory evaluation carries no permit/token and does not alter gate decisions.

## Still simulated: requires verification on Lab-01 (founder-authorized)

Nothing here proves host-level isolation. Unverified until measured on the real host:

- Separate-UID enforcement: service user cannot read, write, or signal gate/backend files and processes.
- systemd behaviour (`InaccessiblePaths`, `LoadCredential`, socket ownership/modes, drop-in order),
  AppArmor confinement, cgroup limits, and network/firewall rules.
- Interruption bounds (T1–T4) measured only in Cloud simulation.
- Anchor storage the service credentials cannot write; operator key custody and real ARM/STOP transport.
- Real Nginx/mTLS, Docker-based ingress tests, and PostgreSQL integration tests (skipped here; they
  require explicitly authorized disposable environments).
- Host firewall and Cloud Firewall approval.

## Other remaining gaps

No billing integration, no gate-to-commercial functional wiring, no external security review, and
no multi-replica anchor coordination.
