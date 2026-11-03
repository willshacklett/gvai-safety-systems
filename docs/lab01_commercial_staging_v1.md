# Lab-01 commercial staging preparation V1

## Founder review only

Target: `gvai-safety-lab-01`, Ubuntu 24.04 LTS, 2 vCPUs, 4 GB RAM,
80 GB disk; operator-supplied public address `138.68.23.151`.
Branch: `feature/onhost-staging-readiness-v1`; reviewed starting commit:
`574b4869817145ad3dbd94f2f6d3aa2beedecabb`.

This is an **unexecuted** host-specific adaptation of the
[on-host gates A-G](onhost_staging_readiness_v1.md), existing
[private HTTPS deployment](private_https_staging_v1.md) and
[PostgreSQL advisory backend](commercial_advisory_backend_v1.md).
No SSH/cloud operation, package installation, DNS change, deployment or
public HTTPS activation is authorized or performed here. Stop for founder
review of the manifest and gates below.

First hosted evaluation means **real HTTPS over approved private access to
Lab-01, with real durable PostgreSQL**, not a public listener. Keep the existing
`127.0.0.1:8443 -> 127.0.0.1:8080 -> 127.0.0.1:5432` topology and units.
No public port 80/443, default Nginx site, signup or operator HTTP endpoint.
Responses remain `advisory_only=true`, `enforcement_applied=false`; an advisory
ALLOW is not execution authority. Independent supervisor STOP, AppArmor,
Bubblewrap, signer and checkpoint controls are not installed, rewired or
relaxed by this deployment.

## Evidence and host-specific preflight

The following evidence was supplied by the operator, not independently
collected in this workspace:

| Supplied observation | Consequence |
|---|---|
| AppArmor active; unprivileged user namespaces restricted | Preserve both; do not enable user namespaces for the advisory API |
| Python 3 and python3-venv installed | Use existing Python for discovery; verify actual executable/version |
| Nginx/PostgreSQL absent; no GVAI service definitions found | Plan fresh isolated installation, not takeover of an existing service |
| SSH only externally listening service | Recheck all IPv4/IPv6 TCP/UDP listeners and reserved loopback ports before change |
| Host firewall inactive | Activation blocker, not permission to ignore firewall checks |
| Cloud Firewall unknown | Mandatory independent verification; no cloud calls in preflight |

After **new Lab-01 read-only authorization**, transfer the reviewed preflight
to a root-owned path and run:

```sh
sudo /usr/bin/python3 /APPROVED/PATH/host_preflight.py \
  --target gvai-safety-lab-01
```

An initial exit 1 is expected: no approved baseline, absent service accounts
and inactive host firewall. Missing Nginx/psql/OpenSSL appear as fixed
`evidence.packages_available` Booleans, not discovery failures. Prepared mode
requires them; executable presence is not version/module validation.
Every report still says `deployment_authorized=false`.

Lab-01 selection requires its exact hostname and the kernel's
`apparmor_restrict_unprivileged_userns=1`, plus the unchanged OS/systemd,
AppArmor-enabled, policy custody, resources, account and listener checks.
It fingerprints the whole policy tree, all loaded profiles and worker/bwrap
unit state **without requiring Test-01's experiment labels to exist here**.
Missing/unreadable policy evidence or restriction is a failure.
The default target remains Test-01 and still requires `gvai-worker (enforce)`
and `gvai-bwrap (enforce)`. Never pass the Lab target as a bypass on Test-01,
copy its baseline, invent/reload profiles, or alter Test-01's existing work.

Founder privately reviews actual Lab-01 profiles, all GVAI unit definitions
and independent STOP ownership/state, including any units other than the two
fingerprinted names. Unexpected existing services require a revised manifest.
Save only `evidence.protected` as Lab-01's root-owned mode-0600 baseline under
a root-owned mode-0700 private directory, retaining an independent approved
copy associated with this hostname. Baseline files are not authenticated
host identities. Never regenerate one automatically on drift.

Before package work, approve an SSH-preserving host firewall policy and
independently inspect the DigitalOcean firewall's actual attachment to this
droplet and inbound IPv4/IPv6 rules. Allow SSH only from approved operator
sources; deny public 5432/8080/8443 and 80/443. Verify no NAT/container/alternate
proxy exposure and confirm a recovery console/access path before firewall
activation. Do not enable UFW blindly over the only SSH connection.
No firewall commands or cloud changes are executed by this preparation.

## Minimum approved installation manifest

Root performs package/account/configuration/unit installation only.
Database bootstrap uses local `postgres` peer access; application/operator
never receive this account, sudo, polkit grants, Docker membership or CA keys.

| Requirement | Purpose / custody |
|---|---|
| `nginx` | Ubuntu Nginx with SSL module at `/usr/sbin/nginx`; distro service stays masked |
| `postgresql-common`, `postgresql-16`, `postgresql-client-16` | Ubuntu 24.04 dedicated cluster and local administration/backup tools |
| `openssl`, `ca-certificates` | Verify separately issued development certificates/trust |
| Existing Python 3, `python3-venv` | Root-owned `/opt/gvai/venv`; install only declared [runtime dependency](../requirements-private-staging.txt) in it |
| `apparmor-utils`, `ufw`, `acl` if missing | Read-only AppArmor/firewall/ACL verification; presence must not cause policy relaxation |
| Existing systemd >=255, cgroup v2 | Validate active credentials and network sandbox, not just directive parsing |
| `gvai-api`, `gvai-proxy` | Separate non-login system accounts/primary groups, no supplementary privileges |
| `gvai-operator` | Separate non-login operator account, invoked only by an authorized administrator; private CLI, no HTTP route |

No Docker, ACME, Certbot, public DNS, extra framework, schema, billing or
worker deployment is needed. Record exact approved package versions/dependency
transaction with an APT simulation before installation. Do not upgrade unrelated
packages or install optional dependencies merely to make offline skips disappear.

Before mutation, record package versions, service enabled/masked/active state,
all newly named paths/accounts, and hashes/metadata/ACLs of configuration
backups. Confirm >=5 GiB free disk and >=2 GiB available memory, and budget
PostgreSQL within the 4 GB host after the API's 512 MiB and proxy's 128 MiB
limits. The nominal disk/RAM size alone is not current headroom evidence.
Use only an agreed maintenance window; do not stop experiments.

### Prevent package-triggered listeners first

Do not run a bare `apt install nginx postgresql`: Debian post-install scripts
can create/start a default cluster or Nginx listener.

1. Confirm `/usr/sbin/policy-rc.d` and the distro units/mask paths do not
   already exist. If present, stop and review; never overwrite them.
   During the approved short package transaction only, root installs a new
   regular mode-0755 `/usr/sbin/policy-rc.d` with exactly:

   ```sh
   #!/bin/sh
   exit 101
   ```

   This temporarily denies package service starts/restarts system-wide.
   Coordinate competing package automation; do not leave this guard behind.
   Retain its hash so cleanup removes only the guard created by this operation.
2. Mask only the previously absent `nginx.service` and `postgresql.service`
   before package installation; record the new mask symlinks. Neither
   umbrella service is the intended GVAI service.
3. Install `postgresql-common` first under the guard. Privately back up its
   newly created `/etc/postgresql-common/createcluster.conf` with metadata,
   then explicitly set `create_main_cluster = false` there. Review the
   effective setting before installing the server package.
4. Inspect a simulation, then execute **only after change authorization**:

   ```sh
   sudo apt-get --simulate install --no-install-recommends \
     nginx postgresql-16 postgresql-client-16 openssl ca-certificates
   sudo apt-get install --no-install-recommends \
     nginx postgresql-16 postgresql-client-16 openssl ca-certificates
   ```

   Add only approved missing verification packages from the manifest.
   Verify no `main` cluster was created, no distro service started and no new
   listener appeared. An unexpected cluster/listener is an abort, not something
   to adopt silently. Do not start `nginx.service` or the PostgreSQL umbrella.
5. On success **or failure**, inspect the guard's path/type/hash and remove only
   this newly created guard. Keep the recorded distro masks; retain evidence
   and stop on a partial installation. Restore the backed-up createcluster
   policy once the package transaction is over; the dedicated cluster below
   has its own manual start policy. Do not use an unattended rerun as recovery.

### Dedicated durable PostgreSQL, still private

Confirm port 5432 and cluster name are unused. After approval, create a stopped
cluster, with no reboot auto-start:

```sh
sudo pg_createcluster 16 gvai --port 5432 --start-conf=manual
sudo pg_lsclusters
```

Record `/etc/postgresql/16/gvai`, `/var/lib/postgresql/16/gvai`,
its socket/log paths and `postgresql@16-gvai.service` in the manifest.
Keep data on persistent disk owned by `postgres`, not `/tmp`, a container or
the release tree. Never delete it during package/code rollback.

While stopped, review/merge the prepared
[PostgreSQL settings](../deploy/private_https/postgresql.conf) and replace
the dedicated cluster's complete [HBA](../deploy/private_https/pg_hba.conf).
Bind **only** `127.0.0.1:5432`; SCRAM for owner/runtime on `gvai_staging`,
local peer for bootstrap postgres, explicit rejection for everyone else.
Use a small-host starting budget: `max_connections=32`, `shared_buffers=256MB`,
`work_mem=4MB`, `maintenance_work_mem=64MB`; verify under actual test load.
Do not disable `fsync`, `full_page_writes` or `synchronous_commit`.

Review a logging change scoped only to the new `gvai-private-postgres` syslog
identity using the [prepared discard rule](../deploy/private_https/rsyslog-private-postgres.conf).
Do not change other facilities/forwarding rules. Separately inspect and
control this cluster's packaged startup stderr/wrapper log file and journal
routing; server settings alone do not redact those. Validate synthetic canary
absence in **all** sinks before any pilot/key data. If the approved logging
configuration cannot contain raw values, keep the cluster/ingress closed.

Start only `postgresql@16-gvai.service` once these checks pass; immediately
verify actual listener, HBA parse and effective settings locally.
Do not enable boot startup yet. Locally as `postgres`, create:

```sql
CREATE ROLE gvai_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE ROLE gvai_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
  NOREPLICATION NOBYPASSRLS;
CREATE DATABASE gvai_staging OWNER gvai_owner;
REVOKE CONNECT, TEMPORARY ON DATABASE gvai_staging FROM PUBLIC;
GRANT CONNECT ON DATABASE gvai_staging TO gvai_owner, gvai_runtime;
```

Set distinct SCRAM passwords via interactive `psql \password` in a private
non-recorded session, not SQL literals, shell arguments, history or source.
Runtime has no membership in owner. As owner in `gvai_staging`, revoke PUBLIC
CREATE on `public`, apply reviewed migrations 001-003 in order with
`psql -X --set ON_ERROR_STOP=1` using private credential custody, then grant:

```sql
GRANT USAGE ON SCHEMA gvai_authority TO gvai_runtime;
GRANT EXECUTE ON FUNCTION gvai_authority.reserve_advisory_v1(
  text,bytea,text,bigint,text,text,text,text) TO gvai_runtime;
GRANT EXECUTE ON FUNCTION gvai_authority.complete_advisory_v1(
  text,bytea,text,text,boolean) TO gvai_runtime;
GRANT EXECUTE ON FUNCTION gvai_authority.advisory_usage_v1(
  text,bytea,text) TO gvai_runtime;
```

Owner explicitly inserts the approved fresh `(singleton_id=1, authority_id,
epoch=1, trust_domain)` into `gvai_authority.authority_state` once, as in the
[integration setup](../tests/test_postgresql_advisory_integration.py).
Pin those same non-secret values in runtime JSON. Never infer an authority,
reset an existing row or reapply migrations on a partially initialized DB.
Inspect owner/non-superuser status, deferred triggers' SECURITY DEFINER and
pinned search paths, exact runtime grants and absence of direct table,
column, sequence, helper/provisioning or owner-membership access.
Application readiness must independently verify its existing role contract.

### Accounts, release, secrets and mTLS

Use the existing [layout/modes](private_https_staging_v1.md#files-and-installation-layout-future-approved-staging).
Root creates dedicated accounts with `useradd --system --user-group
--no-create-home --shell /usr/sbin/nologin NAME` only if each name is absent.
Prepare every `InaccessiblePaths` directory rather than deleting restrictions.
`/etc/gvai-operator` and `/var/lib/gvai-operator` belong solely to
`gvai-operator` (0700); its config/handoffs are 0600.

Runtime JSON remains root-owned 0400 under `/etc/gvai-runtime` (0700);
systemd `LoadCredential` supplies its process-owned copy. It holds **only**
the restricted runtime DSN and independent 32-byte development verifier.
Operator JSON uses owner DSN and the same verifier, bounded `pilot_units=3`,
`pilot_seconds=3600` for this smoke test; no bootstrap/admin credentials.
Use a private editor/secret handoff, never command-line secret values.
Root-owned immutable release/venv and reviewed `current` pointer are separate
from database, backups and secret paths. Do not serve from a mutable checkout.

Issue development-only server and individual client certificates off-host,
with serverAuth/clientAuth, bounded validity and verified server SAN.
Keep all CA private keys off Lab-01. The proxy gets only server key/chain and
client CA in its existing root:`gvai-proxy` 0750/0640 layout.
Record tester identity/expiry and a renewal owner. No cert revocation service
is added: for a compromised test certificate, close ingress and replace the
test trust/certificates under approval before reopening; API-key revocation
does not revoke transport admission.

Run Gates D-E's ACL/custody, synthetic credential and active systemd sandbox
probes with **unchanged** units before real services. AppArmor user-namespace
restrictions stay enabled; unexplained unit denials need review, not a sysctl
or global profile bypass. Verify independent STOP with its owner without
sending STOP or repurposing its keys.
Validate Nginx as `gvai-proxy`, start backend, pass exact readiness, then start
only `gvai-ingress.service`. Keep distro Nginx masked and all public web ports
closed. Run prepared preflight with the original approved Lab baseline:

```sh
sudo /usr/bin/python3 /APPROVED/PATH/host_preflight.py \
  --target gvai-safety-lab-01 --prepared \
  --baseline /PRIVATE/LAB01/protected-baseline.json
```

## First end-to-end HTTPS acceptance

After A-E and explicit private activation approval:

1. Approved operator invokes the existing CLI privately:

   ```sh
   sudo -u gvai-operator /opt/gvai/venv/bin/python -m gvai.private_staging \
     --config /etc/gvai-operator/operator.json provision \
     --key-output /var/lib/gvai-operator/lab01-smoke-handoff.json
   ```

   This provisions the customer/project and issues its API key. Require
   acknowledged success and a new regular 0600 handoff containing
   `tenant_id`, `principal_id`, `resource_id`, `key_id`, `credential`,
   `expires_at`. On any failure, reconcile durable state and revoke an
   unrecoverable key; do not retry provisioning blindly.
2. Deliver the key through approved private custody to the tester. Establish
   an independently authorized SSH tunnel bound to tester loopback, forwarding
   a local port to Lab-01 `127.0.0.1:8443`. Validate host key independently.
   TLS client connects through the tunnel but validates the **issued server
   SAN hostname** and CA, with its client certificate. No DNS alteration or
   `--insecure`; never place bearer values in command arguments, verbose
   output or history. Use a client reading credentials from a protected file.
3. Require HTTPS `GET /readyz` = 200 with exactly
   `{"status":"ready","advisory_only":true,"enforcement_applied":false}`.
   Missing/untrusted client certificate and wrong server hostname must reject.
   With the customer's key, `GET /v1/usage/RESOURCE_ID` must initially report
   top-level `version=1`, `advisory_only=true`, `enforcement_applied=false`;
   its `usage` object has allowance 3, consumed/reserved/completed/failed 0,
   remaining 3.
4. Submit `POST /v1/evaluations`, `Content-Type: application/json`,
   `Authorization: Bearer <credential read privately>`. Substitute the
   issued `resource_id` **only**, retain this request ID and exact body:

   ```json
   {
     "version": "v1",
     "request_id": "lab01-smoke-001",
     "resource_id": "ISSUED_RESOURCE_ID",
     "telemetry": {
       "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
       "repeated_action_delta": 0, "recursion_depth": 0
     },
     "reported_effects": []
   }
   ```

   Require HTTP 200, `outcome=reason=evaluated`, non-null evaluation with
   `advisory_only=true`, `enforcement_applied=false`.
5. HTTPS response's `usage` object now reports allowance 3, consumed 1,
   reserved 0, completed 1, failed 0, remaining 2. Privately as owner,
   independently verify the
   provisioned tenant's `advisory_pilots.consumed=1` and exactly one completed
   `advisory_attempts` row joined to its reservation event/request ID.
   Record only IDs/counts and fixed pass/fail labels, not verifiers/payloads.
6. Close ingress, restart **only** backend, verify ready, explicitly reopen
   private ingress. Same key/usage must survive. Exact retry must return
   HTTP 409 with `error.code=replay` and no evaluation field, no new charge;
   changed telemetry with the same ID must give 409 `error.code=conflict`,
   no evaluation field and no new charge.
   Replay is **not** a cached evaluated response. Missing key gives 401,
   revoked/wrong-project key 403; no consumed increase.
7. Perform Gates F-G's isolated database outage/restart and tenant suspension.
   Same cluster/data must retain the key, consumed/completion/request records;
   no successful evaluation while commit is uncertain. Reconcile the exact
   request ID before reopening. Validate numeric-only logs and canary absence.
   Securely remove only the named handoff after delivery/reconciliation.

## Rollback and recovery acceptance

Close `gvai-ingress.service` first, then stop only `gvai-advisory.service`
and, if needed, `postgresql@16-gvai.service`. No experiment/STOP control is
exercised. Keep ambiguous/charged records and ingress closed.

Code rollback restores the retained reviewed release pointer/unit/config
backups while stopped, preserving ownership/modes/ACLs. No schema, keys,
authority head or usage rollback. Validate compatibility/readiness and active
sandbox, then backend before explicitly reopening private ingress.

For an installation abort, restore only backed-up approved configuration,
remove only the verified temporary package guard and named new staging files
when safe. Keep a disabled/stopped PostgreSQL cluster and its persistent data.
If package removal is approved, simulate and remove **only newly installed
manifest packages** after inspecting dependencies; no autoremove, database
purge, `pg_dropcluster`, broad deletion or automatic account/data cleanup.
Restore only masks introduced by this task if the founder explicitly approves
it and no public/default service can start. Initial uninstallation need not
erase packages/data to count as a safe rollback.

Before pilot use, take a restricted logical backup of this cluster/database
with globals/role custody handled separately; restore into an approved
separate closed disposable database and verify schema/identity and numeric
usage/request/key-state parity privately. This is recovery evidence, **not**
permission to replace the active database with stale history. Recovery of
the active service requires accounting reconciliation and separate approval;
readiness never clears an authenticated restore fence.

Acceptance: staging sockets closed on abort; persistent records unchanged;
original policy/loaded-profile/unit baseline matches; original SSH/firewall
and independent STOP behavior unchanged except explicitly approved firewall
hardening; no resource regression; private restart/replay and restore drill
evidence accepted by founder. Unexplained drift keeps staging closed.

## Genuine blockers and shortest next authorization

1. Founder approval for Lab-01 read-only refresh, its private baseline,
   controlled manifest and private activation (separate decisions).
2. **Known inactive host firewall and unknown attached Cloud Firewall rules**:
   verify/harden with SSH recovery before any service activation.
3. On-host package/config/account/secret/certificate installation and real
   systemd/network/custody/logging validation are still unperformed.
4. Fresh restricted PostgreSQL/authority setup plus real HTTPS durable usage,
   restart/outage/replay and closed restore evidence must pass.

Absent Nginx/PostgreSQL/accounts are planned setup steps, not architecture
defects. Lack of Test-01-specific profiles on Lab-01 is not a blocker.
Public DNS/ACME, payments, dashboards, worker execution and new STOP
integration are not prerequisites for this private hosted evaluation.
Public HTTPS remains separately prohibited pending a future approved network
and service-sandbox review. This preparation stops at founder review.

## Offline preparation validation

Focused command (using the already installed pytest environment, with no
dependency installation):

```sh
/usr/local/py-utils/venvs/pytest/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_host_preflight.py tests/test_private_https.py \
  tests/test_private_staging.py tests/test_commercial_http.py \
  tests/test_postgresql_advisory_integration.py
```

Result: **131 passed, 51 skipped**. Skips are four real-Nginx tests and 47
opt-in PostgreSQL integration cases; no host or real database evidence is
claimed. The default workspace Python lacked pytest; invoking the installed
pytest script also failed imports because its isolated interpreter did not
include the repository. Using that environment's Python with `-m pytest`
resolved collection without installing packages.

Changed Python passes Python 3.9 syntax parsing; local documentation file-link
targets, new-runbook ASCII/final newline and `git diff --check` pass.
These offline checks do not authorize deployment or replace Gates A-G.
