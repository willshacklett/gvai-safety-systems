# Private HTTPS staging V1

For the approval-gated Ubuntu test-host preflight, experiment-policy baseline
and active sandbox/outage/rollback gates, see
[on-host staging readiness](onhost_staging_readiness_v1.md). No host connection
is authorized by either document.

## Approval and product boundary

These are **prepared, uninstalled** test-server configurations. This task does
not contact DigitalOcean, modify a server, install packages, change DNS or
activate ingress. Nothing is production-ready by virtue of this runbook.

The application remains an advisory API: `advisory_only=true`,
`enforcement_applied=false`. It does not control a customer's workload. No
provisioning/key-management endpoint, signer, checkpoint, SQLite grant,
recovery clearance, billing or supervisor STOP integration is added.

[Private application](private_staging_v1.md) and
[advisory accounting](commercial_advisory_backend_v1.md) retain their existing
authentication, quota, ambiguous-commit and completion behavior. The proxy
passes the customer Authorization header unchanged to that application.
Client certificates add a private transport admission check, **not** tenant
authorization or entitlement authority.

## Prepared topology

```text
Invited operator/tester with approved client certificate
  -> separately managed authenticated SSH tunnel / private host access
  -> 127.0.0.1:8443 Nginx (TLS 1.2/1.3, mandatory client certificate)
  -> 127.0.0.1:8080 advisory backend
  -> 127.0.0.1:5432 separately provisioned PostgreSQL
```

Only loopback listeners are included. There is no port 80 redirect, ACME client,
DNS resolver, publicly bound listener, automatic certificate download or
DigitalOcean API integration. External firewall rules must also deny 8080,
8443 and 5432. An independently approved SSH tunnel may expose the TLS listener
to invited testers locally; bind the tunnel only to client loopback.
TLS clients must validate the expected server certificate hostname even when
connecting through a tunnel; do not disable certificate verification.
Any later non-loopback listener requires a separate network/security review
and changes to the systemd network restrictions. Do not silently remove them.

## Prerequisites before any server work

- Separate founder authorization for the target test server, network access,
  approved packages and operational activation.
- Reviewed Nginx with its SSL module, OpenSSL, Python/dependencies, and systemd
  supporting `LoadCredential` and network sandbox directives (Ubuntu 24.04-style
  baseline). Confirm all directives on the actual host rather than relying on
  this workspace's configuration-string tests.
- Root-owned immutable application release and dependency environment;
  dedicated non-login accounts `gvai-api` and `gvai-proxy`, plus a separate
  operator account. Neither service receives sudo, Docker access, login
  credentials, owner-role membership, or authority filesystem privileges.
- Development-only server certificate/chain and private key, explicitly trusted
  client CA and individually issued tester certificates with appropriate
  serverAuth/clientAuth usage, validity, hostname and renewal policy.
  Do not put a CA private key on the server. Use a dedicated test trust domain;
  no production keys or signing/checkpoint credentials.
- Non-superuser PostgreSQL owner `gvai_owner`, restricted runtime `gvai_runtime`,
  explicitly provisioned `gvai_staging` database and authority identity.
  Follow migrations 001-003 and runtime grants in the backend documentation.
  Names are example deployment choices, not implicitly provisioned identities.
- Separate configuration/secret custody, private ingress and database backup
  reconciliation plan. Runtime configuration pins the existing authority;
  readiness is **not** an authenticated recovery check.

## Files and installation layout (future approved staging)

The following actions are documentation only, not commands executed by this task.

| Prepared file | Intended destination |
|---|---|
| [nginx.conf](../deploy/private_https/nginx.conf) | `/opt/gvai/RELEASE/deploy/private_https/nginx.conf` |
| [Backend unit](../deploy/private_https/gvai-advisory.service) | `/etc/systemd/system/gvai-advisory.service` |
| [Ingress unit](../deploy/private_https/gvai-ingress.service) | `/etc/systemd/system/gvai-ingress.service` |
| [Readiness checker](../deploy/private_https/check_ready.py) | In the immutable release, invoked by the backend unit |
| [PostgreSQL settings](../deploy/private_https/postgresql.conf) | Review/merge into separate test PostgreSQL settings |
| [HBA example](../deploy/private_https/pg_hba.conf) | Review as a complete test HBA, not an append-only allowlist |
| [PostgreSQL log discard](../deploy/private_https/rsyslog-private-postgres.conf) | Early rsyslog filter ahead of any forwarding/catch-all rules |

Application, units, checker and proxy configuration are root-owned, not writable
by service accounts, and mode `0644` (directories `0755`). `/opt/gvai/current`
is an operator-controlled pointer to a reviewed immutable release.
`/opt/gvai/venv` is a reviewed root-owned environment containing the declared
runtime dependencies. Do not execute a mutable repository as a service.

Create secret files **outside source**, never through command-line values:

- `/etc/gvai-runtime`: root-owned `0700`; `runtime.json`: root-owned `0400`.
  Its fields are the existing private runtime config with port **8080** and
  max_connections **8**. The backend unit's `LoadCredential` supplies an
  owner-only read-only copy at `%d/runtime.json` owned by the runtime process.
  Operator credentials must never appear in it. systemd credentials are not
  encrypted-at-rest storage; separately control disk/backups and root access.
- `/etc/gvai-ingress`: root:`gvai-proxy` `0750`; server-chain.pem and
  client-ca.pem `0640`; server-key.pem root:`gvai-proxy` `0640`.
  The unprivileged proxy needs to read its TLS key, but not database/API
  verifier/operator secrets. Certificates/keys are deliberately absent here:
  missing files must prevent Nginx startup.
- `/etc/gvai-operator` and `/var/lib/gvai-operator`: operator-only `0700`;
  operator configuration and one-time handoffs `0600`. Services mask these
  paths. Provision/suspend/revoke using the existing separate operator CLI;
  never run provisioning through an HTTP route.

The backend unit only permits loopback network access; no outbound APIs or
customer workloads are allowed. `ProtectSystem`, private temporary/device
namespaces, empty capabilities, no-new-privileges, process/memory/FD limits and
account separation reduce blast radius. They are not a proof of containment.
Validate the host's cgroup/BPF support for `IPAddressDeny`; unsupported network
sandboxing must not be treated as successful enforcement.

## Ingress contract, bounds and logging

The raw method plus `$request_uri` is allowlisted before proxying:

- `POST /v1/evaluations`
- `GET /v1/usage/PROJECT_ID` with the existing bounded identifier grammar
- `GET /healthz` and `GET /readyz`, still behind mandatory mTLS

Query strings, percent-encoded path substitution, alternate methods,
provisioning, key management and additional routes are denied. Nginx is not
a customer identity verifier; both evaluation and usage are reauthenticated by
the backend against current database state and project ownership.

Incoming forwarding/identity headers are discarded. Only Authorization and
Content-Type are forwarded; the proxy owns Host, X-Forwarded-Proto=https and
X-Forwarded-For. `Forwarded` and forwarded host are removed. The backend does
not trust these headers to grant access. There are no response caches,
upstream retries, stale responses, redirects to HTTP or authority fallbacks.
Backend 403/409/429/503 statuses pass through; an ingress-generated error is a
fixed 503 JSON `ingress_unavailable`, including rejected routes and rate limits.
This intentionally exposes no Nginx error details. Unknown accounting status
never means permission to evaluate.

Bounds: one worker/128 worker connections, 16 KiB bodies, bounded headers,
five-second header/body/write timeouts, no persistent client keepalive,
eight active requests globally/four per source, two requests/second/source with
four burst slots. Nginx timeout semantics are generally inactivity limits,
not a whole-request wall-clock deadline; incomplete-header sockets still share
the worker connection/FD budget. SSH-tunneled clients share one loopback rate
bucket. This is deliberately conservative private-staging throttling, not a
per-tenant distributed billing rate limiter. One Nginx and one backend process
are assumed; rate/connection budgets are not coordinated across replicas.

The upstream connect timeout is one second, send timeout five seconds and read
timeout 20 seconds to cover bounded multi-transaction advisory work.
A disconnect/timeout can leave a committed charged attempt; exact retries
return replay without re-evaluation. Never automatically substitute a fresh
request ID after timeout or unknown commit.

Nginx access logs contain **only** numeric status, byte count and request time.
No client address, URL, query, certificate subject, Authorization, body or
upstream credential is logged. Raw Nginx error logs are discarded because
native error entries can embed request lines/headers; ingress stderr is also
discarded. Monitor status totals and unit failure/exit state, not raw request
traces. Protect log files and set short rotation/retention through the approved
host logging policy; no external log forwarding is authorized.

PostgreSQL error text can also embed customer values. The sample settings
disable statements and parameters and route raw server logs to the dedicated
syslog identity, which the accompanying early rsyslog rule discards. **Both**
pieces and rule ordering must be tested together before customer data; otherwise
do not claim database logs are redacted. PostgreSQL startup stderr and existing
distribution logging wrappers must also be routed/discarded deliberately;
these sample files do not automatically control a packaged database unit.
Discarding raw logs reduces diagnostics: monitor private numeric DB health and
availability separately. Do not enable query/error-body logging for debugging.
Application stderr contains fixed event names only; stdout is discarded.

## Approved staging start, checks and shutdown

After separate authorization, an operator should:

1. Verify immutable release content, dependencies, account/secret ownership,
   trust/certificate validity, PostgreSQL loopback/HBA and least privileges.
   Confirm the separate independent supervisor STOP remains unchanged.
2. Validate configuration **before starting listeners**:

   ```sh
   sudo -u gvai-proxy /usr/sbin/nginx -t -q -c /opt/gvai/current/deploy/private_https/nginx.conf
   systemd-analyze verify /etc/systemd/system/gvai-advisory.service /etc/systemd/system/gvai-ingress.service
   ```

   Expected runtime/log directories must exist with the same service ownership
   for manual Nginx validation; systemd otherwise creates them on service start.
   Validation failure is a stop condition, not permission to weaken TLS or units.
3. Start the backend first. `ExecStartPost` checks the exact local ready/advisory
   payload with bounded retries, without printing bodies. A failed check makes
   startup fail and systemd terminates the process. Nginx requires successful
   backend start. Liveness alone is not startup readiness.
4. Start ingress. Inspect listeners locally: only loopback 8443/8080/5432.
   Verify no default distro Nginx site or other listener exposes the backend.
   Validate mTLS without client certificate, wrong CA and wrong hostname all
   deny; a valid client may reach diagnostics, but still needs a customer key
   for evaluation/usage. No public firewall/DNS activation is authorized.
5. Through the private tunnel, test one invited pilot: advisory evaluation,
   usage, duplicate replay, changed-payload conflict, cross-tenant denial,
   expired/revoked-key denial and operator suspension. Do not put bearer keys
   in shell history, process arguments, verbose curl output or proxy logs.
6. Drill backend/database outage and throttling: no evaluated result on
   uncertainty. Inspect log samples using only synthetic canary credentials.
   Confirm no canary appears in proxy, application, database or system logs.

Nginx SIGQUIT gracefully stops acceptance; systemd kills remaining processes
after ten seconds. Backend SIGTERM fences new database leases and stops the
listener, drains existing leases, and is killed as a group after 20 seconds.
These process controls are **not** the independent supervisor STOP and do not
retroactively undo valid committed advisory attempts.

`Restart=on-failure` is bounded to three starts/minute with a five-second delay.
Backend startup probes do not run continuously; later readiness must be
monitored privately. No new live watchdog is installed here.
An intentional backend stop also stops its Requires-dependent ingress.
Systemd does not automatically restart a stopped dependent after a backend
restart: explicitly start ingress only after backend readiness passes again.

## Deployment and rollback runbook

No automatic deployment workflow or infrastructure mutation is included.

1. Retain the current reviewed release path, unit files, config and test evidence.
   Preserve secret custody; never export credentials to a source backup.
2. Obtain approval, stop ingress **before** stopping backend, and record the
   operational state without keys or customer payloads. A restart can abandon
   charged attempts; reconcile uncertain accounting rather than re-evaluating.
3. Install a new immutable release and reviewed environment. Switch the
   root-owned `current` pointer only while services are stopped. Do not change
   database schema, authority history, keys or entitlements in this rollout.
4. Validate units/config, reload the systemd unit definitions, start backend,
   then ingress after readiness. Run the private smoke/adversarial checks.
5. On any failure, stop ingress/backend, restore the previous reviewed code/unit
   pointer, validate, and start in the same order. Keep ingress closed if
   dependency, credentials, authority or accounting status is uncertain.
6. **Code rollback is not database restore.** Never restore a stale database
   snapshot or checkpoint anchor to make readiness green. Data recovery needs
   explicit separate reconciliation/approval; independent production rollback
   resistance is not proven by this application.

## Validation and remaining launch blockers

[Automated tests](../tests/test_private_https.py) assert listener restrictions,
mandatory mTLS, forwarding allowlist, route/header/body/rate bounds, no retry or
cache, numeric logs, service separation and exact readiness semantics. These
static/fake-opener tests are not Nginx parser, network or TLS evidence.

Optional tests use **real Nginx and disposable local TLS certificates** only
when Nginx/OpenSSL are already installed. They run `nginx -t` and exercise client
certificate admission, forwarding spoof rejection, redaction, blocked routes,
backend denial/status preservation and throttling against a local test backend.
That backend is simulated; these tests are not real PostgreSQL or DigitalOcean
deployment evidence. Missing tools cause explicit skips, not a success claim.

### Repeatable isolated official-container validation

[Docker integration tests](../tests/test_private_https_docker.py) opt in separately:

```sh
docker pull nginx:stable
GVAI_RUN_HTTPS_DOCKER=1 python -m pytest -q -s -p no:cacheprovider tests/test_private_https_docker.py
```

These commands require explicit development-container authorization. The image
must already exist when the tests run (`--pull=never`). The tests create one
uniquely named official Nginx container, install Python and systemd **inside
that disposable container only**, then disconnect its Docker bridge before
starting listeners. No ports are published, no host network or privileged
container mode is used, and no volumes or production credentials are supplied.
Source/config are copied in and made root-owned, not mounted writable.

Temporary CAs and server/client certificates are generated locally, including
an untrusted client; CA private keys are never copied into the server. The
unmodified deployed config paths and actual `gvai-proxy` account run `nginx -t`
and the proxy. The actual advisory service/evaluator, customer key verifier,
authorizer and HTTP server run as `gvai-api`; test accounting/usage state is
**in-memory**, not PostgreSQL. This validates transport integration and actual
customer authentication/tenant denial, not durable accounting or DB restore.

Coverage includes TLS 1.2/1.3, missing/untrusted client and wrong-server-hostname
rejection, revoked/expired/missing bearer rejection without evaluator calls,
cross-tenant reads/evaluation denial, exact retry, 16,384-byte acceptance versus
16,385-byte rejection, throttling, forwarding spoof denial, redacted logs,
loopback-only socket topology, and real backend-process outage.
Loopback is not a barrier against trusted processes inside the same host/network
namespace: an operator/root process can connect directly to the backend there.
External clients have no direct backend route in this isolated test topology.

Systemd validation runs `systemd-analyze verify` with real Python and Nginx
executable paths, both service accounts and the actual unit files present.
`systemd-analyze security --offline=yes` checks the configured restrictions.
Real non-root filesystem tests verify secret/account separation, immutable
code/config, zero effective capabilities and no-new-privileges; the last two
are enforced by the Docker test environment. **Systemd is not PID 1 here**:
LoadCredential delivery, service lifecycle, mount restrictions, IPAddressDeny
BPF/cgroup enforcement and full unit sandbox activation still require an
approved systemd host/VM. Offline analysis is not proof they ran.

The fixture removes its named container and temporary PKI directory in `finally`,
including on assertion failure. Official image cache is retained; no host
packages or installed services are changed.

Current real-container evidence:

- **18 passed** using official `nginx:stable`, Nginx **1.30.6**, image digest
  `sha256:66b50d24288dba67f3d000b31223daefc4868c58d29aaacb6a4ff9771597b5eb`.
- Both actual unit files passed `systemd-analyze verify` under systemd
  **257.13**, with real executable paths and service accounts. Offline security
  analysis completed for both; no claim of systemd runtime sandbox activation.
- Focused static/private HTTP regressions: **83 passed, 4 skipped** (the
  older host-Nginx tests; host Nginx remains absent).
- Complete default offline suite: **729 passed, 362 subtests, 69 skipped**:
  47 opt-in PostgreSQL, four host-Nginx and 18 opt-in Docker tests. The 18
  Docker cases passed separately; this mission does not rerun real PostgreSQL.

### Confirmed non-root startup defect

The initial real non-root `nginx -t` parsed the old configuration but failed:

```text
mkdir() "/var/cache/nginx/fastcgi_temp" failed (13: Permission denied)
```

Even unused FastCGI/uWSGI/SCGI defaults need writable temporary paths at startup.
The repair pins all three under `/run/gvai-ingress`, the existing service-owned
runtime directory, without weakening the account or read-only filesystem.
The real regression reconstructs the old three-missing-directive config and
requires it to fail while the repaired original config starts successfully.
No application, database migration, signing, checkpoint or STOP behavior changes.

Run focused and full offline regressions:

```sh
python -m pytest -q -p no:cacheprovider tests/test_private_https.py tests/test_private_staging.py tests/test_commercial_http.py
python -m pytest -q -p no:cacheprovider tests
```

Next blocker: founder-approved **on-host private deployment validation** of
Nginx syntax/mTLS, unit/network sandbox support, role/secret/log custody, outage
and restart drills. Then address client-certificate revocation/renewal, reviewed
private monitoring, support/onboarding, tested backups/reconciliation and
payments under separate missions. No TLS handshakes, infrastructure installation
or independent checkpoint protection should be claimed from static tests.

### Original preparation evidence (before real-container validation)

- Focused: **83 passed, 4 skipped** (the four real Nginx/mTLS tests).
- Full offline: **729 passed, 362 subtests passed, 51 skipped** (47 opt-in
  PostgreSQL cases and four unavailable real Nginx/mTLS cases).
- Nginx is not installed in this workspace. No Nginx parser or real proxy TLS
  handshake was validated; no additional packages were installed.
- `systemd-analyze verify` parsed both units but exited nonzero because target
  executables `/opt/gvai/venv/bin/python` and `/usr/sbin/nginx` are absent
  locally. This is **not** a complete successful unit/host validation.
- PostgreSQL, rsyslog, cgroup network policies, actual service accounts and
  deployed certificate/secret permissions are prepared examples and have not
  been installed or activated. All require on-host validation after approval.
