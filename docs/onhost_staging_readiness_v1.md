# On-host staging readiness V1

## Status and scope

This is a prepared, **unexecuted** procedure for the existing Ubuntu 24.04
DigitalOcean test server `gvai-safety-test-01`. No SSH, cloud API, host inspection,
installation, firewall/service change, DNS change or deployment was performed.
Offline tests prove script behavior, not this server's readiness.

For the separate Lab-01 host, use the
[Lab-01 commercial staging adaptation](lab01_commercial_staging_v1.md).
Explicit `--target gvai-safety-lab-01` selects that exact hostname and preserves
its policy baseline/user-namespace restriction without inventing Test-01's
experiment labels. The default Test-01 target and its enforcing-label checks
are unchanged. Neither procedure authorizes connecting or changing a host.

Read [private HTTPS staging](private_https_staging_v1.md),
[private application](private_staging_v1.md) and
[PostgreSQL advisory backend](commercial_advisory_backend_v1.md) first.
Reuse their existing topology, three reviewed migrations and units.
Do not create another ingress, authority, STOP or recovery architecture.
All responses remain advisory-only, never controlled execution.

**Global NO-GO:** any unexplained privilege, networking, policy, identity,
logging, accounting or recovery result. Close only the new staging ingress,
preserve evidence privately, and stop for founder review. Never relax AppArmor,
Bubblewrap, independent supervisor STOP, signing or checkpoint gates to make a
test pass. Never interrupt an existing experiment to free a port or memory.

## Approval gates

Two approvals are separate:

1. **Read-only discovery:** target identity, access method, time window and
   authorization to run the preflight as root. Obtain the actual server host-key
   fingerprint through an independently trusted channel. Do not use unattended
   host-key acceptance or paste access credentials into commands/logs.
2. **Controlled staging changes:** approve an explicit manifest, account/port
   allocation, development-only secrets, package/dependency list, isolated
   database cluster, backups, sandbox probes and failure drills. Discovery is
   not approval to install or start anything.

No approval is granted by this document or by exit status zero.
Until approval 1, do not connect. Until approval 2, do not mutate the host.

## Gate A: read-only host discovery

The [preflight](../deploy/private_https/host_preflight.py) uses only file reads
and fixed observation commands. It never installs packages, opens connections,
creates files, calls sudo, starts/stops services or changes policies.
Run it with the already installed Python 3.9+ after approved transfer of a
reviewed copy to a root-owned path. Operator redirection saves evidence;
the script itself only emits JSON to stdout.

```sh
sudo /usr/bin/python3 /APPROVED/PATH/host_preflight.py
```

Exit 1 is expected on initial inventory without a reviewed baseline or absent
staging accounts. Inspect each fixed Boolean check; never treat an incomplete
report as ready. Exit 0 means only listed automated checks passed.
`deployment_authorized` is always false.

Checks:

| Check | GO requirement |
|---|---|
| Host/OS/PID 1 | Exact hostname, Ubuntu 24.04, systemd PID 1, systemd >=255 |
| AppArmor | Enabled; exact kernel labels `gvai-worker (enforce)` and `gvai-bwrap (enforce)` |
| Protected evidence | Root-controlled policy tree, loaded profiles, worker/bwrap unit state and referenced unit/drop-in bytes available |
| Firewall | UFW observation succeeds and reports active; **manual rule review still mandatory** |
| Inventory listeners | No existing TCP listener on 5432, 8080 or 8443, even loopback |
| Resources | >=5 GiB free root disk, >=2 GiB available memory, cgroup v2; additional experiment budget reviewed manually |
| Accounts | `gvai-api` and `gvai-proxy` nonroot, dedicated primary groups, non-login shells, no extra supplementary groups |

The report identifies its selected `target` and adds fixed package-availability
Booleans for Nginx, psql and OpenSSL. Missing executables are inventory evidence;
prepared mode requires them. Versions/modules remain an on-host manual check.

The repository does not define existing host `gvai-worker`/`gvai-bwrap`
profiles. If actual kernel labels differ, **stop**; obtain the founder-approved
policy mapping and update/review the check before proceeding. Do not rename,
reload or invent profiles. Absent worker/bwrap *units* are fingerprinted as
reported by systemd: these may be profile names rather than services. Founder
review must identify every actual experiment unit, AppArmor include dependency,
mount and independent STOP process; automated evidence cannot infer these.

Policy fingerprints include the entire `/etc/apparmor.d` tree and metadata,
including disabled links and includes. External/broken symlinks, unsafe custody,
missing commands, malformed output and observation errors block collection.
Unit fingerprints include PID/state, fragment/drop-in paths and bytes. Loaded
profile ordering is normalized. No raw profile text, unit contents, process
arguments, firewall rules, host addresses, secret contents or command errors
are emitted; firewall/listener evidence is hashed.

An operator must privately review raw firewall/listener/policy information
without publishing it. Verify host firewall **and DigitalOcean firewall**
exclude public 5432/8080/8443, current SSH source restrictions are unchanged,
no alternative NAT/proxy/container path exposes the service, and existing
experiment listeners remain accounted for. UFW being active alone is not a
firewall proof. Non-UFW deployments require a reviewed preflight adaptation,
not disabling the check. The script intentionally does not access cloud APIs.

### Founder-reviewed baseline

Before any authorized mutation, retain the full initial report privately.
After founder confirms policy/experiment state, save only the report's
`evidence.protected` object as a root-owned mode-0600 JSON baseline in a
root-owned mode-0700 directory outside source. This is an **operator action**,
not automatic trust bootstrap. Review the file before accepting it.

```sh
sudo /usr/bin/python3 /APPROVED/PATH/host_preflight.py \
  --baseline /PRIVATE/REVIEWED/protected-baseline.json
```

After preparation/start, use `--prepared --baseline ...`. Prepared checks
require all three intended TCP ports on loopback plus root-controlled runtime
secret directory/file, exact unit-file modes, proxy secret directory and
certificate/key metadata. It never reads credential or certificate contents.
It rejects symlink components in custody checks.

Hash equality is evidence of observed continuity, **not** authorization or a
tamperproof external anchor. Root can alter both baseline and host. Keep an
independently retained approved copy; do not regenerate the baseline on drift.
Profile reloads with identical bytes, root compromise, ACLs, hardlinks, dynamic
experiment files and processes not in the mapped inventory require separate
review. Drift from a legitimate experiment restart still requires explanation;
do not automatically accept a new PID. Avoid concurrent experiments during the
short validation window by agreement, not by stopping their processes.

## Gate B: explicit pre-change backup and allocation

Before change approval, record:

- Existing experiment unit/drop-in and AppArmor tree fingerprints; independently
  supervised STOP state verified by its owner without sending a STOP command.
- Existing unit files, owned release pointers, Nginx/PostgreSQL configuration
  and service states. Back up **only approved configuration paths**, preserving
  ownership, permissions, links, extended attributes and ACLs; hash the backup.
  Store privileged/sensitive material outside source with restricted access.
- Current reviewed code/dependency artifacts and their checksums; list every
  new file/directory/account/service and which did not exist before.
- Existing database services/ports and experiment usage. Never snapshot/restore
  a shared live experiment database as a staging convenience.
- A verified way to restore configuration from backups with services closed,
  an operator available to abort, resource budget and no-active-experiment
  window. If restore ownership/metadata cannot be verified, NO-GO.

Do not copy a live database data directory as a backup. For the **new isolated
test cluster only**, use a reviewed logical backup plus restore verification
in another disposable database if recovery testing is approved. Never restore
stale accounting or authority history to an open service.

NO-GO on any occupied reserved port, shared account, unexpected supplementary
group/sudo/polkit/Docker permission, ACL granting cross-service reads, mutable
release tree or insufficient resources. Do not change global firewall, global
rsyslog routing or existing PostgreSQL/Nginx defaults during this procedure.
The prior logging examples require separate review; they are not permission to
alter logging for other experiments.

## Gate C: PostgreSQL isolation and migration plan

After explicit approval only:

1. Provision a **new dedicated test cluster/data directory/service**, not a
   migration into an existing experiment database. Reserve loopback 5432 only
   if unused. No host-port Docker publishing, shared volumes or public bind.
   If existing infrastructure uses that port, stop for a separately reviewed
   port/config change; do not stop it.
2. Use only fresh development credentials. Bootstrap admin performs cluster/
   role/database creation only. Non-superuser `gvai_owner` applies migrations
   001, 002, 003 to a fresh `gvai_staging` database. Runtime `gvai_runtime` has
   no owner membership, superuser, createdb, createrole, replication or bypassrls.
3. Grant only schema USAGE and the three advisory entry EXECUTE permissions.
   No table/column/sequence privilege, raw reservation helper, entitlement or
   ledger writes. Explicitly provision the pinned advisory authority identity.
   Verify privileged bootstrap credentials never enter either runtime service.
4. Restrict HBA to these roles/database on loopback with SCRAM; reject others.
   Validate logging with synthetic canaries, including startup stderr and the
   isolated cluster's distribution wrapper. Prefer isolated log handling; do
   not install a global discard rule without separate approval.
5. Reproduce application-restart persistence, expired/revoked-key denial,
   cross-tenant denial, concurrent final quota, replay/conflict, ambiguous commit
   withholding and customer inability to modify entitlements against this
   cluster. Fake accounting and prior container mTLS tests do not substitute.

GO requires exact role/entry contracts verified by application startup and
independent read-only owner SQL review. Missing/uncertain identity or quota
evidence means NO-GO. Never grant signing/checkpoint/recovery privileges.

## Gate D: account, release and credential custody

Follow the exact layout/modes in the private HTTPS runbook. Use root-owned
immutable release/environment, `gvai-api` and `gvai-proxy`, and a separate
non-service operator account. Inspect supplementary groups, ACLs, parent
directories, sudo/polkit rules and writable code/service search paths manually.

Runtime JSON: root-owned 0400 under root-only 0700 directory; only restricted
DB DSN and independent development verifier, port 8080/max_connections 8.
Operator configuration and handoffs: separate operator-only 0700/0600 paths.
Proxy: its own client CA/server certificate/private key with group-only reads.
CA signing key stays off-host. No production/customer credential reuse.
Never display, hash into public reports, or place secret values in shell
arguments/environment dumps. Use synthetic canaries for exposure tests.

GO requires services cannot read each other's secrets, cannot write release/
unit/config files, and operator keys cannot be reached over HTTP. Missing
paths needed by `InaccessiblePaths` must be prepared explicitly; do not remove
sandbox directives. The `current` release symlink requires an independently
reviewed root-controlled target; preflight does not validate release content.

## Gate E: active systemd sandbox and credentials

`systemd-analyze verify` and `security --offline=yes` are prerequisites, **not**
runtime proof. Existing container evidence never ran systemd as PID 1.

Before starting real staging, approve two temporary uniquely named transient
probe units. Copy the exact relevant restrictions from each prepared service;
do not use `--privileged` or weaken `IPAddressDeny`, mount or capability settings.
Use only a mode-0400 **synthetic marker credential**, never a real runtime JSON.
A root-owned probe program must emit fixed pass/fail labels only.

GO criteria inside the active unit:

- Effective UID/GID equal the intended nonroot account; effective capabilities
  zero; `/proc/self/status` reports `NoNewPrivs: 1`.
- `LoadCredential` provides the exact synthetic marker via
  `CREDENTIALS_DIRECTORY`; check its expected value internally without printing
  it. Copy is readable by that unit only, mode excludes group/world, and is
  removed when the transient unit ends. Runtime can start with real development
  config only after this marker test succeeds.
- Attempts to write a designated existing root-owned release/config path fail
  (never test-write protected experiment files); attempts to read masked
  operator/other-service test-marker paths fail. Check private `/tmp` and device
  view without mounting or altering host policy.
- A loopback-only synthetic listener is reachable. A bounded TCP `connect_ex`
  to the host's **own reviewed non-loopback address** must return EACCES/EPERM
  under the active unit. Do not use an Internet destination, DNS or production
  endpoint. Refused/timeout/unreachable alone is **not** proof of BPF denial.
  Root privately verifies the active cgroup's egress/ingress BPF attachments.
- Process/memory/FD cgroup limits match the unit. No sandbox-related denial,
  downgrade or unsupported-directive warning is unexplained.

Stop/remove only the named transient probes and synthetic files after
validation; retain redacted evidence. If probes cannot be constructed without
changing existing experiments or no local safe network target is available,
NO-GO and move sandbox testing to a separately approved disposable VM.
This runbook does not supply or silently run a privileged probe.

## Gate F: private Nginx/mTLS and live smoke tests

After Gates A-E and change approval, use the existing exact Nginx config and
units; no default distro site activation. Execute reviewed `nginx -t` as
`gvai-proxy`, verify the existing executable paths, then start backend before
ingress. `ExecStartPost` must pass the exact advisory-ready payload.
Run prepared preflight with the approved baseline after every drill:

```sh
sudo /usr/bin/python3 /APPROVED/PATH/host_preflight.py --prepared \
  --baseline /PRIVATE/REVIEWED/protected-baseline.json
```

GO requires all automated checks plus manual continuity of other experiment
listeners and firewall/cloud state. Only loopback 8080/8443/5432 is accepted.

Through approved loopback-bound private access, validate trusted client
certificates on TLS 1.2/1.3; missing/untrusted/expired client and wrong-server
hostname reject. Never disable verification. Customer key still required for
evaluation/usage. Test tenant A versus B, missing/expired/revoked keys, body
16,384/16,385 boundary, throttling, replay/conflict and blocked provisioning
routes. Compare numeric DB counts/evaluator-call evidence for denied requests.
Inspect synthetic canary absence in response, access/application/database/
system logs privately; fixed error JSON and numeric logs only.

## Gate G: reversible drills

Every drill touches **only newly approved staging units/cluster/test tenants**.
No experiment unit, AppArmor policy or independent STOP control is exercised.

| Drill | Action after approval | Exact GO/abort check |
|---|---|---|
| Backend restart | Stop new ingress, restart staging backend; wait for readiness, explicitly start ingress | Same key works, stored usage persists, completed ID replays without evaluation; no new charge on exact retry |
| Database outage | Stop only the new isolated cluster while a bounded synthetic request runs | No evaluated response while accounting uncertain; ready/usage/evaluation fail closed; never change ID to hide ambiguity |
| Database recovery | Restart same cluster/data, inspect committed attempt state before reopening ingress | Exact ID either replay/charged or absent/not charged; no automatic refund/re-evaluation; unresolved status keeps ingress closed |
| Tenant suspension | Operator suspends dedicated test tenant independently of customer keys | All its keys deny new evaluation and usage; no unauthorized quota increase; previously committed units remain charged |
| Shutdown | Stop staging ingress, SIGTERM staging backend using its unit | Listener closes, new leases deny, bounded drain/exit verified; group timeout noted, no experiment process affected |
| Code rollback | Stop staging units, switch to retained reviewed release/unit set, verify/restart in dependency order | No schema/data/key/anchor rollback; contract compatibility and baseline continuity verified before reopen |

Re-run protected baseline comparison after each action. Any AppArmor hash/
loaded-profile or experiment unit/state change means immediate NO-GO; do not
reload policies or regenerate baseline. Resource/experiment regression also
aborts even if staging's own checks pass.

## Restore and abort conditions

Close staging ingress first. Stop only explicitly approved new staging units/
cluster as needed. Preserve charged/ambiguous request records and privately
retain evidence. Restore only the staged configuration/code changes listed in
the pre-change manifest, preserving metadata; remove only individually named
new paths/accounts when safe and approved.

Do not perform broad cleanup, global daemon restarts, firewall flush, AppArmor
reload, host reboot, stale database restore, authority-head rewrites or STOP
changes. If a change unexpectedly affected experiment policy/service state,
do not blindly restore/reload it: keep staging closed and let the experiment/
STOP owner direct recovery. No automatic reopening.

## Final founder evidence and minimum next authorization

Deliver pass/fail matrix A-G, independently retained before/after policy and
unit fingerprints, exact installed manifest/release, test-only role custody,
listener/firewall review, active sandbox/marker results, real PostgreSQL/mTLS
results, canary-redaction evidence, accounting reconciliation and rollback
outcome. Do not include secrets, DSNs, raw logs or sensitive infrastructure data.

Minimum next action is **approval 1: read-only discovery only** on the named
host in an agreed idle experiment window. Then founder reviews the baseline
and blockers before separately authorizing the manifest in approval 2.
No production readiness, customer activation, public exposure or commercial
launch is authorized at either gate.

## Offline verification evidence

- Focused preflight/ingress/private-staging tests: **72 passed, 4 skipped**.
- Full offline suite: **760 passed, 362 subtests passed, 69 skipped**.
  Skips are 47 opt-in PostgreSQL, four host-Nginx and 18 opt-in Docker cases;
  no real service or host tests were run during this readiness-preparation task.
- Script tests cover unavailable observations, wrong host/OS/PID 1,
  missing/drifting baseline, internal versus external policy links, policy/unit
  byte drift, changed PID, public/occupied listeners, shared service identities,
  unsafe credential metadata, resource shortage and redacted failure output.
- Changed Python parses with Python 3.9 syntax; final newlines, new-file ASCII,
  permissions, whitespace and exact four-file scope are checked. These do not
  attest the target host's configuration or runtime security.
