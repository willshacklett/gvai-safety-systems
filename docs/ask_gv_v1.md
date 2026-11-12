# Ask GV V1 and launch hardening

This work is uncommitted local development on `feature/ask-gv-launch-hardening-v1`,
from preserved checkpoint `80041e9e09a33da445eebeafc3237fefb559997f`. It does not
approve a launch, host, model, corpus update, budget increase, API key or deployment.
The public endpoint remains empty in `ask-gv-config.js`; the UI stays disabled.
No real OpenAI calls are used in tests. No protected service is imported or called.

## Boundary and approved facts

GitHub Pages serves only `scripts/prepare_public_site.py`'s explicit static files.
The Node backend and state are never in that artifact. A separate isolated backend
accepts bounded questions, asks OpenAI to select up to three approved fact IDs and
renders only maintained text/status/source links. Model text never becomes a public
claim. Unknown IDs, tools, unexpected output items, refusals and malformed envelopes
fail unavailable. The deployment must select a specific model ID whose response
model matches the configured ID and whose completed output is a single assistant
message with one text item. Reasoning/tool-output envelopes are deliberately not
supported. Real account/model compatibility remains a later approved verification.

`ask-gv/facts.json` is unchanged: seven topics, version `2026-11-12.v1`, verified
site baseline `23299020ea200e268a1d91aa591c49b8a6557ecb`, review deadline
`2027-02-10`. Research, prototypes, plans, inquiry-only pilot, unverified pricing and
offline evidence remain distinguished. Valid ISO calendar dates and at most a
90-day review interval are enforced. Before the as-of date or after the deadline,
readiness fails and no provider call starts. Clock health, current sources, content
approval and a maintenance/expiry owner still need owner review. A checkpoint does
not establish current availability, certifications, pricing or safety guarantees.

There are no model tools, arbitrary retrieval, worker execution, STOP permissions,
billing actions or tenant access. History is bounded untrusted JSON in a user
message, never a privileged role. Injection can affect relevance among approved
facts; it cannot create new rendered claims. A real model's selection quality is
not proved by mocks. Preserve this boundary in future changes.

Reviewed reuse remains the MIT fetch helper from `willshacklett/GvAI` at
`9646e9a867c7cc94b1386277c9c0d592a427fcdf`, now locally hardened for bounded
UTF-8/JSON reading and cancellation. Attribution remains in the static artifact.
No companion/runtime/workforce gateway code is imported wholesale.

## Admission and exact ingress trust

The production CLI binds only `127.0.0.1`, defaults to port 8787, and enabled startup
refuses root. Configure `ASK_GV_TRUSTED_INGRESS=loopback-token-v1` explicitly.
POST admission requires an exact permitted socket peer (`127.0.0.1`, `::1`, or
IPv4-mapped 127.0.0.1), a constant-time matching private `X-Ask-GV-Ingress` token,
and one valid `X-Ask-GV-Client-IP`. Equivalent IPv6/IPv4-mapped addresses normalize
before hashing. Forwarded, X-Forwarded-* and X-Real-IP headers are rejected by the
backend. They are never used as identity. CORS allows only the exact apex/www HTTPS
origins; it is not proof that a caller is human or visiting the website.

The proposed ingress discards client headers, supplies the ORIGINAL Origin and
Content-Type, replaces the visitor address with its observed peer and injects its
private ingress token. It never sends browser cookies or Authorization downstream.
The token does not go in the frontend and is separate from the OpenAI key/salt.
A new CDN/proxy hop needs a new trust review. Unique accounts, private credential
custody and loopback/firewall isolation are part of this trust model; loopback by
itself is not local-process authentication. A compromised ingress can forge visitor
addresses and exhaust allowance; it cannot exceed the final global/budget controls.

Backend limits: two active operations; 32 connections; six admitted requests per
normalized visitor per minute; 30 global admissions per minute; 1,000 hashed visitor
buckets. Busy rejections do not debit visitor/global quotas. Invalid admitted JSON
can debit admission quota but never reserves a provider attempt. IP/salt values are
not logged. Header bytes: 8 KiB; request body: 12,000 bytes; question/item: 1,600 UTF-16
units; up to six history items and 6,400 units combined. The UI sends four recent
items truncated to 800 units. No browser credential is an abuse-control mechanism.
A bot can deliberately consume a public finite allowance; sustained availability
needs an owner-approved abuse strategy, not a larger automatic budget.

## Strict budget custody: fail closed instead of unattended recovery

The old `{reserved:N}` ledger must NOT be silently migrated/reset. Enabled startup
requires an owner-reviewed version-1 ledger and an independently issued one-use
startup permit. There is no initializer, permit issuer, automatic lock removal,
replenishment, refund or retry command in this repository.

Three independent custody inputs must be reviewed by the operator before each
start, including a clean restart:

1. Private durable state directory, e.g. `/var/lib/gvai-ask-gv`, mode 0700 owned by
   the unique service UID, containing regular mode-0600 `reservations.json`:
   `{"version":1,"ledger_id":"<32 lowercase hex>","reserved":N}`.
   N is an integer 0..100 established from the greatest independently verified
   count, not a guessed default. Never reduce it after failed/uncertain attempts.
2. Separate private durable guard directory, e.g. `/var/lib/gvai-ask-gv-custody`,
   with the same restrictive ownership/mode, outside/independent of the ledger
   directory. It contains a regular mode-0600 `high-water.json` with the same version/ledger_id/
   reserved schema and retains `<permit_id>.used` markers permanently. Both count
   files must agree with the independently reconciled permit at startup. No automatic
   pruning or restoration of an older guard snapshot is permitted.
3. Systemd credential `budget_permit`, issued privately by the owner after custody
   reconciliation, with EXACT keys:

   ```json
   {"version":1,"ledger_id":"<same 32 hex>","reserved":0,"state_dev":0,"state_ino":0,"permit_id":"<fresh 32 hex>","boot_id":"<current Linux boot UUID>"}
   ```

   Zeros above illustrate types, NOT deployment values or authorization to reset.
   `reserved` must match the greatest reconciled count. Device/inode bind the state
   directory; boot UUID binds the current boot; permit_id must never be reused.
   Real values are not generated here. Record the authorization/high-water outside
   the VM backup domain. The permit grants one process start, not another 100 units.

Every ancestor must be a regular directory owned by root/service UID with no
writable group/other permission; symlinks are rejected. Final state/guard directories
must be exactly 0700, no special permission bits. State/lock files are regular,
single-link, exact 0600, bounded in size and opened with O_NOFOLLOW; FIFO/device/
hardlink/oversize/mode/owner mistakes fail closed. The startup state must exactly
match the permit. Each reserve/peek rechecks directory identity, state count and
lock custody. External count changes or rollback poison the process permanently.
Reservations use exclusive temporary-file creation, write/fsync/rename/directory
fsync in the separate guard directory FIRST, then the main ledger, before a provider
call. Any mismatched pair or leftover temporary file refuses startup/readiness;
owner reconciliation must preserve the greatest count, never overwrite it downward. Any storage uncertainty poisons custody and leaves
the lock for owner review. Final authorized attempt 100 can still return its answer;
new attempts and readiness are then unavailable.

Exclusive `process.lock` and a durable consumed permit marker prevent duplicate
writers/replay. A clean close may remove only its validated own lock; it does not
remove the consumed permit. A crash leaves the lock. No automatic restart is
proposed. Owner must prove the old process is gone, reconcile any partial temporary
file/reservation conservatively, issue a fresh permit with the SAME greatest count,
and review stale lock removal privately before a later start.

This catches runtime count rollback, a lower restored ledger versus its independent
guard high-water (even with a fresh lower permit), stale/wrong count/inode/boot permits, reused
permits, duplicate processes, crashes and partial file operations under the stated
single-host custody. It cannot cryptographically detect a coordinated restore of
ALL local state/credentials/guard memory to an earlier live VM snapshot. No local
filesystem algorithm can establish an external high-water after that event. Keep
ingress closed after restore/uncertain custody until an independent owner record
is reconciled upward and a new boot-bound permit issued. A hostile root/service
process or a false owner attestation is outside this filesystem trust boundary.
If an off-host monotonic spend authority is required, that is a separate design;
do not borrow M2, STOP or Lab-01 storage. Multiple instances/hosts/auto-scaling and
separate ledgers are unsupported and multiply spend if misconfigured.

## Credentials and control configuration

Enabled production startup reads `CREDENTIALS_DIRECTORY` directly; it does not set
secrets in process.env or argv. Legacy OPENAI_API_KEY, ASK_GV_IP_SALT or ingress-token
environment values cause enabled startup to refuse. Only fake values appear in tests.
Systemd loads four private files into its per-service credential directory:

| Credential | Required content |
| --- | --- |
| `openai_key` | Dedicated project workload key; printable ASCII, 16..256 bytes |
| `ip_salt` | Independent 64 lowercase hex characters |
| `ingress_token` | Independent 64 lowercase hex characters, shared only with ingress |
| `budget_permit` | Exact owner-issued JSON described above |

All are regular single-link mode-0400 files owned by the service UID in a private
mode-0500/0700 credential directory. Ancestor custody is validated. Root owns the
persistent credential sources, mode 0400, under a root-only 0700 source directory.
LoadCredential supplies read-only process-owned copies; the app does not read the
root source. No shell expansion, Environment= secret, EnvironmentFile fallback,
secret-bearing command argument or diagnostic value is used. Root/same-UID memory
inspection is not defeated by credential loading: unique UID, proc/core isolation
and host custody are still required. Ingress receives only a separate private
credential config containing `proxy_set_header X-Ask-GV-Ingress "<same token>";`,
not the OpenAI key or budget permit. These real files are never generated in tests
or committed; synthetic copies are disposable fixtures only.

Non-secret settings: `ASK_GV_ENABLED=1` only after approval, explicit trusted-ingress
mode, `OPENAI_MODEL` exact model/snapshot ID, absolute `ASK_GV_STATE_DIR`, absolute
`ASK_GV_GUARD_DIR`, and absolute `ASK_GV_DISABLE_FILE`. PORT defaults to 8787.
The disabled CLI needs no secrets/state and never calls OpenAI.

Use a SEPARATE root-owned public-control directory (e.g.
`/etc/gvai-ask-gv-control`, 0755) for `disabled` and `OWNER_APPROVED`, not the 0700
secret-source directory. The service must be able to lstat the control path but
cannot write it. Presence of disabled (any type), inaccessible control path, missing
configuration, invalid custody or an expired corpus denies provider calls. It is
rechecked before reservation and after provider completion. Source templates set
ASK_GV_ENABLED=0 and ingress admission 0; no approval markers are created here.

## Health, counters, deadlines and drain

Loopback GET /healthz returns only `{"status":"alive"}`. GET /readyz additionally
requires the private ingress token and returns fixed flags, remaining allowance,
active count and known numeric counters; the public ingress does not route either.
Readiness does not reserve, call OpenAI or debit visitor/global admission. It checks
configured/enabled, operator disable, corpus date, usable custody and circuit/drain
state. It cannot verify a provider account without an explicitly approved paid
request. OPTIONS is CORS negotiation only and must never be used as readiness.

Counters are saturated numbers for success/origin/identity/input/busy/rate/global/
budget/provider/timeout/disabled. No raw prompts, identifiers, IPs, headers, provider
bodies, exceptions or credentials are emitted. Three consecutive provider failures
latch a circuit requiring operator review/restart (and a fresh custody permit).
There are no automatic retries. Provider header and response-body processing share
an eight-second abort deadline; provider bytes max 32 KiB and output max 256 tokens.
Body upload has an absolute five-second timer; header checking interval is one
second with a five-second configured header timeout. Frontend timeout is 20 seconds.
The frontend reads at most 16 KiB before parsing JSON and validates answer/version,
source count/ID/title/URL types and lengths, safe HTTPS links and precise repo prefix.
No arbitrary response HTML is inserted. Deadlines still need real deployment load
validation; synchronous filesystem stalls can delay the Node event loop.

`beginDrain()` irrevocably closes admission, aborts active providers and incomplete
uploads, and closes idle sockets. SIGTERM/SIGINT invoke it; the CLI closes remaining
connections after one second, then closes validated state custody without deleting
permits. Failed/aborted reservations stay consumed. The process does not grant the
browser reset authority over the budget. Listener/configuration failure emits only
a fixed error and refuses startup; no automatic restart/cleanup is attempted.

Disable procedure: close the DEDICATED ingress first with JSON 503/CORS/no-store,
then create the root-owned control disable marker and stop ONLY Ask GV. Cached
frontend configuration cannot bypass backend admission. Preserve ledger, guard,
partial state and consumed permits. Do not restore older budget data. Validate
compatible code rollback and reconcile custody before issuing a fresh permit and
explicitly authorizing a later start. No STOP/billing/tenant action is involved.

## Inert deployment proposals and remaining owner gates

`deploy/ask-gv/*.template` are proposals only: no installation, enablement, DNS,
certificates, firewall edits or host selection occurred. There is no [Install]
section, restart is off, approval marker is absent, backend enablement is 0,
ingress admission is 0 and the listener/address remain placeholders. Do not copy
these files into an existing service config or use a protected account/port.

Review a dedicated host boundary first. Local documentation about Lab-01's private
8443/8080/5432 services is not evidence it is suitable for public traffic. No
unconditional no-interference guarantee exists on a shared host. Owner must verify
host inventory/capacity, UID separation, protected policies/paths, IPv4/IPv6 firewall
attachment, recovery access, private persistent custody and TLS/renewal. Apex/www
Pages hosting stays unchanged; ask.gvaisafety.com is only a proposed unverified
subdomain. No database/cloud-management/STOP credential belongs in the backend.

Ingress proposals preserve Origin, overwrite private identity metadata, enforce
exact path/method/origin, bound body/header/connections and per-IP/global rates,
stream uploads (no proxy body-buffer deadline escape), suppress logs/cache/retries,
and return safe CORS errors. All proxy scratch paths are private runtime paths.
Nginx TLS tests use a downloaded/extracted package in /tmp and synthetic certificates;
they do not install a distro service. Per-service egress/firewall and actual systemd
credential mount/sandbox/resource limits still require host-specific validation.
Do not claim TCP 443 to anywhere is FQDN-restricted OpenAI-only egress.

The owner must separately approve current facts/privacy, a dedicated OpenAI project,
workload permissions, exact compatible model/prices, model/request/token rate limits,
initial finite attempt allowance and enforced project spend limit plus alerts.
Provider enforcement may lag; an alert alone is not a cap. App's 100 lifetime
attempts and bounded tokens limit exposure, not a verified exact dollar ceiling.
Never auto-refill/reset the ledger after a monthly provider-budget reset. A tiny
real-provider smoke test, DNS/TLS/installation/public activation, merge and release
all require later explicit authorization; none is part of this task.

## Reproducible local and release checks

Node 24.22.2; dev-only Playwright 1.65.0 and @axe-core/playwright 4.14.0 locked with
integrity hashes in package-lock.json. No runtime npm dependency was introduced.

```
npm ci --ignore-scripts --no-audit --no-fund
npm run test:ask-gv
python -m pytest -q
npx --no-install playwright install chromium
npm run test:browser
ASK_GV_NGINX=/path/to/extracted/nginx node tests/ask-gv/proxy-qa.mjs
```

The TLS proxy check extracts Ubuntu 24.04 Nginx 1.24.0-2ubuntu7.19, never installs or
enables it. Pin changes require review; if the archive package expires from mirrors,
CI fails closed until the pin/compatibility are reviewed. CI runs the locked Node,
backend/custody/startup, static-template, browser/axe and real disposable TLS proxy
checks in a reusable workflow. Existing Pages repository/main restrictions remain;
validate_build depends on those checks before publishing its allowlisted artifact.
No deployment is triggered from this feature branch or from workflow_call alone.
Branch protections/environment reviewer rules are account settings and remain
unverified/unmodified. Cloud/production and real-model performance remain untested.

Test seams allowing sticky /tmp custody exist only in explicit library test options;
the production CLI never enables them. Production refuses permissive ancestors such
as this workspace's /workspaces mount. Successful production-style startup tests
create private fake credential/state paths under a secure user-home ancestor and
preload a provider-network denial stub. All test state is disposable; no operator
keys or real external inference calls are involved. Ordinary tests never initialize
real state. No automated test grants an operational safety/certification guarantee.
