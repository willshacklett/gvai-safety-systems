# Usage Metering and Quota Foundation V1

## Status and scope

Phase 6E is an offline, experimental, **nonproduction** accounting reference in
`gvai/commercial_usage.py`. Phase 6H.1 adds an explicitly initialized,
file-backed SQLite ledger for local testing; it is not activated by default and
is not approved for customer or production traffic. There is no HTTP server,
payments, subscription state, customer billing, or worker execution.
The $99/month starter subscription is a business target, not a quota policy or
an activated product. Founder approval is required before integration or launch.

Never let the thing behind the switch own the switch.

## Trusted policy and tenant boundary

Trusted server code constructs `InMemoryUsageStore(allowances, clock=...)` and
`CommercialUsage(authorizer, store)`. Allowances are explicit per-tenant integers
from zero through `MAX_EVALUATION_UNITS` (signed 64-bit maximum). There is no
default allowance, price-to-quota mapping, subscription flag, or implicit trial.
Missing policy denies; zero allows no reservations. The constructor copies
configuration. There is no policy update, customer reset, refund, or pruning API.
Changes to commercial allowance policy require a separately reviewed design;
replacing a store is not a safe production policy update because it loses usage.

Every reservation, completion, retry, and summary re-enters the existing
`CommercialAuthorizer`. It alone resolves credentials, current grants, canonical
resource ownership, resource kind, tenant equality, and expiry. Successful
decisions now carry the resolved `tenant_id` for immediate server-side binding;
denied decisions carry `None`. The field is omitted from repr, not a public
response field or a reusable authorization token. Existing decision reasons and
Boolean behavior are unchanged. Never construct a decision from customer fields.

Reservations/completions require `EVALUATE` on an existing evaluation resource.
Summaries require `READ_USAGE` on a separately provisioned usage resource and
contain totals for that resource's verified tenant, not a caller-selected tenant.
The facade accepts credential, resource selector, and request identifier only;
there are no request arguments for tenant, allowance, billing status, or period.
Neither identity objects nor claim mappings are credential evidence. Dependencies,
policy construction, and completion calls are trusted server-only operations.

## Accounting semantics

Periods are calendar months in UTC, labeled `YYYY-MM`, with half-open intervals
`[first day 00:00:00 UTC, next first day 00:00:00 UTC)`. They are not rolling
30-day windows. Store time is read inside the accounting lock, so the reservation
transaction's clock sample decides the month, not arrival time or client time.
Supported timestamps are finite nonnegative Unix seconds before year 9999.

Calendar selection floors the validated timestamp to an exact integer Unix
second before UTC conversion. UTC month boundaries are whole seconds, so this
cannot round an instant before a boundary into the next month. This corrects
the independently reproduced early-rollover defect caused by datetime's
microsecond rounding. The clock input contract is unchanged: integer and float
seconds remain accepted, and the original timestamp, not its floored value,
is retained for full-precision rollback checks.

1. `reserve(credential, evaluation_resource_id, request_id)` atomically checks
   tenant policy, lifetime idempotency, and remaining monthly allowance. A new
   reservation consumes **one** evaluation unit immediately and becomes
   `RESERVED`. Only `result.may_evaluate is True` permits a future trusted caller
   to invoke the advisory evaluator once. This library never invokes it.
2. `complete(..., succeeded=True)` marks an existing reservation `COMPLETED`;
   `succeeded=False` marks it `FAILED`. These are trusted server observations,
   not proof supplied by customers. Completion does not change consumed units.
   Advisory ALLOW, QUALIFY, or BLOCK results are all successful evaluations;
   evaluator errors should be recorded as failed attempts.
3. Failure, cancellation, timeout, lost response, abandoned reservation, or crash
   **does not refund** the unit. This conservative attempt-accounting policy
   avoids free retries, refund races, and negative balances. It is not a claim
   about billable successful results and needs founder approval.
4. Repeating a reservation returns `REPLAY` and its current state, even after
   completion, failure, quota exhaustion, or month rollover. It never grants
   another evaluation or consumes another unit. Same-state completion is also
   `REPLAY`; conflicting terminal completion is denied. An unknown completion
   is denied without creating a reservation.
5. A new request ID is a new attempt and must fit the current month's quota.
   Malformed, unauthorized, missing-policy, and exhausted new attempts consume
   nothing and create no idempotency entry. They may be retried after correction
   or rollover. Retrying a failed **reserved** attempt requires a new ID and unit.

Idempotency is keyed by verified tenant plus a SHA-256 digest of the bounded
ASCII request ID, across all evaluation resources and all retained periods.
Reusing a key for another evaluation resource in the same tenant is a conflict;
the same key in another tenant is independent. A second principal/key belonging
to the same tenant shares the ledger and retry scope. Replays always reauthorize.
Resource identity is also stored as a digest. There is no telemetry input,
payload hash, raw credential, API-key verifier, prompt, or response cache in
accounting records. Request IDs must be opaque, nonsecret identifiers; hashes
are metadata minimization, not protection for low-entropy secrets.

The store does not compare request bodies. A replay, even with a changed body,
never authorizes evaluation. A future adapter must reject it or retrieve a
previous result through a separately designed tenant-bound response cache; it
must never run evaluation again merely because no cached result exists.

`UsageResult.reason` gives a typed diagnostic and `outcome` is `success`,
`denied`, or `error`. `REPLAY`, `SUMMARY`, and completion outcomes are successful
accounting operations but **not** execution grants. Boolean conversion is true
only for a newly reserved unit. Use the explicit `may_evaluate` check instead.
All caught accounting exceptions return `ACCOUNTING_ERROR`, no reservation or
summary, and no permission. No exception text or logging is emitted.

## Atomicity, retries, and clocks

For `InMemoryUsageStore`, all callers must share one store object. Its
process-local lock covers time, policy/quota checks, duplicate detection, and
publication. Updates copy the tenant's counts and reservation map and publish
them together as one replacement ledger; a pre-publication exception leaves no
partial charge/key. Concurrent new attempts cannot exceed allowance; duplicate
attempts yield at most one new reservation grant. Terminal transitions are
monotonic and have no decrement.

If an error occurs before commit, retry can reserve normally. If commit succeeds
but acknowledgement is lost, the operation returns an error and retry returns
`REPLAY`, never another execution grant. A unit may be consumed without work;
this intentionally favors quota integrity over availability. There is no
exactly-once execution, resumable lease, refund reconciliation, or distributed
transaction with the evaluator.

Each tenant ledger retains the highest observed successful transaction time,
including summaries, replays, and quota denials. Earlier samples deny with
`CLOCK_ROLLBACK` until time catches up; even a same-month rollback is rejected.
An invalid/unrepresentable clock yields `ACCOUNTING_ERROR`. On rollover, a new
monthly counter starts lazily at zero; previous counters, reservation states,
and idempotency entries remain. Completion after rollover updates the original
reservation, never the new month's usage. A forward jump can open a later
month, so the clock remains independently trusted, not customer controlled.

## Experimental SQLite usage ledger

`SQLiteUsageStore` uses only Python's standard `sqlite3` module and is an
explicit local opt-in. The existing `InMemoryUsageStore` remains the default
and no service or HTTP configuration selects SQLite automatically. Create a
new file exactly once with `SQLiteUsageStore.initialize(path, allowances)`;
that operation refuses an existing file and creates schema version 1 plus the
trusted allowance rows. Open an existing database with
`SQLiteUsageStore(path, allowances)`. Normal construction refuses a missing,
unversioned, unsupported, or policy-mismatched database; it never creates a
replacement ledger. There is no customer-facing activation or production
migration path.

Every operation uses an explicit `BEGIN IMMEDIATE` write transaction and
commits the reservation/terminal-state change and tenant clock watermark
together. The schema stores server-provided tenant allowance policy, per-tenant
clock watermarks, and reservation rows. A primary key on
`(tenant_id, request_digest)` gives lifetime idempotency; request and resource
IDs are stored only as the existing SHA-256 digests. Counts are derived from
reservation rows, so charging and recording a new reservation are one insert.
The internal ledger primitive requires a new reservation insert to affect
exactly one row and a readback inside the transaction to match tenant, request
digest, resource digest, period, and state. Completion and clock-watermark writes
also require exact affected-row counts and readback. This is storage integrity,
not an evaluation grant: the supported `CommercialUsage` facade denies all
SQLite-backed operations until an independent atomic reservation authority is
reviewed. The exact expected schema, including the absence of extra
triggers/indexes, and trusted policy map are checked at startup; schema and
policy are rechecked inside each transaction.
The SQLite database contains no raw API credential, credential verifier,
telemetry, evaluation payload, or evaluation result. Each writer connection
uses SQLite's full synchronous setting and a bounded busy timeout; SQLite
serializes writers across separate store instances.

The `allowances` mapping is trusted server configuration, validated and copied
at initialization, and stored durably. Reopening requires an exact match; a
policy change fails closed. No API for policy updates, refunds, deletion, or
pruning is provided. Schema versions other than 1 are rejected; there is no
migration runner yet. Use a local file on a local filesystem, not a shared
network filesystem. Backups and restore procedures are not implemented or
validated here. Creation/opening requires a POSIX-owned private parent
directory, rejects symlink path components and changed file identity, and
requires a singly linked regular database file with mode `0600`. Unsupported
platforms and unsafe permissions fail closed; this is not a substitute for
protecting the host or parent directory from its trusted owner.

Startup runs `PRAGMA integrity_check` and `foreign_key_check`, and every
transaction checks the exact application schema. These detect structural
corruption and unexpected schema objects, not freshness or every malicious
data rewrite. There is **no independent anti-rollback checkpoint**. **HIGH
severity:** restoring a valid pre-reservation database snapshot remains
**UNSAFE** and can grant the same request a second evaluation. A party able to
write the database can alter usage rows while preserving valid schema and
integrity. Do not serve from a
restored, replaced, or otherwise unverified database; this implementation has
no trusted reconciliation or recovery protocol.

## Phase 6H.2 Recovery Gate

`SQLiteRecoveryGate` has `UNVERIFIED`, `READY`, `REBUILD_REQUIRED`,
`QUARANTINED`, and `DENIED` states and starts `UNVERIFIED`. It checks local
schema, integrity, and policy, then requires an independently authenticated
trusted-head provider and a projection sequence/hash reader with the expected
authority identity. Missing authority denies; unavailable evidence denies;
invalid or conflicting evidence quarantines; an older projection requires
rebuild; a projection ahead of authority quarantines.

The current SQLite schema contains no projection sequence/hash or authoritative
reservation history. No reader or trusted authority implementation is supplied,
and the gate does not infer a head from current reservation rows. Therefore an
existing database without separately replayed projection evidence remains
`REBUILD_REQUIRED`; schema validity alone can never produce `READY`. Test-only
providers can exercise matching-head state transitions but are not independent
authorities. Even diagnostic `READY` never enables a grant:
`may_authorize_fresh_grant` is always false, and `CommercialUsage` returns
`ACCOUNTING_ERROR` for operations backed by `SQLiteUsageStore`. The SQLite
adapter remains non-customer-usable until a separately reviewed, independently
controlled atomic reservation authority exists.

**MEDIUM — Trusted-head authentication is only an unimplemented provider
contract.** The `authenticated` field is an adapter assertion, not cryptographic
proof; no production provider exists, and test providers are not trusted evidence.

This state machine is not anti-rollback protection. Stale restoration remains
**HIGH severity and unsafe**; it requires independent reconciliation. No journal,
checkpoint, remote service, schema migration, or production provider is added.

At the internal storage primitive, a process crash after commit leaves a durable
reservation and retries observe replay. This persistence behavior is tested as
ledger mechanics only. The supported `CommercialUsage` facade denies all
SQLite-backed operations, so no SQLite `RESERVED` result can reach the
evaluation service. Storage errors, incomplete recovery, and closed stores do
not fall back to in-memory accounting.

Durable usage alone does **not** make API-key verification/revocation, customer
membership, resource ownership, or their authorization decision durable or
transactional with reservation. `CommercialUsage` continues to derive tenant
only from a fresh `CommercialAuthorizer` decision, but authorization happens
before the SQLite transaction. Revocation or ownership changes can race the
reservation/completion boundary until a separately reviewed shared durable
identity/ownership transaction is designed. The local adapter is not a
production authentication or authorization backend, has no durable
transactional revocation, and is **not approved for customer traffic**. SQLite
remains opt-in and experimental. It has no worker or supervisor STOP dependency;
STOP authority and storage remain independent.

## Security findings and limitations

- No tenant/quota claim, payment flag, STOP envelope, or internal identity grants
  usage access. Unauthorised operations never reach accounting storage. Store
  errors never fall back to an unmetered evaluation path.
- Usage imports no evaluator, supervisor, external-control, executor, or worker
  module. Quota exhaustion and accounting outage cannot authorize or block the
  trusted-parent emergency STOP. Customer and supervisor authority stay separate.
- Authorization/ownership and accounting are point-in-time operations, not one
  transaction. Revocation or reassignment after authorization does not undo a
  reservation. Production integration must resolve these races explicitly.
- Process-local locks and Python objects do not protect against hostile code
  running in the trusted process. Dependencies, clock, and configuration must
  remain outside customer/agent control. Direct use of the existing evaluator
  remains unmetered until a separately reviewed integration is built.
- The in-memory reference loses accounting and its clock watermark on restart
  or when callers use another store. The local SQLite option preserves them
  across restarts and serializes local writers, but stale restoration, database
  replacement, shared/network filesystems, and hosted multi-replica operation
  are not protected or validated. Neither option provides a production quota
  guarantee. Lifetime idempotency records are unbounded; this is not an abuse-
  rate limiter or a hosted-scale backend.
- Records contain only tenant accounting metadata, counts, period labels,
  request/resource digests, state, and clock watermark. Metadata still requires
  access control. Future logs, tracing, result caches, and HTTP errors need
  explicit redaction and uniform unauthorized/not-found responses.

## Durable accounting and billing prerequisites

Before production, extend/review beyond this experimental local SQLite adapter:
provide hosted multi-replica consistency, safe backup and restore, operational
reconciliation of uncertain writes, tenant provisioning/deletion, auditable
trusted policy changes, retention, capacity controls, and an abuse-rate limiter.
Define request/result binding and authorization-to-accounting race semantics.
Evaluate database failure and distributed concurrency independently; this
phase supplies no production backend, migration runner, or generalized
multi-backend storage contract.

Founder approval is needed for allowance, attempt-vs-success policy, abandoned
attempt treatment, period rules, overage/denial behavior, and retention. Billing
requires a separate authoritative subscription model, verified payment events,
deduplication/reconciliation, entitlement transitions, invoice semantics, and
secret custody. Never infer payment or entitlement from request fields or this
in-memory usage state. No payment-provider configuration is included.

The offline Phase 6F [commercial evaluation service](commercial_service_v1.md)
now composes this usage facade with strict prevalidation, the existing
authorizer, and the pure evaluator. It reserves once, evaluates only on a fresh
grant, records completion, and denies accounting errors and replays. The service
does not expose completion, store management, STOP, policy mutation, or worker
controls as customer operations. Authenticated routes and billing need separate
approval.

## Offline validation and exclusions

Baseline: clean local `main` and cached `origin/main` at `dca19ac`, the PR #23
merge. Work is on `feature/commercial-usage-v1`. No network fetch was performed;
whether the remote advanced beyond the cached merge is unverified.

```bash
python -m unittest discover -s tests -p test_commercial_usage.py -v
```

Result: **35 tests passed**. The focused pytest run also passed **47 subtests**.
Coverage includes exact/exhausted/zero/missing
allowances; signed-64-bit bounds; malformed policy, identifiers, and clocks;
concurrent distinct/duplicate requests, shared facades, and terminal races;
tenant isolation; forged claims; unauthorized summaries; reauthorization;
real API-key verification/revocation; precommit and uncertain-write failures;
completion retries; month/year/leap-day boundaries and their nearest
representable floats; exhausted quota immediately before rollover; fresh quota
at the exact boundary; cross-month replay and subsecond rollback; metadata
minimization; and STOP independence, including during accounting outage.
Threads exercise the store lock only; no AI actions or worker processes run.

The default Python environment lacks pytest, but the installed pytest virtual
environment at `/usr/local/py-utils/venvs/pytest` supplies pytest 9.1.1 on Python
3.14.2. No dependencies were downloaded or installed. The full permitted offline
gate includes existing commercial identity, API-key, evaluation, identity,
external-command, STOP/control, core, guard, policy, pure-decision experiment,
and read-only public-site regressions, not only the new usage tests:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  /usr/local/py-utils/venvs/pytest/bin/python -B -m pytest -q \
  -p no:cacheprovider tests \
  --ignore=tests/test_agent_safety_v2_acceptance.py \
  --ignore=tests/test_audit.py \
  --ignore=tests/test_capability_executor.py \
  --ignore=tests/test_os_sandbox.py \
  --ignore=tests/test_subprocess_executor.py \
  --ignore=tests/test_transactional_executor.py \
  -k 'not test_builder_publishes_only_the_explicit_allowlist and not test_builder_refuses_a_nonempty_output_directory and not test_demo_assets_are_explicitly_allowlisted_but_private_dashboard_is_not'
```

Result after correction: **384 passed, 127 subtests passed, 3 deselected**.
The same gate before correction passed 381 tests and 112 subtests; the added
boundary tests distinguish the defect that the earlier suite missed. The three
deselected tests write temporary website build output. The six ignored suites
execute workers/executors or write audit output. Pytest caching, bytecode, and
external plugin autoload are disabled.

The full suite is excluded because it includes worker execution. In particular,
do not run OS sandbox, subprocess/capability/transactional executor, acceptance,
or other worker-executing tests under this phase's authorization. Network tests,
package installation, HTTP integration, load/distributed/durable-accounting
tests, billing, payments, host changes, and deployments are excluded. A durable
backend, independently trusted time, production identity/ownership, founder
policy decisions, and production security review remain launch blockers.
Wheel/install builds and actual Python 3.9 runtime compatibility are unverified.
Ready for **founder review of an experimental commit**, not launch approval.

The public website/GitHub Pages, https://gvaisafety.com,
contact@gvaisafety.com, and GvAI.io are unchanged. No commits, pushes, PRs,
merges, deployments, DNS changes, live routes, or customer billing are included.
