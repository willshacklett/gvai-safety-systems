# Usage Metering and Quota Foundation V1

## Status and scope

Phase 6E is an offline, experimental, **nonproduction** accounting reference in
`gvai/commercial_usage.py`. It provides no HTTP server, database, payments,
subscription state, customer billing, evaluator invocation, or worker execution.
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

All callers must share one store object. A process-local lock covers time,
policy/quota checks, duplicate detection, and publication. Updates copy the
tenant's counts and reservation map and publish them together as one replacement
ledger; a pre-publication exception leaves no partial charge/key. Concurrent
new attempts cannot exceed allowance; duplicate attempts yield at most one new
reservation grant. Terminal transitions are monotonic and have no decrement.

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
- Restarts, a second store, stale restoration, or another process lose/bypass
  this reference's accounting and clock watermark. No production quota guarantee
  is claimed. Retaining lifetime keys prevents rollover replay but causes
  unbounded memory growth; copy-on-write updates and summary scans are linear
  in tenant history. This is not a scalable backend or abuse-rate limiter.
- Records contain only tenant accounting metadata, counts, period labels,
  request/resource digests, state, and clock watermark. Metadata still requires
  access control. Future logs, tracing, result caches, and HTTP errors need
  explicit redaction and uniform unauthorized/not-found responses.

## Durable accounting and billing prerequisites

Before production, design a durable ledger with unique tenant/idempotency
constraints, transactional quota checks/increments and terminal transitions,
bounded counters, current reads, rollback-resistant time, durable replay
retention, restart/replica consistency, safe backups, reconciliation of uncertain
writes, tenant provisioning/deletion, and auditable trusted policy changes.
Define request/result binding, retry retention, crash recovery, rate limits,
capacity controls, and authorization-to-accounting race semantics. Evaluate
database failure and distributed concurrency independently; this phase supplies
no database adapter or generalized production storage protocol.

Founder approval is needed for allowance, attempt-vs-success policy, abandoned
attempt treatment, period rules, overage/denial behavior, and retention. Billing
requires a separate authoritative subscription model, verified payment events,
deduplication/reconciliation, entitlement transitions, invoice semantics, and
secret custody. Never infer payment or entitlement from request fields or this
in-memory usage state. No payment-provider configuration is included.

Next integration: validate the strict evaluation schema before reserving; use
server-selected resources/capabilities and authenticated identity; reserve once;
evaluate only on a fresh grant; record completion with trusted result status;
deny every accounting error and every replay from starting new work. Do not
expose completion, store management, STOP, policy mutation, or worker controls
as customer operations. Authenticated routes and billing need separate approval.

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
