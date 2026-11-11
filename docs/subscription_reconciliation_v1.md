# Subscription reconciliation v1 (M2, Stripe TEST mode, advisory-only)

Closes the M2 gap: a continuously paid customer no longer loses evaluation access when the
60-second entitlement lease lapses, while cancelled, unpaid, disputed or expired customers
cannot retain access. Everything here is Stripe **test mode** only; evaluations stay
advisory-only. No live billing, no enforcement, no public service is added.

Status legend: **Implemented** (code exists) · **Tested** (and how) · **Unverified** (assumption
or not exercisable locally).

## Design

| Piece | Where |
|---|---|
| Audited SECURITY DEFINER functions, ticket/floor state, guards | `migrations/postgresql/009_subscription_reconciliation_v1.sql` + forward-only `010_subscription_denial_hold_v1.sql` + `011_legacy_billing_quarantine_v1.sql` |
| Python store (`claim -> Stripe read -> apply`, three short transactions) | `gvai/postgresql_billing.py` |
| Bounded reconciler loop, capacity arithmetic, schedule simulation | `gvai/billing_reconciler.py` |
| Operator CLI (`reconcile-serve`, `webhooks`, `status`, `resume`, `recover-denial`) | `gvai/billing_operator.py` |
| Tenant status response | `gvai/self_service.py` (`GET /v1/account`) |

### Lease and schedule

- `verified_until = max(old, ticket_started_at + 60s)`. The lease is anchored when the claim
  began, never when the apply ran, and it only moves forward on a verified **positive** snapshot.
- Each active tenant is claimed every 20s (+0-2s jitter). Transient failures back off 5, 10, 20,
  40, then 60s. Awaiting-checkout tenants poll at 60s; terminal (cancelled) tenants at 900s;
  dormant tenants never.
- Lease-chain rule: `interval + jitter + scheduling_lag + fetch_time < 60s`. About 38s remain for
  lag plus fetch time. `capacity_report()` computes it; `simulate_schedule()` shows overload.
- **No grace period.** A transient Stripe outage leaves the lease unchanged until it expires;
  nothing extends it. A definitive denial applies immediately.

### Ordering barrier (stale paid snapshots cannot restore cancelled access)

A local `snapshot_started_at` is not trusted. The barrier uses Stripe's own clock:

1. Every Stripe response's `Date` header is recorded; `observed_min`/`observed_max` span all calls
   of one logical fetch.
2. A webhook signal raises `stripe_floor = max(floor, event.created)` (event time is Stripe's,
   authenticated by the webhook signature). Applying a snapshot raises the floor to `observed_max`.
3. A **positive** snapshot is accepted only if `observed_min > stripe_floor`. Otherwise it is
   `stale_snapshot`, retried after ~2s (webhook path: up to 3 attempts, 1.1s apart).
4. A positive snapshot is also refused if it has no observation, if its observations fall outside
   +/-30s of database time, or if its ticket is older than 40s.
5. **Denials always apply.** An unseen verified denial event suspends immediately regardless of delivery age, except
   when covered by authenticated later payment recovery. This happens even before
   the confirming fetch; migration 010 records a durable denial hold that no poll or HTTP Date can clear.
6. Tickets are single-use, tenant-bound and expire; events are idempotent by id + payload hash;
   an event whose time is older than an already-applied snapshot is acknowledged as
   `covered_by_newer`.

### Ordering: what the `Date` header does and does not prove

Migration 010 closes the newer-Date restoration path. An unseen verified denial records immutable
`billing_denials` evidence and sets `billing_reconcile_state.denial_event` under the customer/state
locks, even if the customer is already ineligible. It clears eligibility, lease and access immediately.
Ordinary apply retains all 009 shape, identity, ordering and terminal checks, but cannot make a held
customer eligible. `paid_customer_v1` independently refuses held customers, so a mistaken positive
lease cannot consume paid quota. Denial snapshots and terminal cancellation still apply.

Denial event IDs and hashes are durable independently of fetch tickets. Duplicate delivery cannot
reinstate an already recovered hold; collisions are rejected. Holds survive `resume`, cancellation,
checkout generation changes and resubscription. A new subscription still needs explicit recovery
when the tenant has a hold, plus the existing owner-authorized resubscription transition.

### Operator recovery

Use only the TEST operator configuration and the owner-only `recover-denial` command:

```sh
python -m gvai.billing_operator --config /private/operator.json recover-denial \
  --tenant TENANT --denial evt_DENIAL --evidence /private/invoice-paid.json \
  --signature-file /private/stripe-signature.txt --reason 'Verified subsequent payment after investigation'
```

The evidence file is the exact raw signed webhook body; the signature file contains its Stripe-Signature
header. The owner-only recovery verifier accepts historical HMAC signatures while retaining
future-time, API-version, account and TEST-mode checks. Live ingress still enforces the 300-second
signature freshness limit. The event must
be `invoice.paid`, with a paid, non-out-of-band TEST invoice. Its integer `status_transitions.paid_at`
must follow every recorded denial for that tenant; event creation time alone is insufficient. The operator path refetches the
full subscription/invoice/payment-intent/charge chain and requires the evidence invoice, customer and
subscription to match that verified current paid state. Provider requests happen outside transactions.

`reconcile_recover_denial_v1` is an owner-only evidence-attestation boundary: **never grant it to the
reconciler, paid runtime or self-service role**. SQL cannot verify Stripe signatures; the trusted operator
Python path verifies them before attesting. Calling SQL directly requires the operator to perform the
same verification. This is the existing owner trust boundary, not protection against a malicious owner.
The reconciler retains five reconciliation function names plus the read-only `billing_upgrade_ready_v1`; `reconcile_signal_v1` also has a scoped overload.
Migration 010 copies existing signal EXECUTE grantees to that overload. New installations must grant
both signal signatures. Neither overload grants table access or owner recovery privileges.

Recovery locks customer then state, compares the expected denial, rejects revoked customers and
terminal reactivation, and runs the original apply checks with a valid single-use fetch ticket. Failure
rolls back the hold clear and all grants. Success inserts immutable audit evidence (session user, reason,
raw evidence SHA-256, payment event, payment time, subscription, invoice and denial), rejects evidence
reuse globally and invalidates outstanding fetch tickets. A concurrently delivered denial serializes on
the same locks and suspends access. Integrity incidents still require `resume` before recovery.
Rejected SQL recovery calls raise errors and roll back; retain operator/database access logs for rejected
attempt auditing. No raw webhook, signature, key or evidence body is stored in the audit table.

### Remaining limits

HTTP Date remains an ordering bound, not proof of cross-object consistency. Reads are not atomic;
missing/late denial delivery remains subject to lease and polling behavior. No production or real Stripe
consistency claim is established by synthetic tests. Delivery age alone never exempts an unseen verified denial. A strictly later authenticated
payment recovery for the same tenant covers older denial events; equal-time denials remain protective. Migration 011 does not reconstruct denial types
from 009's hash-only historical event records. It quarantines every customer present at its fenced
cutover, including apparently eligible customers: see [historical upgrade quarantine](#historical-upgrade-quarantine-migration-011). A customer
without a qualifying subsequent payment remains held; operator judgement alone and `resume` cannot
recover it through the supported command. A trusted schema owner can bypass database protections.

### Failure classes

| Class | Examples | Behaviour |
|---|---|---|
| Transient | non-200, timeout, 5xx, 429, 401/403, invalid JSON, DB busy | Lease **unchanged**; backoff; webhook not acknowledged so Stripe retries |
| Integrity | other 4xx, malformed or mismatching objects, subscription replacement, period overlap, unknown error | Suspend (`eligible=false`, lease cleared), phase `needs_operator`, never re-polled until the owner runs `resume` |

`resume` re-enables polling only; it never restores entitlement. 401/403 are transient on purpose so
a rotated Stripe key cannot mass-suspend tenants (leases lapse naturally instead).

### Resubscription

Stripe `canceled` and `incomplete_expired` are terminal. For a terminal customer only,
`reconcile_begin_resubscribe_v1` (owner role) bumps `checkout_generation`, allows one re-pin and
clears the old checkout; Checkout then runs with a generation-scoped idempotency key. Revoked
tenants are refused. A terminal subscription reported paid later does **not** reactivate without
this flow. Terminal tenants poll every 900s, not continuously.

### Privilege separation

| Role | Can do |
|---|---|
| `gvai_reconciler` | EXECUTE on exactly 5 functions: `claim_due`, `signal`, `apply`, `fail`, `status`. No table access, nothing granted to PUBLIC |
| owner (operator CLI) | `claim_one`, `resume`, `recover_denial`, `begin_resubscribe`, bind/checkout/portal/revoke |
| runtime | paid reserve/complete/usage only |

All functions are SECURITY DEFINER with a pinned `search_path`. The reconciler holds a
**restricted** Stripe key (`rk_test_`, read-only) and its client is GET-only with no idempotency
keys. `verify_database_role` rejects any extra EXECUTE grant at startup. Config files must be
private (0600). Logs carry fixed codes only; no keys, tokens, customer ids or payloads.

Behaviour change: `webhooks` now runs as the reconciler role (not the owner). It can signal and
apply but cannot bind, revoke, resume or start checkouts.

### Tenant-authenticated status

`GET /v1/account` returns `entitlement_state` in `active | verification_pending | payment_required |
suspended`, `entitled` (true only for `active`) and `access_until` (epoch seconds, only for
`active` or `verification_pending`). It carries no Stripe identifiers or internal reasons. Key
claim also requires a fresh lease.

## Capacity (important)

One fetch is ~6 Stripe calls (customer, subscription list, subscription, invoice, payment_intent,
charge). Sustainable active tenants at a 20s cadence = `rate * 20 / 6`:

| Stripe rate | Sustainable tenants | Notes |
|---|---|---|
| 10 rps (default) | 33 | |
| 25 rps (test-mode limit) | 83 | at ~100 tenants lag is ~4s+; at 200 it is critical |
| 100 rps (live limit, not used) | ~333 | |

Verified by running `capacity_report` and the real fetch (6 calls: customer, subscription list, subscription, invoice,
payment_intent, charge). The 83/33 figures are at **100% request utilization**, leaving no headroom for webhook-driven
fetches, stale retries, or additional reconciler/webhook processes. Each process owns its own token bucket, so
several processes can exceed Stripe's account-wide limit together. Plan on about 80% of the figures (66 at 25 rps).

**Smallest change to raise capacity:** use the expanded subscription read (mechanism 1 above) and drop the redundant
customer GET (the subscription list is filtered by customer and `sub.customer` is verified). That is 2 calls per fetch:
about 250 tenants at 25 rps and 100 at 10 rps, with no weakening of any check, and it also tightens ordering. Not yet
implemented or tested.

Beyond capacity the schedule degrades **uniformly** (oldest-due-first, no starvation), leases lapse and
tenants see `verification_pending` and are denied: fail closed, never extended. **This design
does not scale past ~80 tenants** without reducing calls per fetch (Stripe `expand`, skipping
redundant reads). `reconcile_status_v1` and `capacity_report` expose lag so operators can see it
before leases lapse.

## Evidence

| Claim | Status |
|---|---|
| 009 functions, role privileges, ticket single-use/tenant-bound/expiry, floor ordering, idempotency, transient vs integrity, revoked never reactivated, quota never reset, cross-tenant period/invoice isolation, terminal resubscribe, SKIP LOCKED disjoint claims, 200-tenant starvation | Implemented + **Tested** on disposable PostgreSQL 16 (`tests/test_reconciler_postgresql.py`; includes migration 010 denial-hold regressions) |
| Store/service logic (stale paid after cancel, reordered/duplicate events, outage keeps lease, integrity suspends) | Implemented + **Tested** with a synthetic DB model (`tests/test_stripe_billing.py`); not proof of SQL |
| End-to-end paid customer survives lease lapse; outage does not extend; cancel denies; cancelled not reactivated; revoked key stays revoked; quota consumed unchanged | Implemented + **Tested** on disposable PostgreSQL with a fake Stripe (`tests/test_self_service.py`) |
| Rate bound, GET-only, deadline, capacity math, schedule simulation, heartbeat 0600, redaction | Implemented + **Tested** (`tests/test_billing_reconciler.py`) |
| Stripe read-after-event consistency (a read after a signed event reflects it) | **Unverified** assumption; the floor gives only second-resolution ordering |
| Real Stripe test-mode behaviour, `Date` header semantics, `rk_test_` permission scope | **Unverified** (no network used) |
| Behaviour above ~80 tenants at real Stripe latency | **Unverified**; simulation only |
| Running the reconciler as a separate OS user/service with a private Stripe key | **Unverified** (no deployment performed) |

## Residual risks

- Ordering still uses HTTP Date, but every unseen authenticated applicable denial creates a durable hold unless covered by strictly later authenticated recovery. Dates alone cannot restore access. Missing delivery and pre-upgrade uncertainty require the controls described above.
- A compromised reconciler can also suspend any tenant (denial signals) or hold the stale floor up to `now+300s`
  (availability only; it cannot extend a lease beyond what the SQL bounds allow).

- A cancellation with no webhook is bounded only by the 60s lease.
- A compromised reconciler can assert paid state; it is limited by the SQL bounds above and a read-only,
  test-mode, GET-only client, but it is a trust point.
- Without a trusted time source other than Stripe `Date` and the database clock, a large clock skew
  causes `clock_skew` (fail closed), not extended access.
- `resume` is manual; a persistent integrity anomaly keeps a tenant suspended until an operator acts.

## Launch blockers (not part of M2; M1 key recovery stays separate)

- **Key recovery:** a lost claim response is unrecoverable.
- **Key expiry:** keys last 365 days and are independent of billing.
- **Key rotation:** none.
- **Cancellation revocation:** cancellation does not revoke keys; the runtime lease/eligibility is
  the only gate. Reactivation after resubscribe restores the same (non-revoked) key.
- Ingress rate limiting, account recovery, narrowing the self-service process's DB role.

## Running the tests

```
GVAI_RUN_RECONCILER_POSTGRES=1 GVAI_REQUIRE_RECONCILER_POSTGRES=1 python -m pytest tests/test_reconciler_postgresql.py
GVAI_RUN_SELF_SERVICE_POSTGRES=1 GVAI_REQUIRE_SELF_SERVICE_POSTGRES=1 python -m pytest tests/test_self_service.py
python -m pytest tests/test_stripe_billing.py tests/test_billing_reconciler.py
```

Needs Docker and a cached `postgres:16` (never pulled). The `*_REQUIRE_*` flags make a missing prerequisite
fail instead of skip. The `postgres-integration` CI job pulls the image, sets every flag and fails on any skip.

## Pre-review migration 010 validation (provided baseline, 2026-11-11)

These results describe the provided baseline, before independent-review remediation. The
current results and the two retained policy conflicts are documented below and in the report.

All database runs used owned disposable local PostgreSQL containers and synthetic Stripe data.
The unchanged `test_newer_http_date_alone_cannot_reverse_denial` failed before the correction
(`applied_eligible` after denial), and passes with migration 010.

Final standalone original regression: **1 passed (3.80s)**.

| Final invocation | Result |
|---|---|
| `GVAI_REQUIRE_RECONCILER_POSTGRES=1 GVAI_RUN_PAID_POSTGRES=1 python -m pytest -q --tb=short tests/test_reconciler_postgresql.py tests/test_stripe_billing.py tests/test_billing_reconciler.py tests/test_paid_postgresql.py tests/test_postgresql_authority_schema.py tests/test_commercial_api_keys.py tests/test_commercial_usage.py` | 258 passed, 70 subtests passed (21.99s) |
| `GVAI_RUN_PAID_CHECKOUT_POSTGRES=1 python -m pytest -q -x --tb=short tests/test_paid_checkout_persistence.py` | 31 passed (52.04s) |
| `GVAI_RUN_SELF_SERVICE_POSTGRES=1 GVAI_REQUIRE_SELF_SERVICE_POSTGRES=1 python -m pytest -q --tb=short tests/test_self_service.py` | 15 passed (15.71s) |

The reconciliation suite covers populated 009-to-010 upgrades, unchanged original regression,
stale and newer-Date snapshots, valid recovery, evidence binding and signature rejection, atomic
rollback, audit immutability, duplicate/colliding events, out-of-order denials, revoked/terminal
customers, held resubscription, concurrent new denial versus recovery, and real quota reservation
denial even when eligibility flags are positive. Self-service tests now load migration 010 and
assert that ordinary paid webhooks cannot clear holds. Superseded tests asserting automatic
restoration were replaced with hold-preservation assertions.

Earlier development runs found and corrected test-helper mistakes; one checkout fixture setup
run failed, and its complete retry passed. No production Stripe requests, production database
connections, commits, pushes or deployments were performed. Independent review is required.

### Independent review remediation

Definitive negative polling snapshots create durable `evt_poll_TICKET` denial records when no hold
is active. Provider exceptions use the existing failure routines: transient failures do not create holds.
Additional negative polls while held do not manufacture newer payment barriers. Recovery invalidates
all outstanding tickets, including negative reads begun before recovery.

Transaction denials use a scoped signal under the customer lock. Invoice failures bind invoice and
subscription; refunds and disputes resolve and validate the charge/payment-intent/invoice/customer
chain before signaling, and require the affected charge to be the intent's latest charge. The currently entitled invoice and pinned subscription determine immediate transaction holds;
while held, the latest immutable billing period preserves that binding. Unmatched scoped evidence
is retained without imposing a hold on unrelated entitlements. A subsequent attempt to grant the
matching invoice/subscription promotes that evidence to a hold, including before initial pinning.
Authenticated later recovery covers the scoped evidence for the same tenant. Subscription deletion binds the pinned subscription; customer deletion remains
customer-wide. Customer-only notifications without transaction identity merely wake polling and
cannot directly attest a denial. Explicit malformed or cross-customer chains are rejected.

Authorized `status` monitoring now includes `active_denial_holds` and
`oldest_denial_hold_age_seconds`. The latter measures continuous hold duration, retained across
additional denial signals and reset only by successful recovery. No tenant identifiers are exposed.

### Historical validation before migration 011

The earlier remediation run reported **833 passed, 2 failed, 0 skipped**, with **181 passing subtests**.
The two failures were outdated expectations: treating an unseen delayed denial as a duplicate,
and restoring a polling-canceled customer through an ordinary positive snapshot after owner resubscription.
Those tests were corrected with additional duplicate/ordering and signed-recovery assertions. The final
pre-011 log reported **836 passed, 181 passing subtests**, with no failures/errors/skips (201.63s).
Separate overlapping invocations reported 2 corrected tests, 63 reconciliation tests and 157 PostgreSQL-backed
tests passing; do not add these totals together. The older temporary remediation report is unavailable.
These are historical local results, not evidence that migration 011 passes or any production-readiness claim.

### Historical upgrade quarantine (migration 011)

Migration 011 is implemented for **local development and owned disposable PostgreSQL testing only**.
No staging/production migration or real customer suspension is authorized. It follows unchanged 009/010.
A separate operational review must approve any future fencing, clock assurance and customer impact.

009 retained current flags and event hashes, not a complete denial/recovery history. An apparently paid
customer may have been automatically restored after a denial. Consequently 011 does not exempt a
customer based on eligibility, a lease, an invoice, absence of events, or the latest outcome. Every existing
customer gets an immutable tenant-bound `billing_legacy_upgrade_cases` record. Empty installs have
zero cases; customers created after installation use normal 010 paid verification.

The migration locks the customer/state and evidence tables, captures database cutover time C, and uses
`floor(epoch(C))+300` as a conservative recovery boundary. Retained floors/timestamps outside that bound,
missing state, or observable backward clock anomalies abort the transaction rather than invent an earlier
retirement time or lower a floor. The local fixture assumes the existing trusted database clock; an
unverifiable real clock/provenance would require stopping, not a config override.

Each `legacy_upgrade_<tenant_ref>` record is an **internal uncertainty/control marker**, outside the
`evt_` authenticated-ingress namespace. Its `billing_denials.event_created` value is a control boundary,
not a historical Stripe event time. Its hash binds canonical audit inventory JSONB, not a webhook signature.
Deferred tenant/hash/boundary constraints require a matching immutable case; no historical Stripe body,
type or payment timestamp is fabricated. The audit excludes keys, checkout URLs, raw evidence and signatures.

Real 010 hold pointers and continuous hold age are retained. Otherwise the internal marker becomes the
hold. Eligibility, verification lease and access are cleared, while invoice identity, subscription state,
periods, quota consumption, attempts and credentials are preserved. All pre-cutover tickets/claims are
invalidated. A completed immutable run record records the inventory count; partial installation rolls back.

`recover-denial` accepts the actual current hold ID, including an internal marker. It still requires a signed
TEST `invoice.paid` and a fresh complete current chain with matching customer/invoice/subscription. SQL
requires paid_at strictly greater than **every tenant denial/control boundary** and relevant scoped evidence.
Equal/older payments fail; waiting until the boundary elapses does not make an older payment qualify.
Original evidence custody and owner privileges remain mandatory. Resume, checkout, a normal positive
snapshot, owner judgment, and newer HTTP Dates cannot release the quarantine. Revoked customers remain
revoked; terminal recovery still requires owner-authorized replacement. Success records the existing immutable
recovery audit and invalidates outstanding tickets; failure rolls back. No extra charges or customer messages
are performed. Genuinely paying customers without qualifying later evidence can remain held until a normal
subsequent payment; do not silently waive ordering. No authenticated historical-provenance exemption API is
implemented: there is no local evidence that could safely authorize one.

`billing_upgrade_ready_v1()` checks the committed run, case count, marker digests/tenant bindings and
that each unresolved case still has a tenant hold. The function exposes a boolean, not case contents.
Paid runtime and reconciler startup validate its owner/search_path/grants and result; self-service checks
it at construction and before paid key issuance/account creation/checkout. The owner billing CLI checks it
before operations. A database trigger rejects positive customer writes when it is false, and paid reservation
independently checks readiness and the active hold. No config flag substitutes for database state.
Custom roles inherit only read-only readiness execution from existing paid/signal grants; new installations
must grant that function alongside their paid/reconciler allowlists. Recovery and case tables stay owner-only.
Status reports readiness and aggregate total/unrecovered cases without tenant identifiers.

Pending holds are compatible with service readiness because SQL independently blocks their access. Real
operational deployment would still require fencing all writers/paid access, draining requests, verifying clock
bounds, reviewing customer impact and signed evidence, validating unchanged ledger data, and independent
approval before reopening. Never roll back to 009 grant semantics or erase case/denial history to regain access.

Migration 011 validation results are recorded separately after execution. The new populated-009 regression
uses the real 300-second boundary and real HMAC/SQL checks against synthetic Stripe objects; it does not
alter clocks, backdate markers or claim live Stripe consistency. An owner-only corruption injection in tests
verifies that missing/inconsistent inventory fails readiness; ordinary roles cannot perform that injection.

### Migration 011 local validation (2026-11-11)

All runs used owned disposable PostgreSQL databases and synthetic TEST Stripe objects. No staging,
production, real customers or payment operations were accessed. Branch `feature/m2-reconciliation-fixes-v1`,
HEAD `bf1382483255054329c59eadf0caf7e18ca070ac`, plus the uncommitted 011 changes:

| Final invocation | Passed | Failed / errors / skipped | Passing subtests |
|---|---:|---|---:|
| New upgrade + complete reconciliation modules | 73 | 0 / 0 / 0 | 0 |
| All six PostgreSQL-backed modules | 167 | 0 / 0 / 0 | 0 |
| Full Python suite, all PostgreSQL opt-ins | 846 | 0 / 0 / 0 | 181 |

These overlap and must not be summed. Durations were 320.28s, 475.97s and 513.26s respectively;
the populated upgrade test waits for the actual 300-second boundary rather than modifying clocks or SQL.
Commands: `GVAI_REQUIRE_RECONCILER_POSTGRES=1 PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider tests/test_legacy_billing_upgrade_postgresql.py tests/test_reconciler_postgresql.py`;
all PostgreSQL runs select those two plus `test_paid_postgresql.py`, `test_paid_checkout_persistence.py`,
`test_self_service.py`, and `test_postgresql_advisory_integration.py`. Full suite uses the same options
without file selection. All five `GVAI_RUN_*` PostgreSQL opt-ins and both available REQUIRE flags are enabled;
advisory integration uses a fresh loopback database with its required non-superuser roles.

Earlier fast tests exposed fixture mistakes in subscription-history comparison and transaction fault injection;
those were corrected without changing payment ordering. A sandbox loopback failure in focused Python tests
was rerun with local socket access; the final focused run passed all 111 tests. Complete final targeted,
PostgreSQL and full-suite runs all passed. Logs and the source-hash manifest are identified in the local
`/workspaces/gvai-m2-migration-011-results.txt` review artifact; temporary log availability is not permanent
repository evidence. `git diff --check` passed. Migrations 009/010 were unchanged. Independent review is
required before preservation; none of these results authorize real migration execution or establish
production readiness, real Stripe consistency, clock assurance or sufficient capacity for a large legacy cohort.


### Bounded integrity and consistent entitlement (migration 012)

Forward-only `012_bounded_billing_integrity_v1.sql` follows unchanged migrations 009, 010 and 011.
It is implemented and exercised only in local owned disposable databases. It does not change the
legacy cutover boundary, create an exemption, clear a hold, reset quota, or enable production rollout.

The 011 global scan is retained as the installation prerequisite. Under locks, 012 copies each checked
case's marker/hash/boundary into protected integrity records and binds a root to the immutable 011 run.
The root stores exact case count, derived invalid-case count and a generation, not a configurable ready
boolean. The historical inventory is sealed against later insertion; its existing update/delete protection
remains. Only internal trigger paths can change derived validity/accounting. Runtime/reconciler cannot
read or write these tables, invoke repair/audit/entitlement helpers, or execute owner recovery.

State and recovery triggers revalidate only the affected tenant and adjust the invalid count only when
validity changes. Clearing a hold temporarily makes the case invalid; the same signed recovery transaction's
audit insert restores validity before normal apply. Rollback restores both accounting and original state.
An unresolved case without a hold makes global readiness false. The ready check reads the singleton root,
matching 011 run and immutable audit-fault latch; it does not count/rehash the entire cohort per request.
Tenant/payment-time recovery lookup is indexed. Callers must install 012 and include both the compatible
`billing_upgrade_ready_v1()` and new `billing_integrity_ready_v12()` read-only functions in exact allowlists.

Paid access authenticates credentials/resource ownership before integrity work and rechecks credential
expiry after billing/root lock waits. Status and locked key issuance use the same internal effective
entitlement state as paid access, including readiness, tenant marker validity, active hold, revocation,
current invoice/period, access window and verification lease. Status authenticates its account first and
locks the billing row before checking. Issuance checks in its locked transaction; no one-time claim is
consumed when a hold or invalid readiness denies access. Root shared locks follow billing locks and
serialize with violation/recovery accounting without serializing ordinary valid requests with one another.
Signup rate admission precedes database readiness; checkout validates its account before readiness.
Database checks still precede provider/account/grant operations; no config flag or force-ready API exists.

Owner-only `billing_upgrade_audit_v12()` performs the complete inventory/registry/count/digest check
outside the request path. Failure writes an immutable negative latch and blocks readiness; success cannot
clear a previous failure. A failure needs separate investigated forward-only repair, not `resume` or SQL
flag changes. Global diagnostic status still performs aggregate queries and is not a constant-cost public
endpoint. No large-cohort operational capacity claim follows from the bounded hot-path design alone.

The approved corruption model is explicit: supported SQL writes maintain the invariant transactionally;
the tenant's actual marker is independently checked at access. A trusted schema owner who disables
maintaining triggers or changes metadata can defeat incremental accounting. Full audits check the covered count/marker/validity invariants, and a tenant-local check rejects
its corrupted marker. They do not prove every database byte or protect against a malicious owner
replacing data and verification logic. Unrelated trigger-bypass corruption
is not magically detected globally on every request. No protection against a malicious schema owner is
claimed. Privileged maintenance must be fenced and fully audited before resuming service.

New disposable schedules cover in-flight 009/010 writers during 011, outside-transaction stale tickets,
lock-timeout rollback, concurrent signed legacy recovery/new denial, legacy terminal replacement,
readiness changes after key authentication, post-lock credential expiry, immutable counters/privileges,
invalid credentials, exhausted signup admission and positive flags under a hold. Measured cohorts compare
011 and 012 with valid/invalid requests and concurrent normal snapshot renewal. Renewals use genuine
SQL validation; clocks, signatures, cutover timestamps and payment ordering are not lowered for tests.
Final hardening execution counts and load artifacts are recorded after acceptance completes.


### Final hardening validation (migration 012, 2026-11-11)

Final targeted acceptance: **87 passed**, zero failures/errors/skips (680.32s).
Clean combined seven-module PostgreSQL acceptance: **179 passed**, zero failures/errors/skips (504.47s).
Full Python suite with every PostgreSQL opt-in: **860 passed, 181 passing subtests**, zero
failures/errors/skips (800.09s). These overlap and must not be added. The full suite passed before
one additional test-harness-only tightening: the pinned checkout fixture now probes TCP readiness,
excluding the temporary Unix-socket init server. All **31 checkout tests** (72.87s) and the clean combined
PostgreSQL run passed after that tightening; production code and assertion semantics were unchanged.

The clean disposable load sample used four clients, cohorts of 100/1,000/10,000 historical customers,
and one active post-cutover customer. There were 80 calls per phase/kind at 100 and 1,000 cases,
and 20 at 10,000. Valid-load phases also ran normal validated snapshot renewal. At 10,000 cases:
invalid-credential p95 fell from **824.417ms (011) to 9.454ms (012)**; valid reservation p95 fell from
**1714.636ms to 73.563ms**. All valid calls succeeded, all invalid calls were rejected, and there were
zero measured request/poll errors. The 012 polling sample retained **59.942s** of verification lease.
These short local SQL samples include shared-host variability and are not production capacity or HTTP SLOs.
Full per-phase quantiles/throughput and artifact provenance are in `/workspaces/gvai-m2-final-hardening-results.txt`.

Intermediate runs disclosed there include a trigger-record implementation error, an incomplete test stub,
a baseline benchmark that outlasted its lease, a 30-second disposable psql timeout, and 31 fixture setup
errors caused by temporary-server readiness. Assertions/timeouts were not relaxed. The readiness fixture
was strengthened to require TCP, valid traffic must succeed under 012, and all final runs above passed.
Migrations 009/010/011 and the signed evidence verifier remain unchanged. No production, real customer,
payment or communication action occurred. Independent review/approval remains required.
