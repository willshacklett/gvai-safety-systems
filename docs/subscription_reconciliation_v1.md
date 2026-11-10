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
| Audited SECURITY DEFINER functions, ticket/floor state, guards | `migrations/postgresql/009_subscription_reconciliation_v1.sql` |
| Python store (`claim -> Stripe read -> apply`, three short transactions) | `gvai/postgresql_billing.py` |
| Bounded reconciler loop, capacity arithmetic, schedule simulation | `gvai/billing_reconciler.py` |
| Operator CLI (`reconcile-serve`, `webhooks`, `status`, `resume`) | `gvai/billing_operator.py` |
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
5. **Denials always apply.** A fresh denial event (within 300s) suspends immediately even before
   the confirming fetch; the next verified poll restores access if Stripe still says paid.
6. Tickets are single-use, tenant-bound and expire; events are idempotent by id + payload hash;
   an event whose time is older than an already-applied snapshot is acknowledged as
   `covered_by_newer`.

### Ordering: what the `Date` header does and does not prove

**Not resolved; mitigated only.** Stripe's `Date` header is the time the HTTP response was generated, at
one-second resolution. It proves a read happened *after* instant T. It does **not** prove the read reflects every
state change made at or before T: Stripe documents no read-after-event consistency for retrieve/list calls, so a
lagging read replica could return pre-event ("still paid") state with a later `Date`. Also:

- The six reads of a fetch are separate requests, not one atomic snapshot; `observed_min`/`observed_max` only
  bound them conservatively.
- A positive snapshot in the same second as `event.created` is rejected (strict `>`), which is safe but coarse.
- Event delivery can be late or lost; with no webhook there is no floor at all (bounded only by the 60s lease).

Residual exposure: after a denial event, a stale-paid read with a later `Date` could restore access until the next
poll (~20s) reads consistent state. It is bounded by one poll interval and never exceeds the 60s lease chain, but it is
not eliminated. **No test can prove this locally**; it needs real Stripe test-mode evidence.

Proposed stronger fail-closed mechanisms (not implemented, in order of value):

1. **Single atomic read:** one `GET /v1/subscriptions/{id}?expand[]=latest_invoice.payment_intent.latest_charge`
   replaces the separate invoice, payment_intent and charge reads, so state and `Date` come from one response.
2. **Events cross-check:** before accepting a positive snapshot, list `GET /v1/events?created[gte]=<last applied
   observation>` filtered to `DENIAL_EVENTS` types and refuse (retry later) if any denial event is not yet recorded in
   `billing_events`. Stripe's event log is authoritative, so this also covers lost webhooks.
3. **Settle margin:** raise the floor to `event.created + N` seconds (N about 5) so a replica must have had time to converge.

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
| owner (operator CLI) | `claim_one`, `resume`, `begin_resubscribe`, bind/checkout/portal/revoke |
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
| 009 functions, role privileges, ticket single-use/tenant-bound/expiry, floor ordering, idempotency, transient vs integrity, revoked never reactivated, quota never reset, cross-tenant period/invoice isolation, terminal resubscribe, SKIP LOCKED disjoint claims, 200-tenant starvation | Implemented + **Tested** on disposable PostgreSQL 16 (`tests/test_reconciler_postgresql.py`, 27 tests) |
| Store/service logic (stale paid after cancel, reordered/duplicate events, outage keeps lease, integrity suspends) | Implemented + **Tested** with a synthetic DB model (`tests/test_stripe_billing.py`); not proof of SQL |
| End-to-end paid customer survives lease lapse; outage does not extend; cancel denies; cancelled not reactivated; revoked key stays revoked; quota consumed unchanged | Implemented + **Tested** on disposable PostgreSQL with a fake Stripe (`tests/test_self_service.py`) |
| Rate bound, GET-only, deadline, capacity math, schedule simulation, heartbeat 0600, redaction | Implemented + **Tested** (`tests/test_billing_reconciler.py`) |
| Stripe read-after-event consistency (a read after a signed event reflects it) | **Unverified** assumption; the floor gives only second-resolution ordering |
| Real Stripe test-mode behaviour, `Date` header semantics, `rk_test_` permission scope | **Unverified** (no network used) |
| Behaviour above ~80 tenants at real Stripe latency | **Unverified**; simulation only |
| Running the reconciler as a separate OS user/service with a private Stripe key | **Unverified** (no deployment performed) |

## Residual risks

- Ordering relies on the `Date` header (see above); stale-paid-after-denial is bounded, not eliminated.
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
