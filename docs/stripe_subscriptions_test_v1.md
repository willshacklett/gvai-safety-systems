# Stripe subscriptions and paid advisory accounting: TEST MODE ONLY

## Status and authority

This is an uncommitted implementation for review, not live billing or deployment
approval. No Stripe request, product/customer creation, webhook registration or
charge was performed during implementation. The standard-library REST transport
avoids a new Stripe SDK dependency; optional PostgreSQL runtime requirements
remain unchanged. Real Stripe test-mode execution and the combined HTTPS/Python
driver/database path still require validation.

The proposed price is USD 99/month and is **not approved for live activation**.
The implementation accepts only test secret keys and objects (`livemode=false`).
There is deliberately no live-mode switch. Production activation requires a
separately reviewed change, founder price approval and operational sign-off.

The product remains caller-input **advisory ALLOW / QUALIFY / BLOCK**:
`advisory_only=true`, `enforcement_applied=false`. No independent shutdown,
certification, safety or uptime guarantee is supplied.

## Explicit subscription policy

- One operator-bound Stripe customer and one lifetime subscription identity
  per tenant; neither can be rebound through a customer request.
- Exactly one configured USD 99 monthly licensed price, quantity one.
  No trial, coupons, credits, prorations, tax adjustments, multi-price plans,
  overages or alternate currencies are supported in this first implementation.
  Configuring those features causes denial rather than an invented entitlement.
- Paid access requires an authoritative **active subscription AND paid invoice**,
  the configured price and matching invoice-line period, a successful matching
  PaymentIntent and an unrefunded, undisputed paid charge. Out-of-band/manual
  invoice payment cannot grant access.
- Each verified paid period gets **100,000 attempts**, independently of calendar
  months. Renewals create new invoice-keyed rows, never reset existing counters.
  Replacement invoices for overlapping periods fail closed for reconciliation.
- Failed payment, paused/incomplete/unpaid/trial/canceled subscriptions deny.
  A scheduled period-end cancellation retains access only until paid-through
  expiry; an earlier `cancel_at` further shortens access. Immediate cancellation
  or operator billing revocation denies new work. Revocation is sticky.
- Each acknowledged new reservation consumes one unit, including evaluator
  failure, lost response, completion failure and abandoned work. No refunds of
  request units. Request IDs remain tenant-scoped across paid renewals; changed
  payload/project conflicts, exact replay never evaluates again.
- Current key expiry/revocation, tenant/membership status and project ownership
  are checked in the database, including after lock waits. Completion rechecks
  access and may withhold an already-calculated result; committed units remain
  charged. This is not cancellation of customer workloads.

There is no claim of instantaneous knowledge of an external Stripe failure.
Verified webhook processing serializes on tenant/mapping locks and suspends
access on failed reconciliation. Lost/delayed events are bounded by a **60-second
freshness lease**, not a payment grace period. The bounded reconciler (see
`docs/subscription_reconciliation_v1.md`) re-verifies each active tenant about every
20 seconds; missed scheduling or Stripe outages expire access and are never extended.
Clock synchronization, reliable webhook delivery and scheduler monitoring are
mandatory launch gates. A transaction already committed before suspension is
not retroactively canceled.

## Separate ledgers and database roles

Apply migrations 001-004, in order, as the same dedicated non-superuser owner
with `psql -v ON_ERROR_STOP=1`. Migration 004 adds customer/subscription mappings,
paid invoice periods, event IDs plus payload hashes, and paid attempts.
It stores no raw events, card data, payment details, API keys or signing secrets.
The Checkout session URL is a sensitive handoff stored only in the protected
owner-access mapping table.

Paid routines reuse `advisory_customer_v1` authentication and canonical request
digests. They do not reuse pilot caps, calendar-month counters, execution
authority receipts or signers. Deferred count checks keep paid attempts and
consumption atomic; protected updates cannot rewrite prior periods/attempts.

Existing unmapped pilots are unchanged. Once a tenant is bound to billing,
a database guard rejects new pilot attempts: nonpayment cannot fall back to
remaining pilot allowance. Paid reservations also reject reuse of request IDs
already in pilot history. Old pilot rows and consumed units remain untouched.

The paid runtime needs a **separate restricted role** with only schema USAGE
and EXECUTE on these functions:

```text
reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)
complete_paid_v1(text,bytea,text,text,boolean)
paid_usage_v1(text,bytea,text)
```

Do not grant direct table access, raw reservation functions, pilot entry points,
owner membership or migration rights to this role. Runtime startup/readiness
use the existing privilege verifier with the paid entry list. The pilot defaults
and its privilege checks remain unchanged. No runtime configuration can promote
itself to owner or switch ledger types.

The billing worker/CLI is a **separate trusted owner process**, not a customer
API. It serializes Stripe snapshot reads and event application under the same
tenant/mapping locks, preventing concurrent workers from applying an older
snapshot after a newer one. A savepoint rolls back failed snapshot changes,
commits denial, and leaves the event unacknowledged for retry. Unknown commit
outcomes require replay/reconciliation, never a new entitlement or request ID.
Billing-only connections allow up to 45 seconds of idle transaction time for
bounded external reads; evaluation connections retain their original bounds.

## Test-mode setup (future authorized execution only)

Do not put real configuration or handoffs in the repository. Use separate OS
accounts/private mode-0700 directories for billing owner, evaluation runtime
and original pilot operator. Configuration files must be owner-only regular
files, mode 0600/0400, using the existing strict private-file parser.

After separate authorization, configure one Stripe **test** recurring Price
with amount 9900 USD, monthly licensed usage, quantity one and no trial or
discount. A trusted operator must pre-create a test customer; the application
does not create external customers. Configure the test customer portal to
permit cancellation/payment-method updates only, not subscription/price changes.
Do not publish the proposed price or send invitations yet.

Billing owner configuration (placeholders, not usable secrets):

```json
{
  "mode": "stripe-test-operator",
  "operator_database_dsn": "host=127.0.0.1 dbname=PRIVATE_DB user=OWNER password=PLACEHOLDER",
  "stripe": {
    "secret_key": "sk_test_REPLACE_PRIVATELY",
    "webhook_secret": "whsec_REPLACE_PRIVATELY",
    "price_id": "price_REPLACE",
    "success_url": "https://FOUNDER_APPROVED_HOST/billing-return",
    "cancel_url": "https://FOUNDER_APPROVED_HOST/billing-cancel",
    "return_url": "https://FOUNDER_APPROVED_HOST/billing-return"
  }
}
```

URLs are server-configured, never supplied by a customer. A success URL grants
nothing. Hosted Checkout and portal URLs are written to newly created mode-0600
files, never stdout. Hand them only to the independently verified tenant contact.
Existing evaluation/usage keys do not authorize billing management.

Provision a synthetic pilot identity and project with the existing operator
onboarding first. Its cap is not converted or reset. Then:

```sh
python -m gvai.billing_operator --config /private/billing.json bind \
  --tenant TENANT_ID --customer cus_TEST_CUSTOMER
python -m gvai.billing_operator --config /private/billing.json checkout \
  --tenant TENANT_ID --output /private/checkout-handoff.json
python -m gvai.billing_operator --config /private/billing.json portal \
  --tenant TENANT_ID --output /private/portal-handoff.json
python -m gvai.billing_operator --config /private/billing.json reconcile --tenant TENANT_ID
python -m gvai.billing_operator --config /private/billing.json revoke --tenant TENANT_ID
python -m gvai.billing_operator --config /private/billing.json webhooks --port 8081
python -m gvai.billing_operator --config /private/paid-runtime.json serve-paid
```

The paid runtime uses the existing runtime JSON format and only its restricted
database role, pinned authority and API-key verifier, **not Stripe/owner secrets**.
The original operator remains responsible for key issuance, expiry, revocation
and tenant suspension. Subscription renewal never extends key expiry; rotate
keys through a reviewed operator procedure before they expire, never rewrite
revoked credentials.

Checkout creation persists intent before the external call and uses a stable
server idempotency key. A cached session is handed off again, never replaced.
After 23 hours, or an expired/completed session needing replacement, stop for
operator recovery rather than risk a second subscription. Verify Stripe's
session/subscription history and database mapping before any repair. There is
no automated resubscribe/rebind/unsuspend or checkout-intent-reset command.

## Webhook and transport contract

The separate billing listener binds **127.0.0.1 only** at
`POST /v1/stripe/webhook`; it exposes no Checkout, portal, evaluation or operator
route. It reuses bounded HTTP headers, concurrency and socket deadlines.
Require JSON, one Content-Length, one Stripe-Signature, no transfer/content
encoding, at most 64 KiB. HMAC-SHA256 covers the exact raw bytes plus timestamp,
uses constant-time comparison and a 300-second timestamp tolerance. Duplicate
JSON keys, malformed/nonfinite JSON, wrong mode/version and Connect events deny.
Processing failures return redacted 503 without acknowledging the event.

Pin both REST requests and webhook endpoint version to **2024-06-20**.
The transport fixes `https://api.stripe.com`, disables environment proxies and
redirects, bounds responses and timeouts, and performs no automatic retries.
Do not configure the same signing secret on an unrelated endpoint.

Subscribe to:

```text
checkout.session.completed, checkout.session.expired
invoice.paid, invoice.payment_failed, invoice.payment_action_required
invoice.voided, invoice.marked_uncollectible
customer.subscription.created, customer.subscription.updated
customer.subscription.deleted, customer.deleted
charge.refunded, charge.dispute.created
```

Only verified event IDs, associated tenant and raw-body hash are committed.
Events are triggers to fetch current customer/subscription/latest invoice/
PaymentIntent/charge state, never payment authority themselves. Duplicate
effects are suppressed transactionally; differing payloads for a retained
event ID are rejected. Historical reordered events always reconcile current
state. Multiple subscriptions, invoice substitution, overlapping periods or
mapping conflicts suspend for operator investigation.

Do not reuse the prepared mTLS-only customer ingress unchanged: Stripe cannot
present an operator-issued client certificate. A separately reviewed HTTPS
webhook ingress must forward only the exact webhook route to this separate
listener. Keep customer advisory ingress authenticated and operator routes
unexposed. No ingress/deployment/website files were changed here.

## Focused validation and remaining launch gates

Synthetic tests mock all Stripe requests and use an explicitly labeled
serialized transaction model for billing-store and adapter behavior:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider \
  tests/test_stripe_billing.py
```

Real SQL contracts can use an already cached PostgreSQL 16 image, without
Python driver installation, network access, host ports or bind mounts:

```sh
GVAI_RUN_PAID_POSTGRES=1 PYTHONDONTWRITEBYTECODE=1 python -m pytest -q \
  -p no:cacheprovider tests/test_paid_postgresql.py
```

The real SQL test applies all four migrations, uses distinct non-superuser
owner/runtime roles, verifies denial and accounting, and tests duplicate and
final-unit races at the **100,000** threshold. The 99,999-attempt state is seeded
as owner with the count/history guards temporarily disabled, matching synthetic
rows and counters; all guards are restored before the boundary race. This is
not 100,000 real HTTP requests or a throughput benchmark. The owned container,
temporary password and tmpfs data are removed on success/failure.

Before any customer/live launch:

1. Validate real Stripe TEST Checkout, payment, webhook retry/reordering,
   failed renewal, portal cancellation, refunds and recovery. Confirm API-version
   compatibility and unsupported tax/discount policy with the founder.
2. Validate real psycopg billing persistence and paid application restart behind
   reviewed HTTPS; original 47 driver integration tests are still unexecuted here.
3. Deploy and exercise the 20-second bounded reconciler (implemented and locally tested;
   see `docs/subscription_reconciliation_v1.md`, incl. its ~80-tenant capacity limit), redacted failure
   alerts, clock synchronization, webhook delivery/queue monitoring, capacity
   limits and database backup/restore reconciliation. Stale restores can restore
   revoked keys, counters or events: fence the service, do not auto-resume.
4. Approve secure operator handoffs, key rotation, cancellation/support identity
   checks, privacy/retention, tax/refund terms and incident procedures. Existing
   verified support contact is contact@gvaisafety.com; never send keys or payment
   details by support email. On uncertainty, revoke/suspend first, reconcile
   Stripe plus database history, preserve attempts, and explicitly approve recovery.
5. Obtain founder price/live-mode approval and a focused payment/customer-security
   review before any separate deployment, live-key handling or real charge.

No skipped test is a PASS, and real SQL alone is not combined HTTPS/Stripe delivery.

## LAUNCH CODE 035 validation evidence

Python 3.14.2: **393 passed, 98 subtests passed, 47 skipped**, covering the
50 synthetic billing cases, one real network-disabled PostgreSQL SQL contract
and the focused commercial/baseline regressions. All four migrations applied
successfully in cached PostgreSQL 16; the real test used Docker's bundled psql,
not the unavailable psycopg driver. Its container and tmpfs were removed.
The 47 original psycopg integration cases were explicitly disabled, not passed.
No actual Stripe call or combined HTTPS/Stripe/Python-driver test occurred.

Syntax/compilation, Python 3.9 grammar parsing (not runtime certification),
changed/new-file whitespace and local documentation links passed. The original
PostgreSQL advisory adapter, reservation adapter and migrations 001-003 retain
their pre-billing hashes. All work remains unstaged and uncommitted.

Billing-task inventory (the prior 27-file extraction remains uncommitted):

New:

- [stripe_billing.py](../gvai/stripe_billing.py)
- [postgresql_billing.py](../gvai/postgresql_billing.py)
- [billing_operator.py](../gvai/billing_operator.py)
- [004_paid_advisory_v1.sql](../migrations/postgresql/004_paid_advisory_v1.sql)
- [test_stripe_billing.py](../tests/test_stripe_billing.py)
- [test_paid_postgresql.py](../tests/test_paid_postgresql.py)
- [this runbook](stripe_subscriptions_test_v1.md)

Updated:

- [commercial_http.py](../gvai/commercial_http.py): separate bounded webhook listener
- [private_staging.py](../gvai/private_staging.py): trusted paid-usage construction;
  unchanged pilot defaults
- [README.md](../README.md): test-mode implementation pointer
- [commercial_advisory_base_v1.md](commercial_advisory_base_v1.md): distinguish extraction history
- [private_staging_v1.md](private_staging_v1.md): distinguish pilot and paid entry points


## M2 denial holds (migration 010)

Apply `010_subscription_denial_hold_v1.sql` after unchanged migration 009 as the non-superuser
schema owner. Previously unseen authenticated applicable denials establish durable holds regardless of delivery age, unless covered by strictly later authenticated recovery; later HTTP Dates and ordinary
polling cannot recover paid access or quota. See [operator recovery and limits](subscription_reconciliation_v1.md#operator-recovery)
for the signed subsequent-payment evidence workflow, audit boundary, permissions and upgrade limits.
`resume` only resumes polling; resubscription does not bypass a hold.


## M2 historical upgrade quarantine (migration 011)

For local disposable testing, install forward-only `011_legacy_billing_quarantine_v1.sql` after unchanged
009/010. All customers existing at cutover are conservatively quarantined; apparently paid flags are not
historical recovery evidence. An empty installation does not quarantine future customers. Internal markers
record uncertainty and a database cutover boundary, never invented Stripe events. Existing real holds,
invoices, quota and credential history are retained; pre-cutover tickets are invalidated.

Owner `recover-denial` still requires signed later payment and a matching current paid chain. A real 010 hold
retains its pointer but its recovery must also cross the legacy boundary. Do not perform an additional charge
or manually clear a hold to work around missing evidence. Paid/reconciler allowlists now also include
`billing_upgrade_ready_v1()`; startup/readiness and the database reject incomplete inventory. See the
[011 policy and historical results](subscription_reconciliation_v1.md#historical-upgrade-quarantine-migration-011).

No staging/production execution, real customer suspension, communications or payment action is authorized.


## M2 bounded integrity (migration 012)

For local disposable testing, apply `012_bounded_billing_integrity_v1.sql` after unchanged 009/010/011.
The migration validates and seals the 011 inventory, then maintains exact invalid-case accounting through
restricted database triggers. Readiness and authenticated tenant access no longer rehash all historical
customers per request. Both read-only readiness signatures belong in paid/reconciler allowlists; owner
recovery, full audit and internal entitlement functions remain unavailable to those roles.

Status, locked key claim and paid SQL share the effective hold/readiness/period/lease predicate. Invalid
credentials and exhausted signup admission are rejected before costly work; database checks still precede
grants/provider actions. A full owner audit latches any failure without a force-ready option. Trigger-disabled
owner maintenance requires a full audit: an aggregate is not evidence that arbitrary privileged corruption
could not occur. See the [012 design and limits](subscription_reconciliation_v1.md#bounded-integrity-and-consistent-entitlement-migration-012).
