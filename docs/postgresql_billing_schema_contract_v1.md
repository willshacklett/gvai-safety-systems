# PostgreSQL billing schema contract: Phases 2A-2B

## Status and scope

Phase 2A specified the then-absent migration; Phase 2B supplies the offline
[migration 004 source](../migrations/postgresql/004_subscription_billing_v1.sql).
It has **not been applied or tested against PostgreSQL**. No database connection,
role, runtime grant, listener or billing activation is provided. Migrations
001-003 and Phase 1 are unchanged.

[The unchanged contract tests](../tests/test_postgresql_billing_schema.py) have:

- An existence check that failed in Phase 2A and now reads actual implementation
  source, not a stub.
- Explicit skips when SQL is absent; the implementation now enables these source
  checks, not database acceptance tests.
- Executable baseline checks for unchanged migrations and existing pilot/UTC-month
  source contracts.

The source checks use the repository's existing regex/string inspection pattern.
They inspect a constrained SQL spelling, not a SQL AST or PostgreSQL catalogs.
Comments are removed; declarations must be actual source, not comments. These
checks cannot establish valid SQL, effective privileges, trigger correctness,
transactional isolation or adversarial safety. A declaration-only implementation
could pass some checks; **stubs are not an acceptable implementation**.

## Proposed records and associations

All Stripe-bearing tables use `stripe_account_id` and `environment`. Initially
`environment` is constrained to `sandbox`; live admission requires separate
review. Sandbox identity must also be tied to the correct independently
configured API credentials and webhook destination: a label alone proves nothing.

| Table | Contract |
|---|---|
| `billing_prices` | Account/environment/Price primary key; product and explicit approval; approval defaults false. Initial fixed offer is USD 9900 cents, monthly interval count 1, quantity 1. USD is an assumption requiring approval, not a configured Stripe Price. |
| `billing_customers` | Account/environment/customer primary key; unique tenant mapping per account/environment; composite tenant/membership FK. A trusted management flow establishes ownership, never webhook email or metadata alone. |
| `billing_subscriptions` | Account/environment/subscription identity; composite customer/tenant FK and approved-Price FK; full Phase 1 status vocabulary; initial incomplete/uncertain state; terminal tombstone, scheduled boundary, revision and lease fence. Admission defaults false; a partial unique index selects at most one admitted subscription per tenant/account/environment for this single-product scope. |
| `billing_invoices` | Account/environment/invoice identity; composite tenant/subscription and reconciliation FKs; status, amount/currency and verified flag default false. Verified must imply paid. |
| `billing_paid_intervals` | Account/environment/invoice/line identity; invoice, subscription/Price and reconciliation composite FKs; finite nonempty service interval. |
| `billing_event_inbox` | Account/environment/event primary key; bounded raw bytes and 32-byte digest; API version/type; database receipt time; pending default; retry, lease and quarantine metadata. |
| `billing_reconciliations` | Subscription-scoped revision primary key; separately unique reconciliation identity; nullable source-event FK for scheduled reconciliation; observation time, digest, certainty default false, outcome and fence. |
| `billing_entitlements` | Subscription-scoped projection referencing an accepted reconciliation revision; defaults deny/uncertain; eligible projection requires nonnull finite fresh/coverage bounds and certainty. |
| `billing_advisory_attempts` | Existing reservation event identity plus paid subscription/reconciliation provenance and completion state. Never fabricate pilot rows. |
| `billing_installation` | Separate migration identifier and contract version; do not rewrite the pinned V1 schema-version row. |

Use the composite candidate keys required by every FK. In particular,
invoice/coverage/projection links must not accept another tenant, account,
environment, subscription or Price through a globally unique surrogate alone.
Most FK columns are nonnull; the scheduled reconciliation source event is the
intentional exception.

Do not delete history with cascades. Accepted invoice identity/coverage is
immutable; mutable invoice observations may progress from unpaid to verified
paid, but cannot rewrite already accepted paid evidence.

## Guards required beyond declarations

The suite requires named trigger attachments to make the enforcement locations
reviewable. Future database tests must prove their actual behavior:

- `billing_subscription_transition_guard`: reject decreasing/reused conflicting
  revisions and fences; preserve identity and irreversible terminal cancellation.
- `billing_invoice_evidence_guard`: preserve association and accepted paid proof.
- `billing_paid_intervals_append_only`: reject update/delete of accepted intervals.
- `billing_reconciliations_append_only`: preserve historical decisions/revisions.
- `billing_event_identity_guard`: prevent rewriting event identity/payload/digest;
  permit only valid processing-state transitions.
- `billing_entitlement_consistency`: reject projections unsupported by current
  subscription state and invoice coverage. May be a deferred constraint trigger.

Every relevant timestamp needs finite, nonnegative Unix-time validation and
integer-second conversion compatible with Phase 1. Nullable times cannot grant
access. A single maximum paid-through timestamp must never bridge unpaid gaps.

No unpaid grace; only `active` plus current verified coverage and fresh/certain
reconciliation can be eligible. Operator-disabled tenants/memberships and terminal
cancellation override billing recovery. A genuinely newer certain reconciliation
can reverse a nonterminal scheduled cancellation, as in Phase 1.

## Role and function boundary

Migration 004 must not create/alter roles, grant privileges to runtime identities,
relax PUBLIC defaults globally, replace existing routines, seed an approved Price
or active customer, or change quota/authority/pilot data. Its own installation
marker is permitted. Actual role provisioning/grants are a later approved task.
All new tables/functions explicitly revoke PUBLIC access.

Future roles must be non-owner/non-superuser, unable to inherit the owner or
other application roles, create schema objects, or mutate tables/sequences:

| Future role | Only proposed entrypoints |
|---|---|
| Receiver | `enqueue_billing_event_v1` |
| Worker | `claim_billing_events_v1`, `begin_billing_reconciliation_v1`, `apply_billing_reconciliation_v1`, `retry_billing_event_v1` |
| Paid advisory runtime | `reserve_subscription_advisory_v1`, `complete_subscription_advisory_v1`, `subscription_advisory_usage_v1` |

Exact typed argument/return signatures require implementation review; names are
specified here, not executable GRANT statements. Entrypoints require a trusted
non-superuser definer and `search_path = pg_catalog, gvai_authority, pg_temp`.
Private helpers get no application EXECUTE grants.

The paid runtime must not execute raw `reserve_v1`, pilot entrypoints, management
operations or billing-worker routines. Existing pilot grants remain unchanged;
the same customer credential must not obtain paid service by falling back to
pilot routes. Separate assemblies and an explicit paid admission mode must enforce
this without changing working pilot semantics. Static absence of GRANT is not
proof that effective inherited privileges are safe.

Operator suspension uses independently managed tenant/membership state. No
billing function may reactivate it, revoke/reissue keys, directly rewrite authority
heads, produce execution grants or invoke supervisor STOP. The paid reservation
wrapper necessarily delegates ordinary atomic accounting (including ledger-head
advancement) to the unchanged `reserve_v1`; it cannot change authority identity,
epoch or trust-domain configuration. Advisory eligibility never confers
independent STOP authority.

## Transactions, retries and trust

1. Receiver: verify Stripe signature/context outside PostgreSQL; commit bounded
   inbox acceptance before acknowledgment. An exact duplicate neither rewrites
   bytes nor refreshes evidence. Conflicting event content quarantines and alerts.
2. Worker: claim inbox work with `FOR UPDATE SKIP LOCKED`; acquire a
   subscription-scoped database lease/fence **before** retrieving authoritative
   Stripe objects, outside long-held transactions.
3. Apply: lock and compare lease generation/expiry, validate association, then
   atomically record reconciliation, invoice coverage, projection and processing
   completion. A stale worker cannot commit, even if its API response arrives last.
4. Reservation: authenticate using existing current credential/tenant/membership/
   ownership checks, lock paid eligibility, reuse `reserve_v1`, then recheck
   freshness/cancellation/payment/key expiry with fresh database time after lock
   waits. Failed authorization aborts all reservation/idempotency/quota changes.
5. Completion: reauthenticate and enforce paid-result release without refunding
   committed attempts or promising cancellation of running work.

Stripe event order/`event.created` is not a revision. Exact delivery retries keep
their identity; a genuinely new reconciliation gets its own ID and increasing
revision. Duplicate invoice lines cannot add a second service interval.
Database commit uncertainty requires unavailable/reconciliation, not success.
Use bounded lock/statement timeouts and one documented lock order.

The trusted verifier/worker still establishes real payment, approved invoice
lines, identity ownership, API-version compatibility and observation provenance.
Database flags and digests do not prove any of these. No arbitrary JSON
`verified=true` or caller-computed `eligible=true` may be a runtime grant.
Evidence-age policy, retention/body-size limit, restore fencing, notifications,
refund/discount treatment and paid request allowance remain review decisions.
Billing renewals must not reset existing UTC-calendar-month quota buckets.

## Required future PostgreSQL acceptance tests

Actual execution in a separately authorized disposable database must prove:

- Migrations 001-004 parse/apply atomically under the non-superuser owner;
  a failed installation leaves no partial contract. Upgrade preserves all old
  rows, objects, privileges and pilot behavior.
- Catalog-checked composite FKs, candidate keys, null/NaN/infinite/negative time
  rejection, approved-price checks and default-deny projections.
- Cross-tenant/customer/Price/account/environment insert/update attacks fail.
- Unapproved Price, unpaid invoice, checkout-only event, missing coverage, stale
  evidence and uncertainty never activate; all 201 Phase 1 cases have DB parity.
- Terminal cancellation, operator suspension, same-revision conflicts, invalid
  schedule removal and immutable paid interval tests hold under concurrency.
- Duplicate delivery/invoice processing, conflicting digest, lost acknowledgment,
  worker crash, lease expiry/steal and stale-fence commit have no duplicate effect.
- Reservation/key/freshness/cancellation expiry during actual lock waits rolls
  back all accounting; expired/revoked access cannot release results.
- Every role is denied out-of-matrix functions, direct DML, owner membership and
  table/sequence access; paid keys cannot bypass through pilot/raw routes.
- Paid renewals preserve consumed UTC-month quota, immutable reservation history,
  and independent authority/STOP boundaries.
- Code rollback never routes paid traffic to an entitlement-unaware fallback;
  restore requires fencing/reconciliation, not replaying stale allow records.

Do not run existing PostgreSQL integration fixtures in this phase: they connect
and apply migrations. Static green checks are necessary source-review evidence
only, never proof that any item above works.

## Offline validation

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/local/py-utils/venvs/pytest/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_postgresql_billing_schema.py
```

Phase 2B source validation: **68 passed, zero failed, zero skipped**. Review the
implementation before separately authorizing any disposable-database execution.

## Phase 2B implementation decisions and limits

- Nothing is seeded except the installation marker. Price approval, trusted
  customer/membership association and subscription admission remain owner-managed,
  separately reviewed provisioning tasks. No worker function creates tenants,
  keys, approved Prices or admitted subscriptions.
- `max_evidence_age_seconds` has no default. Approval requires an explicit value
  between 1 and 86400 seconds; that ceiling is a conservative implementation
  bound, not an approved operational freshness policy. Projection freshness comes
  from the database lease-start time plus this owner-selected value, never a
  worker-supplied deadline.
- The initial normalized payment shape is deliberately narrow: one immutable
  invoice line, USD 9900 actually paid, one approved monthly Price, positive
  integer-second coverage of at most 31 elapsed days. Unpaid observations cannot
  create coverage. Taxes, discounts, zero-dollar invoices, credits, refunds,
  prorations, multi-line invoices and other currencies require separate policy;
  a future adapter must reject unsupported evidence rather than silently normalize
  it into this shape.
- Raw inbox payloads are limited to 256 KiB. The receiver supplies the resolved
  subscription identity as well as account, sandbox context, event type and API
  version only after external signature/envelope validation. The database hashes
  the bytes itself; it does not parse Stripe JSON or validate signatures. Receipt
  and installation timestamps retain database precision; policy evidence and
  service boundaries use whole Unix seconds.
- All seven event types are accepted as reconciliation triggers, not authoritative
  state transitions. After committing `begin_billing_reconciliation_v1`, the
  trusted worker must fetch current Stripe subscription and relevant invoice/line
  objects **after acquiring the fence**, then apply a complete associated snapshot.
  Replaying an old event body under a new reconciliation ID is not a valid use of
  the interface. Invoice evidence on an event-sourced reconciliation requires an
  `invoice.paid` trigger; source-less scheduled reconciliation can recover paid
  evidence from authoritative retrieval. Checkout alone cannot create coverage.
- Exact event duplicates cannot refresh receipt, leases or payment evidence.
  Reconciliation replay returns `duplicate` without writes; conflicting proof
  returns `conflict` and denies the projection. Delivery conflicts quarantine the
  original identity and deny its known subscription. The caller must commit
  conflict/deny results and alert, not roll them back as transport failures.
  Only fresh, certain authoritative reconciliation may recover uncertainty or
  remove a nonterminal cancellation boundary. Terminal tombstones never clear.
  Work targeting an already terminal subscription must be quarantined through the
  fenced retry entrypoint rather than repeatedly attempting a new reconciliation.
- Lock order is inbox (if any), subscription, Price, projection for workers;
  paid calls first use the existing credential/tenant/membership/ownership locks,
  then subscription/Price/projection, then existing quota/authority/bucket locks
  through `reserve_v1`. Post-wait authorization and lease checks use fresh database
  time; expired reconciliation leases abort the transaction. External retrieval
  never occurs inside these database transactions. A future adapter must set
  bounded statement/lock timeouts and treat database exceptions or uncertain
  commits as unavailable, never as authorization.
- This single-product runtime has no account-selector parameter. A second unique
  index therefore permits only one admitted paid subscription per tenant across
  all accounts, in addition to the scoped contract index. Customer creation and
  paid admission reject existing pilot tenants, and paid wrappers deny any pilot
  overlap. This is not a global pilot-route security proof: an owner could later
  create a pilot row using existing provisioning. Future deployment must enforce
  non-overlapping provisioning and deny all pilot/raw entrypoints to the paid
  role. The current pilot-only role verifier and runtime assembly remain unchanged
  and cannot be reused as a paid runtime.
- Paid attempts reuse the existing reservation event, quota and idempotency
  ledger. There are no refunds or quota resets on billing renewal/cancellation.
  Completion and usage reauthenticate and require a current paid entitlement;
  expired access cannot release stored results through these entrypoints.
- No effective-role, PL/pgSQL compilation, concurrency, restore-fencing or rollback
  guarantee has been demonstrated. Keep all paid entrypoints inaccessible until
  actual PostgreSQL acceptance tests and independent review succeed. Rollback
  must disable paid routing/grants first and retain billing/usage evidence; do not
  delete ledger history or fall back to pilot/raw access.
