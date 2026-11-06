# Offline Checkout-attempt contract V1

## Status and scope

[The model](../gvai/checkout_attempts.py) is pure, offline code:
immutable records, deterministic candidate transitions, and an abstract
`CheckoutAttemptStore` protocol. There is **no storage implementation**, migration
005, SQL execution, Stripe client, dispatcher, listener, signer, or key issuance.
It is not wired into HTTP, pilot routing, quota accounting, STOP or independent
authority. No state grants paid access.

The existing [Checkout builder](../gvai/sandbox_checkout.py) remains unchanged.
Its intent and fingerprint are validated again, including exact integer types,
the sandbox-only USD 9900 monthly quantity-one offer, association, redirects,
idempotency key and canonical digest.

`FrozenCheckoutRequest` additionally binds the trusted membership reference,
customer ID, adapter version, API version and exact canonical JSON parameter
bytes. Its independently domain-separated fingerprint covers all of these fields.
The only outbound parameters are mode, customer, one Price/quantity line item,
success/cancel URLs and an internal attempt client-reference ID. No arbitrary
metadata, email, discounts, custom amount or customer/subscription override is
accepted. Account/environment/idempotency and API version are frozen separately
for future adapter header/context use.

These are normalized adapter input bytes, not a claim about Stripe's wire
encoding or supported API versions. The future adapter must faithfully encode
this exact allowlist with the frozen context; no added defaults/options or
changed adapter version on a retry. The full request must be compared alongside
the digest; a caller-supplied digest is not trusted.

## Trust boundaries

`CheckoutApproval` and `VerifiedCheckoutSession` are **trusted adapter outputs,
not client schemas, cryptographic proofs or durable authority**. Constructing a
Python object or setting an approval flag proves nothing independently.

A future identity/provisioning adapter must resolve immutable issuer/subject to
the existing tenant/membership, explicit checkout-management permission, current
tenant and membership status, approved Price and trusted customer association.
Customer and Price must belong to the same sandbox account/environment/tenant as
the frozen request. Email, metadata and client-reference IDs never establish
ownership. No default Price, account, API version or credentials are provisioned.

Approval is request-exact and expires exclusively. Prepare and creation claim
require all approvals literally true, pilot presence and admitted subscription
literally false. Storage must re-read these conditions transactionally; a retained
approval object is not a substitute. Authentication-session expiry, permission
revocation and issuer mapping custody remain the verified identity adapter's job.

Recovery is a separate trusted worker operation, not a customer authorization:
it can record/close an already created purchase after membership revocation, but
cannot dispatch another create. Authoritative evidence must independently verify
session ID, account, sandbox context, customer, subscription, Price, quantity,
mode and originating attempt/request. `cs_test_...` syntax is an additional
restriction, not sandbox provenance. Raw webhook fields or a success redirect
cannot become `VerifiedCheckoutSession` without that verification.

## Deterministic state contract

All times are injected integer seconds. Transitions deny rollback, invalid types,
unexpected state, stale generation and invalid/expired leases. Records retain
request, creation time and prepare deadline across transitions.

| Operation | Source | Result and prerequisites |
|---|---|---|
| Prepare | No attempt | PREPARED, generation zero; current approval |
| Claim creation | PREPARED | DISPATCHING; current approval; before prepare expiry; committed dispatch intent required |
| Mark ambiguous | DISPATCHING, UNKNOWN, SESSION_ATTACHED | UNKNOWN; clear lease; retain session if known |
| Claim reconciliation | DISPATCHING, UNKNOWN, SESSION_ATTACHED | UNKNOWN if no known session, otherwise SESSION_ATTACHED; previous lease absent/expired |
| Attach/refresh evidence | DISPATCHING, UNKNOWN, SESSION_ATTACHED | SESSION_ATTACHED; live matching lease/generation, exact request, observation since claim and not in future |
| Quarantine | Any slot-holding nonquarantined state | QUARANTINED; retain request/session and slot |
| Expire unsent | PREPARED only | EXPIRED_UNSENT at/after prepare deadline |
| Close verified | SESSION_ATTACHED without active recovery lease | CLOSED_VERIFIED only with authoritative expired session/no subscription, or verified durable subscription handoff |

There is **no transition back to PREPARED or to a second creation claim**.
UNKNOWN never means safe to retry create. A timeout, process crash, lost Stripe
acknowledgment or uncertain dispatch outcome requires UNKNOWN/reconciliation.
Quarantine has no automatic exit in V1; investigation requires separate review.
EXPIRED_UNSENT and CLOSED_VERIFIED cannot restart.

Generations range from zero through `2**63 - 1`. Every changing transition
increments once; exhaustion explicitly raises `AttemptDenied` and retains the
slot, without wrapping or returning an invalid record. Lease duration is 1-300
seconds; boundaries are exclusive. Lease expiry is not evidence that an external
call never happened. Fencing protects local writes, not remote Stripe execution.

Exact session-evidence replay against the current attached record is a no-op:
it does not refresh timestamps, leases or generation. Stale generations still
deny. Once a session ID is attached it cannot be replaced; terminal session status,
subscription and durable handoff identity cannot be rolled back or rewritten.
Conflicting evidence must be explicitly quarantined by the trusted storage path,
not swallowed or overwritten. Evidence refresh requires a new reconciliation
lease. These comparisons do not verify Stripe signatures or real session state.

## Required atomic storage behavior

The protocol deliberately has no in-memory or PostgreSQL backend. Pure
`resolve_prepare` only checks supplied snapshots; it does not acquire locks,
query history, prove uniqueness or prevent concurrent purchases.

A future transactional backend must:

1. Use `(account, sandbox environment, attempt ID)` as durable identity, matching
   the Phase 3A idempotency namespace. Never scope uniqueness by tenant alone.
2. Lock tenant admission across accounts, then membership/permission, customer,
   Price and attempt in one consistent reviewed order. Check existing admitted
   subscriptions and pilot overlap under compatible provisioning locks.
3. Atomically recheck approval, insert the immutable request and acquire one
   unresolved-purchase slot per tenant. A different attempt or account cannot
   bypass an occupied slot.
4. On exact attempt replay, compare the entire frozen request and return existing
   state unchanged, including old expiry. Changed owner, membership, customer,
   offer, adapter version or bytes is conflict. Another tenant receives only a
   sanitized denial, never the existing session or request.
5. CAS the **complete expected record**, not a caller's generation alone, for
   claim, confirmation and recovery. Reject changes to request, identity, creation
   time or deadline; call `validate_recovery` in the same transaction for proposed
   recovery candidates. It reconstructs the permitted transition and rejects
   arbitrary state, generation, session or lease replacement. Python frozen
   objects are not database immutability.
6. Commit creation claim before exposing any dispatch eligibility to a future
   supervised adapter. Bound statements/locks and leases; never hold a transaction
   open across a Stripe call. No automatic create retries are supplied by V1.
7. Enforce scoped session-ID uniqueness across attempts and durable customer/
   subscription composite associations. Confirm duplicates without writes;
   preserve/quarantine conflicts atomically with auditable sanitized codes.
8. Use database time for authoritative lease/expiry decisions. Return a result
   only after known commit. Raise `AttemptStorageUnavailable` on unavailable
   storage; raise `AttemptCommitUnknown` for uncertain commit. Read/reconcile the
   same identity on ambiguity; never treat an exception as success or allocate a
   replacement. An unknown prepare/claim commit may exist even when no record
   was returned. Local UNKNOWN candidates do not make that outcome durable.

No persistent replay prevention, SQL constraints, transactional rollback, ACL,
deadlock handling, crash recovery or exactly-once external purchase is proved.
A paused/stale worker can outlive a database lease; a future dispatcher must
prevent delayed create calls and safely reconcile them. Local fencing alone
cannot guarantee this or undo a remote purchase.

## Slot release and retention

PREPARED, DISPATCHING, UNKNOWN, SESSION_ATTACHED and QUARANTINED hold the tenant
slot. Local deadlines, browser cancellation, missing webhook delivery, failed
lookup, or an expired idempotency cache never release it.

Only EXPIRED_UNSENT (durably never dispatched) or CLOSED_VERIFIED releases the
attempt slot. Verified expiration must establish that the specific session is
no longer payable and produced no subscription. Completion alone is insufficient:
release requires a separately verified durable subscription handoff reference.
The backend must validate that reference against the same customer/tenant/Price
and serialize it with admission so no gap permits a second purchase. An admitted
subscription continues blocking new Checkout even after attempt-slot release.
No attempt, handoff or session status creates an eligible entitlement projection;
the existing active-plus-paid fresh authoritative reconciliation remains required.

Keep attempt identity, request, fingerprints and session tombstones; no delete,
purge or automatic replacement policy is implemented. An exhausted/quarantined
record remains blocked pending separate investigation.

## Verification gates

[Offline tests](../tests/test_checkout_attempts.py) exercise immutable request
binding, replay/conflict behavior, substitution, revocation, leases, stale workers,
unknown outcomes, generation boundaries, evidence checks and slot release.
They are candidate-model tests, not evidence that a persistent store implements
this protocol. No fake store is presented as durability.

Before any operational adapter: review this contract; separately authorize
additive schema/role design; test actual disposable PostgreSQL compilation,
FKs/ACLs, two-connection races, full-record CAS, session uniqueness, rollback,
lost commit acknowledgment and restart/restore fencing. Independently validate
Stripe API semantics, account/Price provenance and reconciliation. Authentication,
non-pilot provisioning, paid-only runtime and secure one-time key delivery remain
launch blockers. No database or Stripe execution is authorized by this document.
