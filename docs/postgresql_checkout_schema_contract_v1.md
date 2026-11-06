# PostgreSQL Checkout persistence schema contract: Phase 3C

## Status and evidence boundary

Migration `005_checkout_attempts_v1.sql` intentionally **does not exist**.
[Source contracts](../tests/test_postgresql_checkout_schema.py) specify proposed
object names and constrained SQL spelling before implementation. One existence
test must fail; tests requiring its SQL explicitly skip until it exists.
Baseline hashes and extractor tests run independently. Do not create a stub,
xfail the existence check, or substitute comments/dummy functions for SQL.

These are regex/string checks, not a SQL parser, database execution, authentication
test or proof of transactions. Required declarations and source anchors can pass
without correct control flow. Every behavioral invariant below remains binding
even where it cannot be proved statically. Static green results must never be
presented as PostgreSQL or operational Stripe acceptance.

Migrations 001-004, [Phase 3A](./sandbox_checkout_intent_v1.md), and
[Phase 3B](./checkout_attempt_contract_v1.md) are preserved byte-for-byte.
No database, role, credential, listener or paid service is provisioned.

## Minimum proposed additive objects

Use the existing `gvai_authority` schema, BEGIN/COMMIT and a non-superuser
schema-owner guard. No replacement/alteration of existing objects, runtime GRANT,
role creation, approved seed data or entitlement activation. Revoke PUBLIC from
every new table and function. No automatic cleanup or cascades.
`ALTER TABLE ... ADD CONSTRAINT` is permitted only on the newly created Checkout
tables to install composite/circular references; existing tables remain untouched.

### checkout_authorizations

Owner-managed trusted issuer/immutable principal/tenant/membership binding.
`authorization_ref` is the primary key; issuer/principal/tenant is unique.
Composite tenant/membership FK references existing membership rows; a composite
candidate key includes authorization_ref, issuer, principal, tenant and membership
for attempt references. `active` and `checkout_approved` default false.
An optional finite integer-second expiry is exclusive.

`checkout_authorization_guard` validates exact principal-to-membership mapping,
valid external tenant/identifiers, and immutable binding. Revocation/permission
changes are allowed to the separate provisioning authority, never the customer
or Checkout worker. No email, display name, metadata or Python boolean proves
ownership. Authentication must resolve issuer/subject to this approved mapping.
An active evaluation membership alone does not grant checkout permission.

### checkout_attempts

Primary key: `(stripe_account_id, environment, attempt_id)`. Environment permits
only sandbox; attempt is nonzero 32 lowercase hex. All ownership, authorization,
membership, account, customer, Price and request fields are required and immutable.
Composite FKs bind:

- The full authorization identity to `checkout_authorizations`.
- Account/environment/tenant/customer to existing `billing_customers`.
- Account/environment/Price to existing `billing_prices`.

The customer must already be independently provisioned for a non-pilot tenant.
No function creates or reassigns it. Existing billing-customer membership identifies
its provisioning association; it does not automatically grant other members
checkout permission. Explicit authorization must be checked separately.

Store bounded nonempty `intent_bytes`, `request_bytes`, and `parameters` as bytea,
with 32-byte `intent_fingerprint` and `request_fingerprint`; required idempotency
key, adapter version and API version. Bytes represent the exact Phase 3A/3B
canonical objects, including the correct domain separators and nested JSON shape.
Fingerprints are binary decoding of existing lowercase hex digests, not hashes
of an alternative JSONB rendering. Validate/recompute them and compare full bytes.
Do not trust caller-supplied fingerprints or invent a second canonical format.

`checkout_request_guard` must validate canonical encoding, exact allowlisted
parameters, agreement with relational fields, fixed offer, and both fingerprints
and deterministic idempotency key. If implementing exact Python-compatible
canonicalization cannot be demonstrated, stop for review rather than silently
accepting JSONB normalization. Approved database Price must be USD 9900/month,
interval count one, quantity one; independently verified sandbox/account
provenance and trusted redirect custody remain adapter/configuration obligations.

Unique `(account, environment, idempotency_key)` and `(account, environment,
session_id)`; multiple NULL session IDs are allowed. Add a composite candidate
key over account/environment/tenant/attempt/session/customer/Price for handoffs.

`checkout_attempts_one_unresolved` is a unique partial index on **tenant_ref only**,
WHERE state NOT IN ('expired_unsent', 'closed_verified'). This includes UNKNOWN,
QUARANTINED, and SESSION_ATTACHED across accounts. No local timeout releases it.
Index uniqueness alone does not serialize subscription/pilot provisioning.

### checkout_handoffs

Immutable handoff ID and full account/environment/tenant/attempt/session/customer/
subscription/Price association with verified timestamp. Composite FKs bind both
the exact attempt/session/customer/Price and existing subscription/Price.
`checkout_handoff_guard` additionally compares the subscription's customer:
the existing subscription/Price FK alone does not prove that association.
Attempt `handoff_id`, when nonnull, must reference the same complete handoff,
not any globally unique handoff ID. Define supporting composite keys and an
appropriate deferred FK if needed for atomic attach/handoff transactions.

Only the reconciliation worker may record verified handoff evidence to an
already provisioned/admitted subscription. No Checkout function creates, admits,
activates or modifies that subscription. A cyclic handoff/attempt FK must be
implemented with explicit transactional ordering/deferral, never by dropping
association checks. Confirmation may atomically record the handoff and attach
its reference after verification. Handoffs cannot be rewritten or deleted.
The attempt-to-handoff FK uses account/environment/tenant/attempt/session/customer/
Price/handoff-ID in both directions' candidate keys, preventing ID-only linkage.

## State and transaction invariants

States exactly match the seven Phase 3B states. Default PREPARED, generation zero.
All timestamps finite/nonnegative; policy times are whole seconds. Nullable
session/lease fields have coherent all-or-none constraints. Generation is bounded
bigint, never decreases/wraps; any changing transition increments exactly once.
At maximum, deny without releasing the slot or returning invalid state.
`checkout_attempt_guard` rejects immutable-field changes, deletion, invalid
rollback, session identity replacement, and terminal evidence reversal.

All mutation entrypoints lock and compare the full expected stored record plus
expected generation, not merely an attempt ID or caller-supplied digest.
Use bounded statement/lock timeouts and database clock after waits. Match the
Phase 3B lease bounds (1-300 seconds), exclusive expiry, and generation behavior.

| Entrypoint | Required behavior |
|---|---|
| prepare_checkout_attempt_v1 | Lock tenant admission, current authorization/membership/customer/Price. Deny suspended, revoked, expired, unapproved, pilot or admitted-subscription overlap. INSERT with conflict resolution; exact request duplicate returns existing state unchanged; changed ownership/parameters returns sanitized conflict, never another tenant's record. |
| claim_checkout_attempt_v1 | PREPARED only, before deadline; revalidate all current approval and purchase-admission checks; commit DISPATCHING with new generation/lease before any future external call. |
| confirm_checkout_session_v1 | Changing confirmation requires live matching worker lease/generation and full request association; current trusted evidence observed since claim and not in future. An identical already-attached confirmation may return a zero-write duplicate without a live lease, subject to the checks below. Conflicting ID/context quarantines without replacement. |
| claim_checkout_reconciliation_v1 | Claim after absent/expired lease; UNKNOWN if no known session, otherwise SESSION_ATTACHED. Never changes state to DISPATCHING or authorizes another create. |
| mark_checkout_unknown_v1 | Ambiguous DISPATCHING/UNKNOWN/SESSION_ATTACHED outcome retains request/session/slot and clears lease. |
| quarantine_checkout_attempt_v1 | Retain unresolved purchase and evidence; no automatic exit or redispatch. |
| expire_checkout_unsent_v1 | PREPARED only, at/after deadline, never-dispatched provenance; EXPIRED_UNSENT. |
| close_checkout_verified_v1 | SESSION_ATTACHED without recovery lease; only authoritative expired/no-subscription evidence OR complete session with fully verified durable admitted-subscription handoff; CLOSED_VERIFIED. |

Use tenant-wide serialization across sandbox accounts, then a reviewed consistent
membership/authorization/customer/Price/attempt order, coordinated with future
provisioning. No external call inside a transaction. No backwards state or
second create claim. Expired leases do not prove a call did not occur.
Crash/timeout/lost acknowledgment/unknown commit require same-identity resolution,
never automatic replacement, even after Stripe idempotency retention expires.
Unknown prepare/claim commits must be queried before dispatch or allocation.

Exact prepare/session replay cannot refresh deadline, evidence, lease, state or
generation. For confirmation replay, first lock and validate the current full
expected record, exact attempt/owner/tenant/request association and expected
generation. Only SESSION_ATTACHED with no stored lease and entirely identical
stored session evidence qualifies for the no-live-lease exception. Preserve
session identity, observation/expiry timestamps, ownership, tenant-slot state,
generation and every other stored field; stale generation still denies.
The source contract requires an explicit `IF ... 'session_attached' ... THEN
RETURN 'duplicate'; END IF;` branch before any mutation, followed by lease checks
for changing confirmations. Token presence cannot prove equality or branch
correctness; future database tests must verify no writes and all negative cases.
Conflict outcomes must commit quarantine/audit effects where required,
not be rolled back as generic transport failures. No credential strings, raw
customer payloads or sensitive provider errors in logs/results.

Slot release requires durable never-dispatched expiry, or authoritative closure.
Browser cancel, success redirect, absent lookup, local deadline, metadata, or
client-supplied session ID is insufficient. Verify actual session account,
sandbox status, customer, mode, Price/quantity, request origin and subscription
through authoritative retrieval; a SQL `verified` flag proves none of this.
Completed session alone is insufficient. Handoff and admission must serialize
with slot release so no window admits another purchase. An admitted subscription
continues blocking new attempts after release. Preserve tombstones; no purge.

## Least privilege and forbidden effects

Future roles: authenticated preparation gateway gets only prepare; dedicated
Checkout worker gets claim/confirm/reconciliation/unknown/quarantine/expire/close.
A separately controlled provisioning authority manages authorizations, customer
mapping and Price approval; it is not the worker or customer gateway.
All entrypoints SECURITY DEFINER with a non-superuser trusted owner and pinned
`search_path = pg_catalog, gvai_authority, pg_temp`. The same path is required
for every SECURITY DEFINER helper. Private guard/helpers get no
application EXECUTE. Migration 005 issues no grants; deployment must separately
review exact signatures, inherited privileges and grant only intended functions.

Migration 005 must not overload any function name: one declaration per name,
including private helpers. A shared inventory examines every visible CREATE
token outside comments, literals and dollar-quoted bodies before any function
is extracted or its ACL checked. Only CREATE FUNCTION, TABLE, INDEX, UNIQUE INDEX,
TRIGGER and CONSTRAINT TRIGGER heads are supported. Any other CREATE form fails
closed, including CREATE OR REPLACE FUNCTION. Function definitions must use
unquoted ASCII `gvai_authority.name` with no whitespace around the dot; names
match `[a-z_][a-z0-9_]*`. Quoted/Unicode-escaped identifiers, unqualified names,
other schemas, dollar signs in names, alternate body delimiters and overloads
are rejected, including a quoted same-name SECURITY DEFINER overload in either
declaration order. Case and whitespace between keywords are normalized;
ordinary comments are ignored without treating comment markers inside literals
as comments. Nested block comments are unsupported and rejected.
Each function requires its own exact input-type signature in `REVOKE ALL
[PRIVILEGES] ON FUNCTION ... (types) FROM PUBLIC`; name-only or wrong-signature
revocation is not evidence. Literal/body/quoted-identifier text cannot supply
revocation evidence. The constrained source grammar uses named `p_...`
input arguments, single-token built-in or schema-qualified types (including
arrays), no defaults or OUT/INOUT/VARIADIC parameters, and `$function$` bodies.
Explicit IN modes, type modifiers, multiword types and quoted declaration
identifiers are also unsupported.

The approved path is exactly the ordered three-schema tuple `pg_catalog`,
`gvai_authority`, `pg_temp`, specified once as `SET search_path = ...`.
The checker parses the complete comma-separated value, not a substring.
Whitespace around `=` and commas is permitted. Appended, prepended, reordered,
duplicate, unexpected, quoted or string-valued schemas, missing/extra commas,
`TO`, `FROM CURRENT`, and repeated/overriding path settings fail.
Place language/security/volatility attributes before the path; its value ends
at the next function SET clause or the AS body delimiter. Other SET clauses,
such as statement/lock timeouts, may follow, but cannot override the path.

Unsupported spelling must fail rather than be silently ignored. This is a
deliberately constrained regex/token source gate, not a complete PostgreSQL
parser, an inventory of dynamic SQL, or proof of effective privileges.
Catalog tests must still check every function OID/signature, PUBLIC privileges,
runtime inheritance, trusted schema ownership/write permissions, owner
privileges and the effective search_path after actual installation.
Static checks cannot prove runtime SQL behavior, zero-write replay,
transactional correctness or isolation.

Neither runtime gets direct table/sequence writes, owner membership, raw/pilot
reservation calls, billing entitlement writes, key management or provisioning.
No new evaluation capabilities are added. Checkout code may read existing
tenants/memberships/Prices/customers/subscriptions/pilots but must not mutate
them, quotas, usage, credentials, authority heads or STOP controls. No attempt
status supplies verified payment or grants service. Existing active-plus-paid
fresh reconciliation and UTC-month quota accounting remain unchanged.

## Required future evidence (not established by source checks)

- PostgreSQL compilation, atomic migration rollback, FK candidate keys/deferral,
  function resolution, trigger execution, canonical digest compatibility.
- Restricted-role catalog/ACL tests including inheritance, PUBLIC and search_path.
- Two-connection same/different-attempt tenant races across accounts; concurrent
  revocation, Price withdrawal, pilot/subscription admission and handoff release.
- Full-record CAS tampering, session uniqueness, stale worker/fence/expiry,
  generation exhaustion, deadlock handling, transaction rollback, lost commit
  acknowledgment and restart/restore fencing.
- Authoritative Stripe account/Price/session/subscription provenance, closure,
  lost-response recovery and idempotency retention semantics.
- Dispatcher prevention of delayed calls: database fencing cannot fence Stripe.
  Exactly-once external purchase is not guaranteed by this schema.

All such tests remain blocked pending separate authorization, implementation,
and isolated disposable PostgreSQL/Stripe test stages. No unconditional skips
should hide missing behavior once migration 005 exists.
