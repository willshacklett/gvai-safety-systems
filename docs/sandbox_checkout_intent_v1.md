# Offline sandbox Checkout intent V1

## Status and trust boundary

[The builder](../gvai/sandbox_checkout.py) produces an immutable internal plan
only. It does not authenticate customers, persist attempts, provision tenants or
pilots, create Stripe sessions, verify payment, activate entitlements, or issue API
keys. It is not connected to existing HTTP or pilot routing. No credentials,
network, database, migration, listener, or execution authority is required.

Construct it only in trusted server code with explicit configuration, a membership
store, and an injectable clock. The client request allowlist is exactly the empty
JSON object `{}`; every property and non-dictionary input is rejected.
`context` and `attempt_id` are separate trusted server arguments, never fields to
deserialize from that request.

`AuthenticatedCheckoutContext` must come from a future verified identity adapter:
its issuer is a server-controlled identity-provider namespace, its principal ID
is an immutable internal subject identifier (not an email or display name), and
its selected tenant must be authorized. The builder checks expiration, syntax,
and an exact issuer/principal/tenant match against a fresh server-owned membership
with active status and explicit checkout-management approval on every build.
Membership adapter failures deny explicitly. Boolean-like integers are not
accepted as approval. No customer/subscription identity is accepted from clients.

These Python objects and configuration approval flags are **not authentication
or independent attestation**. Untrusted callers must never choose the adapter,
trust namespace, context, membership records, clock, or server configuration.
Someone controlling that trusted code can fabricate a plan, but no such plan
confers payment, tenant ownership, API access, or STOP authority.

## Fixed offer and redirects

The normalized plan always describes GVAI Advisory API, subscription mode,
USD 9900 per month, interval count one, quantity one, and sandbox environment.
There is no default Price/account or environment-variable discovery. Supply
explicitly approved sandbox `acct_...` and `price_...` identifiers; tests use
synthetic values only.

ID syntax and `price_approved=True` do not establish that a Price belongs to a
sandbox account: Stripe IDs do not reliably encode sandbox/live provenance.
Future trusted configuration approval and the Stripe adapter must independently
verify account, sandbox context, product, recurring currency/amount/interval,
quantity, and Price activity before creating anything. Deny mismatches; do not
substitute a Price, use client `price_data`, or silently switch environments.

Success/cancellation URLs are distinct server-pinned HTTPS destinations. The
deliberately narrow grammar requires a lowercase qualified DNS host and explicit
absolute path; credentials, ports, IP literals, localhost/local names, query
strings, fragments, percent escapes, traversal, backslashes, Unicode and whitespace
are rejected. This is lexical validation, not DNS/domain-ownership attestation.
Server configuration custody must establish control of both destinations.
Checkout success is informational only, never ownership or payment evidence.

## Attempts and idempotency

A server-supplied attempt ID is exactly 32 lowercase hex characters
(the all-zero ID is rejected). The server must generate it independently of
client claims and use it only after authenticated ownership checks. No generator
or durable allocation is included.

The immutable association includes issuer, principal, tenant and attempt. The
idempotency key is a domain-separated SHA-256 digest of account, sandbox
environment and attempt; a second canonical digest binds the complete normalized
intent, including association, approved Price and redirects. Neither is a secret,
signature, authorization token, or proof of persistence.

Identical retries (including concurrent calls) intentionally return identical
plans. Reusing an attempt with changed parameters produces the same key and a
different fingerprint. **The stateless builder cannot reject historical reuse**,
across tenants or otherwise. It cannot prevent duplicate subscriptions or
guarantee replay protection. Renewing authentication expiry does not change a
previously identical plan; membership and expiry are still checked on every call.

Before any Stripe call, future durable storage must atomically allocate/bind
account/environment/attempt to its owner and complete normalized intent; compare
the stored fingerprint and full intent on retries, reject conflicts, serialize
concurrent creation, and retain resulting session identity and uncertain outcomes.
Use the same Stripe idempotency key and parameters for an authorized retry.
Stripe's idempotency retention is not durable local replay prevention. Unknown
creation outcomes require reconciliation, never blind creation with a new ID.
Membership revocation races still require transactional admission/revalidation
in that future stage.

## Remaining onboarding gates

Future work needs authenticated sessions/CSRF protection, non-pilot tenant
provisioning, trusted customer mapping, durable attempt storage and recovery,
restricted Stripe credential custody, verified webhook ingestion, authoritative
fenced reconciliation and active-plus-paid fresh entitlement enforcement.
Paid-only runtime roles, quota policy and one-time authenticated API-key delivery
also remain required. Migration 004 is still unapplied and not operationally
approved. No existing pilot, UTC-month accounting, STOP or independent-authority
behavior changes.

[Offline tests](../tests/test_sandbox_checkout.py) cover the normalized shape,
membership/identity substitution, client overrides, IDs, redirects, explicit
sandbox approval, deterministic repetition/conflict fingerprints, dependency
failures, expiry and immutability. They establish no real Stripe, PostgreSQL,
durability, browser or operational payment-security guarantee.
