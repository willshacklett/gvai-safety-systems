
# Reservation Authority Contract V1

## Status and scope

This document and `gvai/commercial_reservation_authority.py` define an offline
contract only. The reference authority lives in the test module and is an
in-memory fake. There is no production signer, credential database, authority
adapter, network endpoint, KMS integration, or activation/registration path.
Neither a `ReservationResult` nor a test receipt is an evaluation permission.

`CONTRACT_VERSION` is `1`. Unknown versions and out-of-contract fields must be
rejected, not silently ignored. The contract is not a cryptographic protocol
standard and does not claim production security by defining Python dataclasses
or `Protocol` interfaces.

## Request and trust boundary

`CanonicalReservationRequest` contains only the version, bounded request ID,
resource ID, and SHA-256 digest of the exact bounded evaluation input. IDs are
restricted to 1-128 ASCII identifier characters; the payload digest must be 64
lowercase hexadecimal characters. The canonical request bytes are ASCII JSON
with sorted keys, compact separators, no floating-point values, and a
versioned domain-separated SHA-256 request digest. A trusted upstream must call
`payload_digest_for_bounded_input()` on the same immutable bytes the evaluator
will consume, and bind that resulting request to that exact input. A
customer-supplied digest by itself proves nothing. Direct dataclass construction
is not an authentication or payload-integrity boundary.

There are deliberately no client fields for tenant, principal, authority ID,
credential status, policy version, quota, or ownership. The authority receives
the opaque credential separately; it must authenticate that evidence and
derive principal/tenant from current authoritative credential and membership
records. The credential is never included in an event, receipt, digest, or log.
Production adapters must bound credential input, redact it from telemetry, and
store only an approved verifier, never the raw credential.

`AuthorityCredentialRecord`, `ResourceOwnership`, and `MonthlyQuotaPolicy` are
server/authority-owned records. The authority must resolve the resource's
current owner and kind, require that owner to match the verified tenant, reject
revoked/disabled/expired credentials, and select the policy version itself.
Their public Python constructors do not authenticate their contents.

## Reservation operation and outcomes

`ReservationAuthority.reserve(request, credential)` is one logical atomic
authority operation. In one transaction it must authenticate the current
credential and tenant membership, check current revocation, resolve current
resource ownership, load the current policy version and UTC monthly allowance,
check idempotency, enforce quota, append the reservation event, advance the
authority sequence/head, and commit. External lookups outside that transaction
need a separately proven consistency/locking contract; a precomputed tenant or
authorization decision is not sufficient.

Idempotency is unique by stable authority identity, tenant, and digest of the
bounded request ID. It remains unique across signing-key rotation and authority
epoch changes. Exact request-content retry returns `REPLAY` and the existing
event reference, never a new reservation. Reusing the request ID with another
resource or payload returns `CONFLICT`. A new reservation consumes one unit in
the selected UTC `YYYY-MM` period. Quota exhaustion returns `QUOTA_EXCEEDED`.
Invalid/currently revoked identity or ownership returns `UNAUTHORIZED` without
an evaluation grant. `AUTHORITY_UNAVAILABLE` means the caller cannot conclude
whether commit occurred; it must not fall back to SQLite or in-memory quota.

The contract separates result status from commit knowledge:

| Result | Commit state | Caller behavior |
| --- | --- | --- |
| `RESERVED` | `COMMITTED` only | A future production service may proceed only after verifying the authority receipt and the complete atomicity contract. |
| `REPLAY` | `COMMITTED` | Do not evaluate again; replay is not a fresh grant. |
| `CONFLICT`, `QUOTA_EXCEEDED`, `UNAUTHORIZED` | `NOT_COMMITTED` | Deny; no local fallback. |
| `AUTHORITY_UNAVAILABLE` | `UNKNOWN` | Deny now; retry the same idempotency key or reconcile with authority. Never issue a new key just to retry uncertain commit. |

The interface type itself does not prove atomicity. A production adapter must
demonstrate that no `RESERVED` receipt escapes before durable commit. If commit
succeeds and acknowledgement is lost, retry must return `REPLAY`. This provides
at-most-one fresh reservation decision per key, not exactly-once evaluation or
response delivery.

## Authority identity and event evidence

`AuthorityIdentity` contains a stable authority ID, epoch, and trust-domain ID.
The caller pins the expected identity from protected configuration; it is not
accepted from the reservation request. Epoch changes must chain to the prior
head and must not reset tenant/request uniqueness, quotas, or event history.

Each committed reservation has one event ID and a strictly increasing
authority-wide sequence. `ReservationEvent.canonical_bytes()` defines the V1
ASCII JSON representation using sorted keys, compact separators, fixed
field names, integers only, and no unknown fields. Its hash is
`SHA-256("gvai-reservation-event-v1\\0" || canonical_event_bytes)`. The event
contains authority ID/epoch, sequence, event ID, previous event hash, tenant,
principal, resource, request-ID and request digests, period, policy version,
and units. Tenant/principal/resource/request values are represented by
SHA-256 digests; credentials and payload bodies are absent.

`AuthorityReceipt.canonical_envelope_bytes()` is the V1 deterministic signing
envelope: a domain separator plus canonical ASCII JSON containing receipt
purpose (`reservation_decision`), `RESERVED`/`REPLAY` status, evidence
version/class, authority ID/epoch and trust domain, event ID/sequence/event
hash/previous hash, tenant/principal digests, request ID/request/resource
digests, period, policy version, unit count, and signing-key ID. Changing
receipt status or evidence class changes the bytes to be authenticated; a replay
response is distinguishable from the original reservation event.

Before a verifier callback runs, the caller supplies an
`ExpectedReceiptContext` built only from trusted authorization and the pending
request: pinned authority ID/epoch, expected receipt status/purpose, tenant,
principal, request ID/request/resource digests, policy version, allowed pinned
signing-key IDs, and evidence version. Local mismatches and `TEST_ONLY` evidence
are rejected before callback invocation. Do not construct this context from
customer claims.

For production, the verifier must cryptographically authenticate the exact
canonical envelope bytes with a pinned authority trust root and approved
signing-key set, validate algorithm/key usage and rotation windows, and verify
the event hash chain. `AuthorityEvidenceVerifier` is only an interface; no
implementation or production key is supplied. An injected callback returning
literal `True` is a trust decision delegated to that callback, not proof that
the callback or its cryptography is trustworthy. `authenticated=True`,
signature-shaped bytes, matching hashes, and test evidence do not establish
cryptographic authenticity. Tests use a fixed-key HMAC fixture solely to show
that changes to the canonical envelope invalidate that test signature; this is
not a production signer or verifier.

Signing-key rotation must have an overlap/revocation process and preserve
verification of old event signatures. Authority identity/epoch rotation is a
separate operation and cannot reset uniqueness or quota. Keep authority
signing keys, API-credential verifier keys, and supervisor STOP keys in separate
trust and rotation domains.

## SQLite projection and recovery

SQLite is a rebuildable projection, never the authority. A future projection
schema must persist authority ID/epoch, last applied sequence, last event hash,
schema version, and reservation/accounting rows. Apply each verified event and
advance its cursor in the same SQLite transaction. Enforce unique event ID and
sequence and make replay of an already applied event idempotent. Verify every
signature, authority identity, sequence continuity, previous hash, and event
schema before applying.

On startup, compare the SQLite cursor to the independently authenticated
authority head. Behind means replay/rebuild before serving. Equal sequence with
a different hash, a cursor ahead, wrong authority/epoch, invalid signature, or
gap means quarantine and rebuild from trusted history. Missing/unavailable
authority evidence means deny; do not infer a cursor from reservation rows or
silently create an empty ledger. A stale snapshot with a cursor behind the
authority must be detected. Recovery must be fenced until a rebuilt projection
exactly matches the authenticated head.

Schema migrations must be versioned and tested by rebuilding the projection
from an authenticated event stream. A migration cannot manufacture authority
history for the current Phase 6H.1 schema: that schema has no event sequence or
projection hash. Existing SQLite contents cannot be promoted to authoritative
history without a separately approved reconciliation procedure.

## Crash and outage behavior

| Boundary | Required result |
| --- | --- |
| Before authority commit | No event or receipt. A same-key retry may attempt the atomic reservation. |
| After commit, before acknowledgement | Reservation is consumed. Same-key retry returns `REPLAY`, never a second `RESERVED`. |
| After acknowledgement, before SQLite projection update | Authority remains decisive. Retry is replay; rebuild/replay the projection before serving any projection-dependent operation. |
| After projection update, before evaluation response | Retry is replay and must not re-evaluate. Result recovery requires a separate result-cache contract. |
| During projection rebuild | Keep the projection fenced. Resume authenticated replay or discard/rebuild; no grant path while incomplete. |
| Authority unavailable | Deny fresh grant. For an in-flight call, commit is unknown; retry/reconcile the same key only. |

SQLite or a process-local cache must never resolve an unknown authority commit
by granting locally. Supervisor STOP does not query this authority and must
continue independently during any authority or projection outage.

## Interface guarantees versus adapter proof

The data classes enforce basic types, sizes, identifier syntax, digests,
contract version, and result-shape consistency. The test fake demonstrates the
state transitions under a process lock. It does **not** prove durable storage,
transaction isolation, cross-process uniqueness, authenticated identity,
cryptographic signing, rollback resistance, credential custody, or disaster
recovery. No fake object is registered in `CommercialEvaluationService`, and
the existing SQLite-backed `CommercialUsage` path remains fail-closed.

For a first paid single-region deployment, the simplest plausible authority is
a separately operated reservation service backed by one transactional
PostgreSQL database that owns credential status/membership, resource ownership,
policy, idempotency, quota, and event append in the same transaction. Protect
WAL and backups in a separately controlled immutable recovery domain and fence
restores until authority history is reconciled. PostgreSQL transactions alone
do not prevent rollback to an older restored backup. A remote append-only
service is an alternative with greater isolation but adds service, network,
availability, and operational cost.

## Offline fake and exclusions

`tests/test_commercial_reservation_authority.py` contains the only fake. It
uses deterministic clocks, a lock, in-memory maps, and `TEST_ONLY` evidence. It
is not an authority provider and cannot be registered as one in production.
Its conformance suite validates request validation, new/replay/conflict,
quota/period changes, concurrent idempotency and exhaustion, tenant isolation,
revocation, reassignment, policy-tenant mismatch, unsupported resource kinds,
unavailable/unknown commit, lost acknowledgement, event/envelope binding,
payload digest derivation from trusted bounded bytes, and supervisor STOP
independence. Passing these tests is not production approval.
