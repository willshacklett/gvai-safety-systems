# Offline PostgreSQL permits and lifecycle (Phase 2F)

The [verification module](../gvai/postgresql_billing_permits.py) contains no
signer, executor, persistence, bootstrap, connection, filesystem mutation or
environment attestation. It does not replace or enable the
[Phase 2D execution refusal](../gvai/postgresql_billing_acceptance.py).
Existing migration and harness inputs remain unchanged.

## Wire contract

Version 1 uses canonical ASCII JSON: sorted object keys, compact separators,
no alternate whitespace, duplicate/unknown fields, noncanonical numbers or
embedded keys. The bounded envelope has exactly `permit` and `signature`.
Signature is 64-byte Ed25519 represented as lowercase hex. The signed message is
`gvai-disposable-postgresql-permit-v1` followed by a NUL and the canonical
`permit` object bytes, not the signature envelope.

Required signed fields: version, run ID, bootstrap challenge nonce, unique
operation ID, issuer, audience, key ID, issued/expiry Unix integer seconds,
operation, predecessor state, generation, identity digest and a nonempty named
SHA-256 artifact map. Validity is at most 300 seconds; issued time is inclusive
and expiry exclusive. There is no implicit clock, grace period or default key.
Each approval must cover the complete expected artifact set: bootstrap/runner,
PostgreSQL and extension build, isolation/configuration profile, and ordered
migration-bundle manifest. The opaque identity digest binds a canonical,
independently attested run identity, not merely a database name.

The issuer/key-ID public-key mapping is explicitly supplied from independent
trust custody. Keys in a permit are rejected as unknown fields. Verification
copies and pins trust configuration and requires an independently supplied
`ExpectedPermit`; do not derive expected fields from the candidate itself.
Key revocation/rotation is external: construct a new verifier from the currently
authorized key set, never continue using a revoked snapshot.

This module requires the repository's existing `cryptography` Ed25519 backend.
Missing dependencies fail import, never substitute a fake signature algorithm.
No new package requirement or installation is introduced.

## Consumption and lifecycle

`authorize_intent` verifies signature, time and exact context, compares the
complete supplied lifecycle record, then invokes `PermitConsumption.consume_once`.
The interface must atomically consume `(issuer, operation_id)`, compare current
record including generation/identity, and persist a pending operation intent
before returning literal True. Only a clean CAS/replay rejection returns False.
Outage and ambiguous commit raise `ConsumptionUnavailable`; no automatic retries.
Do not pass raw storage/driver diagnostics to this API or evidence reporters.

There is deliberately NO durable implementation here. In-memory unit-test stores
do not establish restart, concurrency, backup or rollback replay resistance.
Independent authenticated storage must also atomically finalize pending intents,
preserve generation monotonicity and recover interrupted intents as UNKNOWN.
Future storage requires bounded deadlines and authorization-expiry checks at the
actual operation boundary, not just at initial offline verification.

Successful forward transitions:

`APPROVED -> CREATED -> INITIALIZED -> STARTED -> ATTESTED -> MIGRATED -> TESTED`

Each edge requires its exact operation. Created through tested, FAILED and UNKNOWN
may transition to STOPPED with a new stop permit. STOPPED and CLEANUP_INCOMPLETE
may transition to CLEANED with a cleanup permit. APPROVED and CLEANED cannot
stop; CLEANED is terminal. There is no backward transition, restart shortcut or
automatic recovery. Cleanup-incomplete retries require fresh approval and proof
that only previously owned remaining resources are targeted.

`finish_intent` produces a pure next-record candidate: success selects the planned
target, failure selects FAILED, ambiguous outcome selects UNKNOWN, and partial
cleanup selects CLEANUP_INCOMPLETE only for cleanup. Generation increases by one.
Lifecycle records retain the range `0 <= generation < 2**63 - 1`.
At generation `2**63 - 2`, all completion outcomes explicitly deny with
`generation_exhausted` rather than returning an invalid record. No generation
wrap, reset or recovery shortcut is provided; the predecessor remains unchanged.
The highest completable predecessor is `2**63 - 3`. Permit generation validation
is unchanged and does not by itself establish that a lifecycle record can advance.
Calling it, fabricating its dataclasses, or receiving a candidate proves neither
operation success nor approval nor durable completion. No candidate can authorize
execution; the independent supervisor must verify persisted intent, observed
outcome, current attestation and permit scope before durably finalizing it.

Initial APPROVED state must originate from external approval, not runner
self-provisioning. Pre-initialization identity covers the run compartment and
bootstrap provenance. Binding a newly attested cluster/system identifier to later
records requires separately approved external CAS/rebinding; this foundation
does not provide identity-update or restart APIs.

## Required independent boundaries

The runner must have neither approval private keys nor write access to trusted
public-key configuration, permit-consumption history or lifecycle truth.
The host supervisor must enforce dedicated namespace/process/listener identity,
fresh data provenance, exact immutable executed migration bytes, and handle-based
filesystem ownership. Python types, hashes and caller-supplied records alone
cannot enforce these guarantees against a compromised runner or host.

STOP and independent execution authority are unaffected. These permits concern
only disposable test-resource lifecycle, never supervisor STOP or production.
No PostgreSQL role grants are added; receiver/worker/paid/pilot/owner boundaries
remain in the existing plan.

## Test evidence and remaining gates

The [offline tests](../tests/test_postgresql_billing_permits.py) use injected
integer time, exhaustive lifecycle pairs, a deliberately non-durable store, and
mocked public verification calls for successful permit-context/consumption tests.
Mocks are explicitly not cryptographic evidence. Actual backend verification
uses the published RFC 8032 section 7.1 TEST 1 public key and signature of the
empty message; that signature correctly fails against a canonical permit.
No private key or signing operation is present.

Full valid canonical-permit signature success remains BLOCKED until an
independently approved, externally signed non-sensitive fixture is supplied.
Do not manufacture that fixture in the test runner or call mocked tests proof of
end-to-end authorization. Durable replay prevention, independent approval custody,
live environment attestation and all database acceptance tests remain blocked.
This is not authorization to create, connect, start, migrate, test or clean up
any PostgreSQL environment.
