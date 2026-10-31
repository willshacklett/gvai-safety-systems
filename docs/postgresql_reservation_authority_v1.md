# PostgreSQL Reservation Authority Schema V1

## Status and scope

`migrations/postgresql/001_reservation_authority_v1.sql` is an isolated,
versioned PostgreSQL schema foundation for the V1 reservation contract. It has
not been executed against PostgreSQL. It creates no authority identity,
credentials, tenants, resources, policies, or reservations. An unprovisioned
or unavailable authority must deny; this migration is not wired to
`CommercialUsage`, `CommercialEvaluationService`, SQLite, or an API route.

`tests/test_postgresql_authority_schema.py` inspects the migration text and
asserts expected DDL and constraints. These are static schema-contract tests.
They do not parse SQL with PostgreSQL, apply the migration, or prove that
PostgreSQL enforces any behavior. No PostgreSQL server, driver, migration
runner, network, or database is part of this phase.

Run the migration as a standalone PostgreSQL script as a dedicated
non-superuser migration owner, with a client configured to stop on the first
error (for `psql`, use `-v ON_ERROR_STOP=1`). Do not run it as `postgres` or a
superuser: the migration role owns its SECURITY DEFINER trigger function and
must remain a controlled, separate owner. The runtime role must be distinct
and must not inherit owner/migration privileges. The script contains an
explicit `BEGIN`/`COMMIT`; do not run it in a transaction wrapper that may
commit the surrounding transaction. On any statement error, PostgreSQL marks
the transaction failed and the schema, objects, and version row are rolled
back together. Verify the migration process reports failure and check
`schema_version` before any later migration attempt.

## Schema and integrity constraints

The migration creates the `gvai_authority` schema and singleton version
metadata for version 1. Its objects cover:

- Stable authority ID, epoch, trust domain, sequence head, and last event hash.
- Tenant and tenant-membership status.
- Customer credential key IDs, keyed 32-byte verifier, capabilities, lifecycle
  status, and expiry/revocation timestamps.
- Tenant membership and versioned resource-ownership rows restricted to the V1
  `evaluation` resource kind. Reassignment creates a new ownership version;
  historical reservations continue to reference the former owner version.
- Versioned quota policies and a per-tenant current-policy pointer.
- One usage bucket per tenant and UTC month, with a policy/allowance snapshot.
- Reservation events with a strictly unique authority sequence, canonical V1
  fields, and digests, not request bodies or raw tenant, principal, resource, or
  request identifiers.
- Idempotency rows uniquely keyed by authority, tenant, and request-ID digest,
  constrained by a composite foreign key to the matching reservation event.

Composite foreign keys bind credentials and event principals to memberships,
events to tenant-owned resource versions and policies, and idempotency keys to
the matching event. Event rows use internal surrogate references for these
foreign keys; those references are storage metadata, not canonical event
fields. Status, digest, one-unit, period, and nonnegative quota
constraints reject invalid stored shapes. `credential_verifier` stores only a
keyed verifier; it is not the supplied API credential. No table stores raw
credentials, evaluation input, or evaluation results. The schema has no
supervisor STOP tables, keys, or references.

The migration installs a head-update trigger that requires an unchanged
authority identity/epoch and exactly one sequence increment matching a newly
inserted event whose previous hash equals the old head. The event table has
update/delete rejection triggers and PUBLIC update/delete/truncate revocations.
Idempotency rows also reject updates/deletes and have PUBLIC update/delete/
truncate revoked. Credential rows reject deletion and identity/verifier
rewrites, as well as revocation rollback.
Runtime roles must not own these objects, have schema DDL rights, receive
truncate or direct authority-head update rights, inherit such rights through
another role, or use a superuser-equivalent role. A migration/owner role should
be kept separate from the runtime role. The schema does not install role
grants because deployment role names and provisioning are not defined here.
Credential, idempotency, ownership-history, and usage-bucket rows also reject
their protected delete/update transitions or revoke corresponding PUBLIC
privileges. The runtime role must not receive truncate rights or ownership of
these tables/functions. The quota trigger is `SECURITY DEFINER` with a pinned
search path; its owner must remain the trusted schema/migration owner.
The deferred commit-check trigger functions are also `SECURITY DEFINER` with
a pinned search path, so they can validate protected rows at commit when an
approved, restricted runtime routine is the transaction caller. Their owner
must remain the trusted schema/migration owner; this does not authorize direct
runtime table access or replace the future reservation routine's checks.

The head trigger checks row continuity, not that the event hash was correctly
computed from canonical V1 bytes, cryptographically signed, or appended by a
transaction that also performed the approved credential, idempotency, and
quota checks. Those checks must be implemented and tested in the future
reservation transaction; no adapter currently provides them. Owners,
superusers, privileged administrators, trigger-disabling operations, and stale
backup restores remain outside these database-level protections.

Revocation triggers prevent an already-revoked row from becoming active or
changing its revocation timestamp through ordinary updates. Privileged owners
can alter schema/triggers or restore an older credential backup; these controls
do not make revocation rollback-resistant against administrators or restores.

The event-insert trigger locks and checks the authority head first, then locks
the matching tenant-period bucket and increments its consumed count by the
event's one unit. Bucket updates can only advance by one without changing the
tenant, period, policy, or allowance; delete is rejected. This keeps event
insertion and quota consumption atomic and fixes their lock order. The future
reservation transaction must not separately increment the bucket. It must
insert the event before advancing the head; the head trigger then verifies the
new head matches that event. Idempotency lookup and current authorization
remain responsibilities of that approved transaction.

Initially deferred constraint triggers verify at commit that every inserted
event has exactly one field-matching idempotency row, the authority head equals
that event's identity/epoch/sequence/hash, and its quota bucket consumed count
equals the committed event count for that tenant/month. A corresponding
deferred bucket trigger checks bucket/event-count consistency whenever a bucket
is inserted or changed. If any condition fails, commit fails and PostgreSQL
rolls back the event, quota increment, idempotency row, and head update
together. This design deliberately permits only one new reservation event per
authority transaction: each event's deferred check requires the final head to
equal that event. Idempotent replay performs no new event and does not invoke
this fresh-reservation check.

The migration revokes all schema/table/sequence/function privileges from
`PUBLIC` and grants nothing to a runtime role. The runtime role must be a
separate non-owner, non-superuser role with no inherited membership in the
schema-owner or migration role and no schema DDL, trigger, truncate, direct
event/head/bucket mutation, or arbitrary `SECURITY DEFINER` function rights.
No runtime role is created and no reservation routine is granted by this
experimental migration. Until a narrowly scoped reservation routine and its
least-privilege `EXECUTE` grant exist, direct runtime reservation writes are
intentionally unavailable. Table/function owners and superusers can still
alter triggers, bypass protections, or rewrite state.

Resource ownership history is append-only apart from an active row's one-way
transition to `reassigned` or `disabled`. An insert trigger requires ownership
versions to start at one and increase by one after the previous row is inactive.
This validates a single transaction path but still requires PostgreSQL
concurrency testing before relying on the trigger under concurrent ownership
provisioning.

## Required reservation transaction

An eventual adapter must use one transaction on the authoritative PostgreSQL
primary, with current reads and no cache or external authorization result.
`READ COMMITTED` with explicit row locks is the proposed initial design; the
adapter must validate its exact SQL and driver behavior in PostgreSQL before
relying on it.

Use a documented, consistent lock order:

1. Lock and verify the current credential, tenant, membership, resource, and
   current policy rows. A revocation, disablement, membership change, ownership
   reassignment, or policy update must update/lock these same rows so it
   serializes with the reservation. Verify capability, expiry, active status,
   resource kind, and tenant match in this transaction.
2. Lock the singleton `authority_state` row `FOR UPDATE`. This deliberately
   serializes the first implementation's reservation decisions and sequence /
   hash-head updates. The unique event sequence is a second integrity barrier.
3. Check idempotency by stable authority ID, verified tenant, and request-ID
   digest. Exact request digest returns the existing event as `REPLAY`; a
   different request digest returns `CONFLICT`. Preserve this key across epoch
   and signing-key rotation. Replay must not consume quota or append another
   event, and it is not permission to evaluate again.
4. Create or lock the tenant/month usage bucket and check its allowance. Use
   database-derived UTC month boundaries, not a caller period. The bucket
   snapshots its policy version and allowance on creation; policy change and
   mid-month effect require an explicit approved policy. The authority must
   deny when allowance is exhausted.
5. In this same transaction, allocate the next authority sequence, append
   exactly one event (whose trigger validates the prior head and consumes one
   quota unit), add its unique idempotency row, and update the sequence/hash
   head. All writes either commit together or roll back together.
6. Return `RESERVED` only after durable commit and after producing the receipt
   required by the V1 contract. If a commit acknowledgement or post-commit
   receipt signing result is uncertain, return unavailable/unknown and retry
   or reconcile with the same idempotency key only. A committed retry is
   `REPLAY`, never a second reservation. Do not fall back to SQLite or
   process-local quota.

Authorization and ownership checks precede replay, so a now-revoked credential
or reassigned resource does not reveal a prior event. Lock ordering, deadlock
handling, connection failures, sequence allocation, and receipt signing remain
unverified until a real adapter is tested against PostgreSQL. The transaction
does not make the later evaluation and result delivery exactly once.

## Migration, backup, and recovery limits

This is a new schema, not a promotion of existing in-memory or SQLite rows.
The experimental SQLite ledger has no authenticated event sequence/hash
history, so its contents cannot initialize authoritative history. The
versioned migration is one-way initial DDL; future migrations need distinct
versioned files and explicit compatibility/recovery review. A future reviewed
migration runner must apply each file atomically and verify the stored schema
version; no runner is included here. The schema must
remain fenced until an approved authority identity, credentials, tenant
membership, ownership, and quota policy are provisioned.

PostgreSQL transactions, constraints, WAL, and a valid backup do **not** by
themselves detect restoration to an older valid backup. Protect backups and WAL
in a separately controlled immutable recovery domain, maintain independently
authenticated head evidence, and fence restored service until the authority
history is reconciled. A backup restore must not silently reset idempotency,
quota, revocations, event history, or sequence.

## Validation boundary and STOP

Offline static checks verify names and DDL fragments, key/foreign-key
relationships, unique idempotency and event sequence constraints, status/quota
checks, transaction wrapper, append-only and monotonicity triggers, migration
version, and absence of forbidden plaintext/body/result columns or STOP
dependencies. They cannot establish SQL syntax validity, trigger execution,
transaction isolation, locking, race behavior, durability, backup safety, or
anti-rollback.

No supervisor STOP code, storage, key, API, or configuration is changed or
referenced by this schema. STOP must remain independently operable during
authority or database outages.
