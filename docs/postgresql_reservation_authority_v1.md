# Commercial PostgreSQL reservation accounting V1

## Scope

Migrations 001 and 002 and the Python reservation adapter are shared
transactional accounting dependencies of the advisory backend. They are
preserved byte-for-byte from the verified commercial source commit. Their
historical names do not grant execution authority. No signer, authority-head
provider, STOP controller, checkpoint store or recovery gate is imported.
The adapter emits only unauthenticated accounting receipts and refuses
authenticated-head reads.

The [advisory wrapper](commercial_advisory_backend_v1.md) adds migration 003.
The application runtime receives access only to its three advisory entry
functions, never the raw reservation routine or direct table writes.

## Migration and role boundary

Apply 001, 002 and 003 in order as the same dedicated non-superuser migration owner.
Do not run it as `postgres` or a superuser. Use a standalone SQL client with
`-v ON_ERROR_STOP=1`; each migration has its own explicit transaction.
Check migration failure and installed state before retrying. Migration 002
requires the database privileges needed for the trusted `pgcrypto` extension.

Keep the owner/operator credentials separate from the restricted runtime role.
The runtime must not inherit owner membership, create schemas, write tables,
alter triggers, truncate history or execute arbitrary definer functions.
Startup verifies these role constraints. See
[private configuration and onboarding](private_staging_v1.md).

## Preserved accounting invariants

- Current credentials, tenant membership, ownership, capability and expiry
  determine authorization; request fields cannot select tenant or allowance.
- Canonical request and payload digests bind idempotency to the exact input.
  Exact retries replay without reevaluation; changed payload/project conflicts.
- The authority head and tenant-period bucket serialize reservations. Event
  insertion, quota consumption, idempotency and head advancement commit together.
- Deferred security-definer checks with pinned search paths validate protected
  rows at commit even for the restricted runtime caller.
- Revocation and accounting history retain their one-way mutation constraints.
- Migration 003 rechecks authorization after reservation lock waits. Expired
  credentials/pilots abort the transaction instead of consuming a unit.
- Lost commit acknowledgement is UNKNOWN/accounting unavailable, not permission
  to evaluate or to retry with a fresh request ID.

Owners, privileged administrators, trigger changes and stale restores remain
outside these protections. Database history is not independent rollback proof.

## Validation boundary

Schema/routine tests inspect SQL text. Adapter tests use fake connections.
Neither establishes actual PostgreSQL behavior. The separately opt-in
[integration suite](../tests/test_postgresql_advisory_integration.py) requires a
fresh disposable loopback database, psycopg and separate non-superuser roles.
No historical PostgreSQL result is a PASS for this extraction.
