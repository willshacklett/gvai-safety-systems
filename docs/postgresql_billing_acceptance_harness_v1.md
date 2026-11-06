# Billing acceptance harness foundation (Phase 2D)

## Status

The [foundation](../gvai/postgresql_billing_acceptance.py) is an offline planner,
not a database runner. It imports no PostgreSQL driver and provides no database,
process, network, migration, credential-loading, or deletion implementation.
Every execution request refuses even when supplied an operation-scoped
authorization. Authorization objects are declarations, not authenticated approval.
They must not become an execution capability without separate review.

The [offline tests](../tests/test_postgresql_billing_acceptance.py) exercise
refusals, role plans, manifest completeness, identity comparisons and reporting.
Passing them does not pass any PostgreSQL acceptance category.
The [schema contract](./postgresql_billing_schema_contract_v1.md) and migrations
001-004 remain unchanged.

## Planning and isolation

`prepare_plan` requires explicit opt-in, a nonzero lowercase 32-hex run identity,
synthetic-only declaration, literal `127.0.0.1`, and a dedicated unprivileged port
other than 5432. Generate a new random run identity for every future run; the
foundation does not generate resources or establish uniqueness by itself.
It refuses an existing run directory, including a dangling symlink.
It reads migration 004 and refuses unreadable, symlinked or hash-mismatched source.

Database and paths are derived, never supplied as a DSN:

- Database: `gvai_billing_test_<run>`
- Run directory: `/tmp/gvai-billing-acceptance-<run>`
- Exact data/socket children: `data` and `socket`
- Separate run-scoped owner, receiver, worker, paid and pilot role names.

The default preflight inspects the actual environment and rejects all `PG*`,
DSN-containing names, database URL/service defaults and the old integration
opt-in variable, even when empty. An explicit environment mapping supports offline
unit tests; it is not permission to hide inherited settings during future execution.
No connection string, password, service file or callback is accepted.

`compare_cluster_identity` compares supplied expected/observed system identifier,
loopback listener, port, database, exact paths and synthetic-only declaration.
It does not independently observe PostgreSQL, verify synthetic contents, resolve
running-directory symlinks, or authenticate the source of either identity.
Matching objects are therefore NOT authorization to connect.

Future execution requires independently reviewed bootstrap and live attestation:
dedicated newly initialized cluster; exclusive directory creation and ownership;
canonical paths without symlinks; process identity/start time; listener/socket
inspection; recorded `pg_control` system identifier; fresh database/catalog state;
explicit connection parameters without libpq defaults; rejection of identity
changes before every operation. This must occur without probing an unapproved
server. Startup/creation, first connection, migrations, tests and teardown each
require explicit run-bound authorization. Prevent TOCTOU and PID-reuse attacks;
never trust a database-name prefix alone.

## Manifest and evidence

`MANIFEST` covers Phase 2C A01-A16: apply/atomicity/preservation/catalogs,
default deny/payment/cancellation/event identity/reconciliation, workers/fencing,
rollback/isolation/accounting/pilots/authority/recovery. Each category specifies
required evidence and remains blocked. Additional mandatory blockers are:

- A14-UTC: actual UTC month rollover; no approved safe real-time method.
- A16-RESTORE: independent restore fencing is not implemented.
- A06-STRIPE: external signature/context/authoritative retrieval is out of scope.

These are not unconditional pytest skips or passing placeholder database tests.
There is deliberately no database test collector or runnable executor yet.
`evidence_json` emits only fixed allowlisted foundation statuses and the pinned
migration hash. It cannot accept arbitrary SQL, exception messages, DSNs, role
configuration, payloads or credentials. All cases report `blocked`; execution is
false. The planner checks the source hash, but this is not database evidence.
Future execution must recheck actual files immediately before applying them.

Future result reporting requires test IDs, observed SQLSTATEs, commit outcomes,
sanitized catalog/ACL snapshots, before/after row digests and barrier traces.
Do not serialize raw driver errors or connection objects. A denial must be the
intended failure, not an unrelated fixture/permission error.

## Future role and transaction verification

`ROLE_ENTRYPOINTS` records exact typed signatures, not SQL grants. The owner has
no application entrypoint grant list; it remains a separate controlled migration
identity. Bootstrap administration is separate again. All application roles must
be non-owner/non-superuser with no role/database creation, replication, bypass-RLS,
owner/application-role membership, grant options or schema creation rights.

First prove the ungranted installation denies access. Only then apply separately
approved test grants: schema USAGE plus exact per-role function EXECUTE.
`CATALOG_CHECKS` requires actual constraints, enabled/deferred triggers, function
owners/security/search paths, default/PUBLIC/inherited ACLs, effective privilege
functions, authenticated negative sessions and shadowing attacks. No direct table
or sequence grants; no raw reservation or pilot fallback for the paid role.

`TRANSACTION_CHECKS` requires rollback snapshots spanning inbox, reconciliations,
invoices, intervals, projections, reservations, idempotency, attempts, quotas and
authority head. Concurrency needs separate connections, deterministic barriers,
bounded timeouts and 20 consecutive repetitions per schedule. Include lease
expiry during waits, stale retry versus newer lease, invoice identity races,
deferred failure at commit and unknown commit outcomes.

Acceptance requires zero failures/errors/unexpected skips/xfails, all mandatory
cases executed, correct restricted-role positive paths, safe denials without
partial accounting, unchanged 001-003/Phase 1/pilot/STOP behavior and independently
verified teardown. Blocked requirements prevent complete acceptance.

## Teardown and recovery

`teardown_plan` requires scoped authorization and matching identity and returns
only the exact data/socket candidates. It performs no cleanup. These candidates
are NOT evidence of ownership and must never be handed directly to recursive
deletion. A future executor must check a bootstrap ownership record, canonical
paths, exclusive run identity and stopped cluster/process identity immediately
before cleanup. Stop only the recorded process, close only recorded sessions,
drop only the recorded disposable database/roles, and verify listener closure.
Never use wildcards, name-based process killing or broad/root deletion.

Preserve sanitized evidence first. Disable paid grants/routing before rollback;
retain durable payment/accounting history during recovery exercises. Destroying
the entire synthetic disposable cluster happens only after those assertions.
Stale restores require an external fence and fresh reconciliation, not merely a
restored eligible row. No Lab-01, production, shared database, customer data,
Stripe API, HTTP listener or deployment is part of this harness.

## Next gate

Review this foundation and resolve the bootstrap/independent identity-attestation
design before authorizing an executor implementation. Database creation,
connection, startup and migration execution remain separately unauthorized.
