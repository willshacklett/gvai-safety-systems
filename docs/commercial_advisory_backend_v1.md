# Commercial advisory pilot backend V1

For the runnable loopback-only assembly, separate operator commands, connection
bounds and HTTP usage/diagnostics, see [private staging V1](private_staging_v1.md).

## Scope and trust boundary

This is a development-validated PostgreSQL foundation for an invite-only,
advisory evaluation beta, not a deployed public API or production launch approval.
It reuses the existing customer-key format, canonical reservation/event contracts,
PostgreSQL reservation routine, commercial service, HTTP adapter and evaluator.
Responses remain `advisory_only=true`, `enforcement_applied=false`.

The new [PostgreSQL adapters](../gvai/postgresql_advisory.py) are explicitly for
direct trusted-database advisory accounting. Committed, unauthenticated records
establish accounting against that database only. They are not cryptographic
execution grants. No existing authenticated-receipt gate is weakened, no
`CommercialUsage` SQLite grant is enabled, and no worker, signer, checkpoint
store, recovery privilege, service deployment or supervisor STOP is activated.
The original reservation adapter still refuses authenticated-head reads.

## Minimum customer backend

- `PostgreSQLCustomerStore.provision_pilot` is a trusted operator operation,
  not a request endpoint. It atomically creates a new tenant, membership,
  evaluation project, monthly quota policy and time-bounded lifetime pilot cap.
  Duplicate provisioning fails rather than resetting usage. Existing identity
  and tenant validation are reused.
- `CustomerApiKeys` uses the durable store for insertion, lookup and revocation.
  Keys remain random, their keyed verifiers are stored instead of raw secrets,
  delivery is one-time, and expiry/current revocation are checked. Disabled
  tenants and memberships invalidate verification. Provisioning/key-management
  credentials must never be given to the customer-facing runtime.
- `PostgreSQLAdvisoryUsage` supplies the existing service's accounting protocol.
  The service canonicalizes its validated request as sorted, compact ASCII JSON
  and passes immutable bytes to `reserve_evaluation`. The existing V1 payload
  and request digests bind the request ID, project and exact evaluated snapshot.
- Migration [003](../migrations/postgresql/003_advisory_pilots_v1.sql) adds a private
  current-customer authentication helper, fixed pilot cap and completion records.
  Its restricted reservation wrapper calls the existing `reserve_v1` routine.
  Credential, membership, tenant, ownership and entitlement checks precede use.
  Pilot consumption, event/idempotency/head, monthly quota and attempt insertion
  commit in one transaction. The existing monthly allowance remains an
  additional ceiling; the pilot's lifetime cap does not reset each month.
- Explicit completion records `completed` or `failed` without refunds. Summaries
  authenticate `usage:read` against the owned evaluation project and return
  lifetime pilot counts, not a fabricated monthly summary.

## Accounting and retry policy

Every committed new attempt consumes one unit, including evaluator failures,
lost responses, abandoned attempts and failed completion writes. A failed
reservation transaction consumes none. Exact retries return `replay` without
another charge or evaluation; changed payload/project returns `conflict`
(HTTP 409). No result cache or exactly-once result delivery is supplied.
Expired, future, inactive or missing pilots cannot begin evaluation.

The adapter evaluates only after acknowledged commit. If commit acknowledgement
is lost, it returns unavailable/unknown even if PostgreSQL committed. The
service withholds evaluation. Retry with the same ID either sees the original
record as replay or creates a fresh attempt if the original transaction did
not commit. Never substitute a new request ID to hide ambiguous accounting.
Completion ambiguity also withholds the response; the unit stays charged.
Revocation after reservation does not cancel an already running advisory
calculation, but completion reauthentication can withhold its result.

### Authorization expiry during lock waits

The release audit confirmed a medium-severity expiry race in the original
migration 003 (pre-fix lines 110-139). Hold `authority_state` with `FOR UPDATE`,
begin a request while its credential/pilot is valid, wait past expiry and release
the lock. The old code charged and invoked the evaluator after both kinds of
expiry. Pilot expiry even returned an evaluated response; credential expiry
withheld completion but still consumed a unit and ran the calculation.

The wrapper now reauthenticates the current credential/identity after
`reserve_v1` returns, when its policy, authority and bucket lock waits have
finished. It checks credential and locked pilot expiry against a fresh
`clock_timestamp()`, never transaction-start time. Elapsed authorization raises
a SQL authorization exception, aborting the transaction: reservation events,
idempotency, monthly quota, pilot consumption and head advancement roll back.
The existing adapter reports accounting unavailable (HTTP 503) and the service
never invokes the evaluator; there is no success-shaped fallback.

Executable regression in the authorized disposable test environment:

```sh
python -m pytest -q -p no:cacheprovider tests/test_postgresql_advisory_integration.py \
  -k 'expiry_during_authority_lock or concurrent_revocation_winning or pilot_expiry_preserves or revocation_after_committed'
```

Both expiry cases failed against the original SQL and pass after repair. Tests
synchronize on live `pg_blocking_pids` and database-clock expiry, not a simulated
clock or acknowledgement. Revocation winning the credential lock denies new
usage; revocation after a committed attempt does not refund it and withholds
completion. Pilot expiry does not undo a previously valid committed attempt:
completion remains permitted under a currently valid key, while new requests
and replay through the evaluation endpoint deny. Completed/failed attempts are
never re-evaluated.

Authorization is checked at the final post-lock database validation point,
not issued as a lease over arbitrary future work. Expiry or revocation after
that point does not retroactively cancel committed advisory attempts, guarantee
process termination, or authorize controlled execution.

## Database roles and migration

Apply migrations 001, 002 and 003 in order as the same dedicated non-superuser
authority owner in an explicitly provisioned database. The owner requires the
database privilege needed to create the trusted `pgcrypto` extension. No migration
runner, production database or runtime role is automatically created.

Runtime must be a separate non-superuser, non-owner role, with no membership in
the owner role, no schema creation, direct table/sequence access, or raw
`reserve_v1` execution. Grant only schema `USAGE` and `EXECUTE` on:

```text
gvai_authority.reserve_advisory_v1(text,bytea,text,bigint,text,text,text,text)
gvai_authority.complete_advisory_v1(text,bytea,text,text,boolean)
gvai_authority.advisory_usage_v1(text,bytea,text)
```

All new tables/functions revoke PUBLIC access. Public entry routines use
`SECURITY DEFINER` under the non-superuser owner and a pinned `search_path`.
The authentication helper is private and is not granted to runtime.
Inject connection factories with bounded connect/statement/lock timeouts.
Supply a separately controlled API-key verifier secret; never use STOP keys.

Provision the authority identity explicitly before use. Pilot provisioning
cannot create/reset authority history or infer trust from old SQLite rows.
Owner/admin custody, backup validation, migration review and restored-service
fencing remain operational responsibilities, not production rollback proofs.

## Repeatable disposable PostgreSQL validation

The integration suite is opt-in and refuses non-loopback connections, database
names outside `gvai_advisory_test_*`, superuser/mutable-role credentials and
owner/runtime role overlap. It requires a fresh test database, applies all three
migrations as its non-superuser owner, and grants only the above runtime entry
points. Default offline runs explicitly skip these tests; a fake is not evidence
of successful PostgreSQL execution.

Use an authorized official `postgres:16` container with a random temporary
administrator password only for bootstrapping the test database and roles.
Publish its port only on `127.0.0.1` and mount the database directory as tmpfs,
not a persistent Docker volume. Use random separate owner/runtime credentials.
Neither test DSN should be printed, logged, committed or reused in production.

Install the [integration requirements](../requirements-postgresql-test.txt) in
an authorized temporary virtual environment, then supply:

```sh
export GVAI_RUN_POSTGRES_INTEGRATION=1
# Supply secret DSNs securely, not as committed files:
# GVAI_TEST_POSTGRES_OWNER_DSN
# GVAI_TEST_POSTGRES_RUNTIME_DSN
python -m pytest -q -p no:cacheprovider tests/test_postgresql_advisory_integration.py
```

The real suite covers persisted state across application reconstruction,
revocation/expiry, disabled identities, tenant isolation, concurrent final-unit
and duplicate-request races, changed payload/project conflicts, time-bounded
pilot access, zero allowance, runtime privilege denials, atomic provisioning
rollback, immutable revocation and idempotent completion. A local HTTP integration
proves advisory flags and rejects customer entitlement/identity claims.

Failure injection is labeled separately: commit-acknowledgement loss is simulated
around actual PostgreSQL commits/rollbacks; a test trigger rejects attempt insertion
to prove real transactional rollback; evaluator failure is injected in Python.
These do not claim network-partition, power-loss or production crash certification.

Validated results for this foundation:

- Official PostgreSQL 16.15, disposable loopback container, tmpfs data and
  separate non-superuser owner/runtime roles: **32 integration tests passed**.
  These include separate-application-process persistence, usage-only key denial
  and actual runtime privilege denials. Injected acknowledgement failures are
  explicitly named in the tests, not represented as observed network failures.
- Focused offline commercial and existing PostgreSQL regressions:
  **372 passed, 131 subtests passed**.
- Complete offline Python 3.12 suite: **688 passed, 362 subtests passed**;
  **32 integration tests explicitly skipped** without test-database opt-in.
  They passed separately against the real database, not through mocks.
- New/changed Python sources parse with Python 3.9 syntax; integration execution
  used Python 3.14. This is not a Python 3.9 runtime-validation claim.
  Newlines and changed-line whitespace were checked.

Remove the disposable container (including tmpfs data), temporary credentials
and temporary Python environment after validation. Do not delete other users'
containers, images, environments or data.

## Remaining hosted-staging blockers

The HTTP server still binds only to loopback. There is no public TLS ingress,
operator/customer login, secure onboarding transport, usage HTTP route, production
rate limiter, recurring billing, result retrieval, approved migration/deployment
runner, monitored backups or operational recovery controller.
Global authority-head locking serializes reservations; capacity and retention
remain unvalidated. Metadata retention and customer support policies are needed.

Signatures and production-independent rollback protection remain disabled.
Database backups alone cannot detect co-restored usage/revocation history.
Do not claim agent control, enforced ALLOW/SLOW/HALT or live STOP based on this
advisory service.

Next launch-focused task: a reviewed private-staging application assembly with
bounded database connections, operator-only invite provisioning, redacted
readiness/diagnostics and tenant-scoped usage access. Keep deployment and customer
activation behind separate approval.

STOP for founder review before any commit, push, PR, deployment or billing,
DNS, hosting, production-data or supervisor-control change.
