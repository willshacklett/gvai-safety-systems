# Isolated commercial advisory baseline V1

## Provenance and boundaries

Base: verified remote main `23299020ea200e268a1d91aa591c49b8a6557ecb`.
Commercial source: `3df7d3f49e928384487632f292e7c0e853908b56`.
Only explicit committed paths were transferred; no source-worktree changes
or unrelated commits were imported. Main's existing website and research code
remain inherited and unchanged, not newly promoted commercial functionality.

The product returns advisory ALLOW / QUALIFY / BLOCK recommendations:
`advisory_only=true`, `enforcement_applied=false`. It does not independently
observe or terminate customer workloads. No price, subscription or availability
claim is activated.

## Dependency closure

| Surface | Required files |
|---|---|
| Identity and keys | Existing `commercial_identity.py`; updated `commercial_api_keys.py` adds the keyed-verifier helper used by PostgreSQL |
| HTTP and service | `commercial_http.py`, `commercial_service.py`; optional private usage/diagnostic routes and payload-bound accounting protocol |
| Usage compatibility | Existing `commercial_usage.py` plus only the six-line `reserve_evaluation` compatibility method; no SQLite store |
| Durable accounting | `commercial_reservation_authority.py`, `postgresql_reservation_authority.py`, `postgresql_advisory.py` |
| Database | PostgreSQL migrations 001, 002 and 003, unchanged |
| Application and operator | `private_staging.py`; optional psycopg requirements in `requirements-private-staging.txt` and `requirements-postgresql-test.txt` |
| Tests | Updated commercial service tests; PostgreSQL schema/routine/adapter/integration tests; private staging tests; extraction-boundary tests |
| Documentation | This boundary, PostgreSQL accounting, advisory backend, private staging, HTTP/service updates and README pointer |

The shared reservation value types, canonical hashes, result validation and
adapter remain unchanged rather than rewriting the transaction contract.
Receipt/context protocols retained in that module are inert compatibility
types, not configured signature verification or customer execution grants.
The commercial path imports no experimental signer, observer, STOP authority,
checkpoint or recovery implementation. Existing main evaluator dependencies
on effect labels and external-control policy remain unchanged; the advisory
path does not call workload-control or shutdown operations.

Not imported: experimental SQLite ledger/recovery, Ed25519 verifier,
receipt signer, independent authority head, checkpoint recovery, STOP/observer
modules, host preflight, service units, HTTPS/Docker host harnesses and Lab-01
configuration. Source uncommitted HTTPS acceptance work is not imported.

## Offline validation

Use the existing test interpreter; do not install dependencies as part of this
extraction:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -q -p no:cacheprovider \
  tests/test_commercial_identity.py tests/test_commercial_api_keys.py \
  tests/test_commercial_usage.py tests/test_commercial_service.py \
  tests/test_commercial_http.py tests/test_private_staging.py \
  tests/test_postgresql_authority_schema.py \
  tests/test_postgresql_reservation_routine.py \
  tests/test_postgresql_reservation_authority.py \
  tests/test_postgresql_advisory_integration.py \
  tests/test_commercial_baseline.py
```

Default integration skips are not real database validation. Historical numbers
in the imported backend/private-staging documents are explicitly source history.
HTTPS to real PostgreSQL, host isolation, credential custody, monitoring and
restore reconciliation still require separately authorized operational checks.

Extraction validation on Python 3.14.2: **342 passed, 98 subtests passed,
47 integration cases skipped**. Psycopg is unavailable in the existing test
environment; no database was contacted. The shared accounting modules,
application and three migrations match the source commit byte-for-byte.
All changed Python files parse with Python 3.9 grammar and compile in memory;
this is not runtime validation on Python 3.9. Tracked and new-file whitespace
checks passed. The source worktree's seven changed/untracked file hashes were
unchanged. No website, backend deployment or dependency installation occurred.

## Extraction-time changed-file inventory against main

Code (8):

- [commercial_api_keys.py](../gvai/commercial_api_keys.py)
- [commercial_http.py](../gvai/commercial_http.py)
- [commercial_reservation_authority.py](../gvai/commercial_reservation_authority.py)
- [commercial_service.py](../gvai/commercial_service.py)
- [commercial_usage.py](../gvai/commercial_usage.py)
- [postgresql_advisory.py](../gvai/postgresql_advisory.py)
- [postgresql_reservation_authority.py](../gvai/postgresql_reservation_authority.py)
- [private_staging.py](../gvai/private_staging.py)

Migrations and optional requirements (5):

- [001_reservation_authority_v1.sql](../migrations/postgresql/001_reservation_authority_v1.sql)
- [002_restricted_reservation_routine_v1.sql](../migrations/postgresql/002_restricted_reservation_routine_v1.sql)
- [003_advisory_pilots_v1.sql](../migrations/postgresql/003_advisory_pilots_v1.sql)
- [requirements-postgresql-test.txt](../requirements-postgresql-test.txt)
- [requirements-private-staging.txt](../requirements-private-staging.txt)

Tests (7):

- [test_commercial_baseline.py](../tests/test_commercial_baseline.py)
- [test_commercial_service.py](../tests/test_commercial_service.py)
- [test_postgresql_advisory_integration.py](../tests/test_postgresql_advisory_integration.py)
- [test_postgresql_authority_schema.py](../tests/test_postgresql_authority_schema.py)
- [test_postgresql_reservation_authority.py](../tests/test_postgresql_reservation_authority.py)
- [test_postgresql_reservation_routine.py](../tests/test_postgresql_reservation_routine.py)
- [test_private_staging.py](../tests/test_private_staging.py)

Documentation (7):

- [README.md](../README.md)
- [commercial_advisory_backend_v1.md](commercial_advisory_backend_v1.md)
- [commercial_advisory_base_v1.md](commercial_advisory_base_v1.md)
- [commercial_http_v1.md](commercial_http_v1.md)
- [commercial_service_v1.md](commercial_service_v1.md)
- [postgresql_reservation_authority_v1.md](postgresql_reservation_authority_v1.md)
- [private_staging_v1.md](private_staging_v1.md)

## Billing boundary

The subsequent [test-mode billing implementation](stripe_subscriptions_test_v1.md)
adds separate paid-period entitlements. The 27-file inventory and validation
counts above describe extraction time, not the later billing diff.

This is the existing finite pilot backend, not a subscription entitlement
implementation. The operator CLI remains capped at 1,000 units and 30 days;
pilot consumption is a lifetime ceiling in addition to UTC monthly quota.
Do not relabel or reset a pilot to supply the approved future subscription
allowance of 100,000 per paid period.

Stripe development must add durable verified payment/subscription mapping and
paid-period entitlements atomically enforced by the reservation path. Preserve
tenant isolation, revoked-key denial, idempotency history and consumed units.
No entitlements may derive from browser redirects or customer payment claims.
The approved future policy is paid invoice plus active subscription, immediate
suspension on payment failure, no trial/grace period, and denial beyond the
paid-through date or on immediate cancellation/revocation. Price activation
still requires founder approval.
