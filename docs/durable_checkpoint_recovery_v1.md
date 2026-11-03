# Experimental durable checkpoint recovery V1

Phase 6J.4 is an offline foundation, not production approval. The isolated
[provider and recovery fence](../gvai/experimental_checkpoint_recovery.py) reuse
the [V1 signed checkpoint contract](./independent_authority_head_v1.md) unchanged.
No production store, credentials, signer, live service, registration, PostgreSQL
schema/privilege changes, commercial activation, or supervisor integration exists.

## Durable independent storage contract

`DurableCheckpointStorage` exposes a complete signed checkpoint read and an
atomic compare-and-swap. Provisioning is a separate, approved administrative
operation; runtime reads and updates cannot initialize missing state.

- Authenticate records with independently pinned, nonrevoked Ed25519 keys and
  the existing domain-separated canonical bytes, including full authority,
  epoch, trust domain, sequence, hash, key ID, purpose, version and algorithm.
- Atomically compare the complete expected signed record, not just its sequence.
  Reject identity changes, lower sequences and equal-sequence hash conflicts.
  Idempotent observations are allowed; concurrent updates cannot regress state.
- Persist before reporting success. `False` means a clean comparison loss only.
  Missing records, unavailable storage, corruption and ambiguous writes raise
  `CheckpointStorageError`; they never return success-shaped defaults.
- Enforce bounded deadlines and authenticated transport/responses. Maintain
  linearizable behavior across clients/processes, durable commit guarantees and
  protected recovery history under independent administration.
- Separate custody from PostgreSQL hosts, credentials and backups, checkpoint
  signing custody, receipt signing and supervisor controls. An ordinary local
  file or in-memory store is not production-independent storage.

`ExperimentalDurableHighWaterProvider` authenticates both the candidate and each
stored record. It enforces a separately provisioned, signed recovery anchor as
a lower bound, uses bounded CAS retries, and authenticates again after a clean
comparison loss. Detached snapshots and separate callback argument copies
preserve the Phase 6J.3 provider-substitution repair. Adapter argument mutation,
nonboolean success responses and elapsed deadlines fail explicitly. Callback
arguments are revalidated and authenticated after CAS, including substitutions
that compare equal in Python (such as integer sequence `7` replaced with `7.0`).

The storage adapter remains a trusted boundary: signatures do not prove that
the adapter persisted data or that a response is the current record. A production
implementation must independently meet the transport, custody, atomicity and
durability obligations above. No implementation of that production boundary
is supplied.

## Explicit recovery reconciliation

`ExperimentalCheckpointRecoveryFence` starts `FENCED` on each construction.
`assess(checkpoint, database_head)` reports `MATCHED` only when the supplied
database head, pinned-authenticated checkpoint and current stored head agree.
Assessment alone does not reconcile. `reconcile(...)` is the explicit trusted
recovery-controller operation; it rechecks the same agreement with atomic CAS
and reports `RECONCILED`. It never advances storage from restored database
evidence or a newer caller checkpoint.

Missing/malformed evidence, stale database snapshots, conflicting hashes,
unknown identity, corrupt/unsigned storage, storage below the external anchor,
concurrent comparison loss, and ambiguous writes remain fenced with an explicit
reason. Reconciliation is not serialized into a store or inherited on restart.
`check_reconciled(fresh_database_head)` revalidates the reconciled checkpoint
against current storage; any discrepancy fences it again and requires another
explicit reconciliation. Higher history must first be reconciled and published
through the independently approved checkpoint/history boundary.

The controller, signed anchor and independently obtained, consistent post-commit
database observation are trusted inputs, not arbitrary customer requests.
Neither these classes nor `RECONCILED` reopen a service or authorize a grant.
`may_authorize_fresh_grant` is always false. There is no commercial, PostgreSQL
reader, trusted receipt signer, startup or supervisor wiring. Production startup
must remain fenced until a separately approved recovery controller reconciles
history and supplies an atomic downstream fence/lease appropriate to that system.

## Offline persistence and adversarial evidence

[Tests](../tests/test_experimental_checkpoint_recovery.py) contain a SQLite
adapter only inside the test module. It uses explicitly provisioned temporary
files, separate connections, `BEGIN IMMEDIATE`, complete-record comparison,
monotonic checks and `synchronous=FULL`. Missing files are opened in `mode=rw`
and are never created by runtime operations. Stored canonical checkpoint bytes
and detached signatures are decoded strictly and authenticated by the provider.
Test keys are ephemeral; no private key is serialized.

Coverage includes adapter reconstruction and a separate-process committed read,
stale database and storage backup restore, concurrent independent adapter
updates, equal-sequence conflicts, corruption and signature substitution,
missing trust rows/files, forged inputs, storage read/write failures, ambiguous
commits, callback substitution, CAS contention, and explicit recovery fencing.
All files are temporary and cleaned up by the test fixture. No live database,
network service or infrastructure is used.

## Remaining limitations and readiness

- SQLite tests demonstrate local transactional persistence and offline restart
  behavior, not independent custody, host-crash/power-loss durability, production
  rollback resistance or distributed linearizability.
- An externally retained recovery anchor detects a store restored below that
  known history. It is not a current-tip oracle. Restoring both the store and
  its anchor to matching older signed history is undetectable. A production
  anchor needs independently protected monotonic publication and recovery.
- Signatures authenticate assertions, not legitimate event generation or
  contiguous database history. Higher signed sequences may skip checkpoints.
  Complete chain reconciliation belongs to the trusted signer/history boundary.
- Results describe a linearization point, not a durable lease. A concurrent
  update can invalidate a result immediately. The fence assessment is offline
  evidence, not atomic authorization against changing database state.
- Adapter-enforced deadlines cannot interrupt a malicious blocking Python
  callback. Signer compromise, dishonest storage and co-restored trust state
  remain outside this foundation's protections.

## Validated offline results

Using the existing approved Python 3.12 environment, with no package installs:

```sh
PYTHONDONTWRITEBYTECODE=1 /tmp/gvai-phase6j3-py312/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_experimental_checkpoint_recovery.py tests/test_experimental_authority_head.py \
  tests/test_experimental_receipt_signer.py tests/test_commercial*.py tests/test_postgresql*.py
PYTHONDONTWRITEBYTECODE=1 /tmp/gvai-phase6j3-py312/bin/python -m pytest -q -p no:cacheprovider
```

- Focused, commercial and PostgreSQL regressions: **441 passed, 282 subtests**.
- Full offline suite: **686 passed, 362 subtests**.
- Checkpoint/recovery tests on the existing approved Python 3.14 environment:
  **60 passed, 144 subtests**.
- New Python sources parse with the project's Python 3.9 syntax target; this
  is not a claim of runtime testing on Python 3.9. Final newlines, ASCII and
  trailing whitespace were checked. No new dependencies are required.

The exact scope is three new files: the experimental module, its test module
and this document. Existing checkpoint, receipt signer, PostgreSQL, commercial
and supervisor files are unchanged.

Experimental commit readiness does not authorize a commit, PR, merge,
deployment, commercial activation, billing/DNS/hosting changes or STOP changes.
STOP for founder review.
