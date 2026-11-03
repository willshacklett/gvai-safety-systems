# Experimental STOP-latch verification V1

Governing principle: **Never let the thing behind the switch own the switch.**

## Scope and status

This is an experimental, disconnected prototype. The implementation is
`gvai/experimental_stop_latch.py`; the tests are
`tests/test_experimental_stop_latch.py`. No production module imports it
(enforced by `test_production_modules_do_not_import_the_latch`). The commercial
service, HTTP layer, staging deployment and PostgreSQL schema are unchanged and
remain advisory-only (`advisory_only=true`, `enforcement_applied=false`).
Nothing is registered, activated, deployed or approved.

### This is in-process verification only

**It is not independent enforcement and not durable STOP protection.** The gate
runs inside the same Python process as the commercial service. A compromised
commercial process can skip, replace, monkeypatch or never call it, can read
and delete anything its OS user can, and can simply not consult the latch. The
wrappers define a *mandatory interface* and prove that correctly written callers
fail closed; they do not prevent a malicious caller from bypassing them. The
verifier's state is held in memory and is lost on restart.

## Architecture

| Component | Role |
|---|---|
| `StopLatchRecord` | Immutable, hash-chained, Ed25519-signed statement: authority, sequence, previous hash, `run`/`stopped`, `issued_at`/`expires_at` (lease of at most 300 s), key ID |
| `decode_record` | Strict canonical wire decoder: exact fields, no duplicates, no NaN, no coercion, size limit, byte-exact re-encoding |
| `StopLatchVerifier` | Pinned public keys only; chain, rollback, lease and sticky-STOP logic under one lock |
| `LatchAnchor` | Independently provisioned lower bound (sequence and hash) used at construction |
| `StopLatchSource` / `FileStopLatchSource` | Read-only record supplier; the file source rejects symlinks, hardlinks, non-regular, group/other-writable and oversized files |
| `StopLatchGate.require_run(op)` | Reads, verifies and denies on any doubt; only `evaluate` and `reserve` are valid operations |
| `LatchEnforcedUsage` | Wraps usage `reserve_evaluation`; denies (`UNAUTHORIZED`) without touching the inner object |
| `LatchEnforcedEvaluationService` / `build_latch_enforced_service` | Enforce at `evaluate` and, independently, at `reserve` |

Signing input: domain prefix `gvai-stop-latch-record-v1` + NUL, then canonical
JSON (sorted keys, compact separators, ASCII, no NaN) of all fields except the
signature. The domain is distinct from the receipt and authority-head
checkpoint domains. The record hash chained into the next record is the SHA-256
of those same signed bytes. Genesis is sixty-four zeros.

### Decision rules

ALLOW only for an authentic, in-chain, unexpired `run` record from a pinned,
unrevoked key, for the pinned authority/epoch/domain. Every other outcome is a
falsy `LatchDecision` with a specific reason: missing, corrupt, wrong
authority, unknown/revoked key, bad signature, rolled back, equal-sequence
conflict, chain break, sequence gap, not yet valid, expired, clock error,
source unavailable, invalid operation, internal error.

- A valid signed `stopped` record latches STOP permanently in that verifier,
  regardless of sequence, chain position or age. Replaying a captured STOP can
  only deny service. There is no reset, clear or unstop API.
- After STOP, a missing, corrupt, rolled-back or unavailable source still
  reports STOPPED.
- Sequence must advance by exactly one from the high-water mark; lower
  sequences are rolled back; an equal sequence needs the identical hash.
- The injected clock must be monotonic per verifier; regression, NaN, infinity,
  booleans and non-numbers deny.

## Key custody assumptions

- The verifier receives only 32-byte Ed25519 **public** keys. The module imports
  only `Ed25519PublicKey` and `InvalidSignature` from `cryptography`; a test
  asserts that exact set and the absence of any signing or key-generation
  attribute.
- The STOP signing key must be generated and held by a separately administered
  supervisor, never by the commercial service, its database role or its host
  account. This prototype provides no signer. Tests use ephemeral keys held by
  a test-only `Supervisor` class.
- Key reuse is rejected only for keys the provisioner *declares* (by ID or raw
  public bytes) as belonging to receipt, checkpoint, HMAC or other purposes.
  The verifier cannot discover undeclared reuse or prove custody.

## Test evidence

Measured in a fresh Python 3.12.3 virtual environment (pytest 9.2.0) on the
commercial tip plus this change:

| Run | Exit status | Result |
|---|---|---|
| `tests/test_experimental_stop_latch.py` | 0 | 69 passed |
| Adjacent commercial/authority suites | 0 | 209 passed, 179 subtests |
| Full suite | see PR description | 89 skips are PostgreSQL/Docker tests |

Adversarial coverage: field tampering (every signed field), state flip from
STOPPED to RUN, mutation of frozen records and nested authority via
`object.__setattr__`, malformed construction, unsigned/zero signatures,
attacker key with a trusted key ID, unknown and revoked keys, wrong
authority/epoch/domain, signature-domain substitution, declared key reuse
(by ID and renamed key), private-key bytes as a public key, strict wire decoding
(duplicate keys, extra fields, floats, booleans, NaN, noncanonical, oversized),
deletion/corruption/unsafe-permission/symlink/hardlink/directory file sources,
rollback and replay (old RUN, captured STOP, forks, gaps, equal-sequence
conflicts), expiry, future leases, clock regression, restart below the anchor,
sticky STOP after source deletion or rollback, wrapper denial before any usage
or evaluator work, preserved advisory behavior under a valid lease, STOP
mid-stream, and concurrency (32-thread reads, STOP racing 16 readers,
conflicting same-sequence records, shuffled out-of-order submission, ordered
multi-thread submission, and 24 simultaneous submissions of one next link).

These tests measure Python control flow and cryptographic checks. They are
offline, use temporary files and ephemeral keys, and touch no network, database,
process or infrastructure.

## Required external enforcement boundary (not implemented)

Preventing bypass by a compromised commercial process requires a boundary the
commercial process does not own:

1. **Separate supervisor identity.** A different OS user/service holds the STOP
   signing key and the writable journal. The commercial account has read access
   to at most the public record and no access to keys, the journal directory or
   control IPC. The existing iron-switch STOP journal and cgroup adapter
   (`gvai/supervisor_stop.py`, `gvai/linux_containment_stop.py` on the
   `iron-switch` line, which shares no history with this branch) are the
   candidates to reuse.
2. **Gateway or kernel-enforced stop.** The commercial process must not be able
   to reach customers, the database or model egress except through a gateway
   that performs this verification itself, or it must be killed (for example
   by cgroup kill) by the supervisor when STOP is latched. Verification inside
   the governed process is advisory.
3. **Durable independent high water.** A record store and anchor outside the
   commercial host's control, with monotonic publication, so restart cannot
   reset the chain (compare `docs/durable_checkpoint_recovery_v1.md`).
4. **Fenced output.** STOP must be ordered with dispatch and publication so a
   decision cannot be released after STOP is observed.

## Unresolved limitations

- Bypassable by the process it governs (see above); no process isolation.
- Not durable: latch stickiness and high water reset on restart to the supplied
  anchor. Restoring both the record and the anchor to older valid history is
  undetectable.
- Freshness is lease-based against an injected clock the verifier does not
  authenticate; a compromised clock source can extend or shorten leases.
- The file source does not verify ownership or directory protection, and a
  read-then-verify sequence is not an atomic fence against later change.
- No signer, publication channel, provisioning, rotation or revocation
  procedure exists. Compromise of the STOP key defeats the design.
- No evidence on Linux: OS-user separation, file permissions, reboot
  persistence, supervisor death, cgroup kill and power-loss durability are
  untested. These need a disposable Linux host under separate approval.
- The commercial and iron-switch lines are unreconciled; no integration is
  attempted or claimed.

## Status

Experimental prototype for founder review. No production activation,
deployment, merge to `main` or integration is authorized.
