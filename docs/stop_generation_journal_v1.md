# Restart-Persistent STOP Generation Journal V1 (experimental)

Governing principle: **Never let the thing behind the switch own the switch.**

Status: **experimental, disconnected, no enforcement claim.** Nothing imports
`gvai/stop_generation_journal.py` (asserted by a test). It is not wired to the
commercial service, the STOP gate, systemd or any host. Based on PR #44 head
`054e604`; PRs #42, #43, #44 and #47 are untouched.

## Contract mapping

| Contract item | Implementation | Tested |
|---|---|---|
| STOP terminal within a generation | `latch_stop` appends a `stop` record; a second STOP in a generation is a chain break; an instance that has seen STOP/fault/missing state is sticky | yes |
| No ARM/RESET/CLEAR/UNSTOP | Public surface is exactly `latch_stop`, `state`, `close`; AST/name tests reject reopening vocabulary | yes |
| Missing/corrupt/stale/unverifiable fails closed | Every unexpected condition yields `stopped=True, fault=True` | yes |
| New generation only via offline provisioning | An `open` record for generation N+1 is accepted only after the `stop` of N and only with a valid Ed25519 signature from a pinned key. The module cannot create one | yes |
| Hash-chained canonical journal, locking, durability | `journal.json` canonical JSON, SHA-256 chain, `flock`, `fsync` of files and directory, atomic `rename` | logic yes; real durability **no** |
| Crash-left intent preserved | `journal.intent` (O_EXCL, fsynced) precedes `journal.pending`; leftover files are `incomplete_commit` and never deleted by the module | simulated |
| File substitution | Directory held by fd (`O_DIRECTORY\|O_NOFOLLOW`), `dir_fd`-relative `O_NOFOLLOW` opens, regular-file/`st_nlink==1`/owner/`0600` checks, lock inode identity re-checked | yes |
| No signing authority | Only `Ed25519PublicKey` and `InvalidSignature` imported; no sign/generate/private-key names | static test |
| Local state cannot prove no coherent rollback | `rollback_detection="none"` without anchor; limitation test | yes |

## Format

`{"records":[...],"version":1}` canonical (sorted keys, no whitespace, ASCII),
max 64 records / 64 KiB, byte-exact re-encode check. `record_hash =
SHA-256(domain || canonical(record))`, genesis `0*64`.
`open` (offline-signed) and `stop`
(unsigned: STOP is the safe direction and needs no secret). Every `open`
signs, under domain `gvai-stop-generation-open-v2`: authority, trust domain,
key id, **`journal_id`**, **`not_before`**, **`not_after`** (integer epoch
seconds, `not_before < not_after`), generation, index and `previous_hash`.
Directory layout:
`journal.lock`, `journal.json` (both pre-provisioned, mode 0600, never created
by the module), transient `journal.intent`, `journal.pending`.

## Identity and validity

- The caller injects `expected_journal_id` (required), obtained independently
  of the journal storage. Every `open` must carry exactly that id
  (`journal_id_mismatch` otherwise), which blocks replay of a valid journal
  from another deployment that shares the authority, domain and key.
- The *active* `open` (last record, not terminal) must satisfy
  `not_before <= now < not_after` by an injected clock (default `time.time`):
  `open_premature`, `open_expired`, or `clock_unverifiable` (clock raises, or
  returns a non-number, bool, NaN or infinity). These are stopped faults and
  sticky for the instance. A terminal STOP does not depend on the clock.
  Earlier generations' windows are not re-checked.
- Revoked or unpinned keys, wrong authority/domain, and bad signatures remain
  faults. Editing any signed field breaks the signature.
- **Clock limitation:** the clock is local. Rolling the host clock back lets a
  *new* instance accept an expired `open`; the window bounds operation only
  against an honest clock, and is not an independent time source.

## STOP commit protocol

In-memory STOP first; exclusive `flock`; verify chain; create intent + fsync +
dir fsync; write pending + fsync; `rename` over journal; dir fsync; unlink
intent + dir fsync. Any failure poisons the instance. Cleanup failure after the
rename is deliberately conservative (next start reports `incomplete_commit`;
resolving that is an offline operator action, not an in-process one).

## STOP acknowledgement

`StopOutcome.ack` is an ordered `StopAck`, replacing the old `durable` boolean;
it never decreases for an instance.

| Ack | Meaning | After restart |
|---|---|---|
| `MEMORY_ONLY` | Denied in this process only. No proven durable evidence. | **May read active** |
| `INTENT_DURABLE` | Intent file and its directory entry were fsynced (or leftover intent evidence was observed). | Fails closed (`incomplete_commit`) |
| `COMMITTED` | The `stop` record was renamed in and the directory fsynced (or a committed STOP was observed). | Terminal STOP |

A STOP in memory is effective after any write failure. A requester that gets
no acknowledgement, or `MEMORY_ONLY`, must treat durability as **unknown**
(unreceived and accepted-but-not-durable are different facts, but both leave no
restart-safe evidence) and rely on independent backend enforcement.

## Rollback and fork detection

- Long-lived instance: remembers the longest chain seen; a shorter prefix is
  `rollback_detected`, a divergence `fork_detected`, disappearance
  `journal_deleted`.
- Fresh instance with an independently held `JournalAnchor(record_count,
  head_hash)`: same detections across restart.
- **Fresh instance without an anchor cannot detect a complete, coherent
  restore of older journal state** (`test_COHERENT_ROLLBACK_IS_UNDETECTABLE_WITHOUT_AN_ANCHOR`).
  Local-only state cannot solve this; an external anchor, TPM/monotonic
  counter or remote authority is required.

## Test evidence (Cloud, offline, temp dirs)

`tests/test_stop_generation_journal.py`: 109 tests (plus subtests) covering
persistence incl. subprocess restart, generation authority (forged/wrong key/
revoked/skipped/replayed/missing stop), journal-identity replay, validity
window and clock boundaries, acknowledgement correctness, corruption
(truncated, oversized,
noncanonical, duplicate, coerced types), crash and syscall-failure injection,
symlink/hardlink/permission/FIFO/foreign-owner/dir-swap attacks, thread and
multi-process contention, rollback/fork/deletion, and static surface checks.
Full-suite results are in the commit report.

## Unresolved limitations

1. **Crash before durable intent (unresolved).** A crash, or an I/O failure,
   before `journal.intent` is durable leaves no trace; restart reads
   not-stopped and the request is `MEMORY_ONLY`. This cannot be closed by the
   journal. It requires independent backend enforcement: the protected backend
   must hold downstream credentials and require a fresh positive authority,
   and a requester must escalate on anything short of an acknowledgement.
   Tested only by injection (`test_failure_before_intent_exists_is_memory_only_and_restart_reads_active`).
2. Durability (`fsync` semantics, power loss, reboot, filesystem behaviour) is
   **unproven on Linux hosts**; tests inject failures, they do not cut power.
3. No independent anchor exists yet; coherent rollback is undetectable locally.
4. A same-UID or root compromise of the host can edit/replace the journal; the
   unsigned STOP record is hash-chained, not authenticated. The commercial
   service must run as a different UID with no write access (host config, not
   proven here).
5. Offline provisioning tool, key custody and human authorization workflow are
   out of scope; test code signs `open` records with throwaway keys.
6. "Not stopped" is informational, not authorization; downstream credential
   control by the protected backend and gate integration are not implemented.
7. Locking is advisory `flock`; behaviour on NFS or similar is unsupported.
8. Max 64 records; a full journal fails closed (`journal_full`) pending
   offline replacement.
9. Validity windows rely on a local clock (see above); `journal_id` must be
   provisioned to the verifier independently of the journal's storage.

No production enforcement claim is permitted until Linux host evidence and
external authority validation exist.
