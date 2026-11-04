# STOP command reconciliation V1 (experimental)

Status: prototype in `gvai/experimental_stop_latch.py` and `gvai/experimental_external_gate.py`.
Not deployed or wired to the STOP-generation journal. I6D changes local restart
and persistence behavior only; timeout, heartbeat, token and signed ARM bytes
are unchanged.

## Problem

`_Client.request` returns `communication_failure` for every transport error after a 2.0 s wait. The gate keeps
processing after the client gives up, so a STOP may be applied, not applied, or crash mid-way, and the old
`stale_or_replayed` reply to an identical retry hid a successful STOP.

## What is implemented

| Item | Where | Behaviour |
|---|---|---|
| `reconcile` control request | `GateCore.reconcile`, `StopLatch.reconcile` | Read-only. Needs a parseable, correctly signed STOP for this latch (ARM envelopes rejected). Control socket only; not in `SERVICE_GATE_REQUESTS`. |
| Verdicts | `ReconcileResult` | `EXACT_APPLIED` (submitted digest == durable head, anchor and re-verified store agree), `NOT_APPLIED` (sequence above head), `CONFLICT` (same sequence, different digest), `SUPERSEDED_UNVERIFIED` (head is newer: the submitted STOP is neither proven nor disproven), `UNVERIFIABLE` (fault, store missing, anchor/store mismatch or unreadable), `REJECTED` (not authentic). Client adds `UNKNOWN` on transport failure. |
| Idempotent retry | `StopLatch._apply` | An identical signed STOP at the head returns `already_applied` (`CommandResult.accepted` stays False: only a new application is "accepted"; the gate maps it to `ok: true`) only after re-reading the anchor and the stored command, re-verifying its signature and matching the full digest. Signature checks happen first, so it cannot bypass authentication. |
| Conflicts | `_apply` | Different STOP at the head sequence: `conflicting_command`. Lower sequence: `stale_or_replayed`. ARM replies are unchanged. |
| Client outcome | `GateClient.submit_stop` | `UNKNOWN` on transport or persistence uncertainty, never an acknowledgement. `STOP_RECORDED` / `ALREADY_APPLIED` set `durable=True` only for confirmed local transaction state. No persistence failure proves non-application. |
| Backend notice | `make_control_handler` | `backend_notice` is `acknowledged` only if the backend replied `ok` to the notice, else `unconfirmed`. A retry re-sends the notice. |

## Three distinct claims

1. **STOP accepted**: the gate returned `accepted`/`already_applied`.
2. **STOP locally recorded**: `durable=True` / verdict `EXACT_APPLIED` — the exact command, anchor and transaction receipt match after the local file/directory persistence barriers. This is not physical power-loss proof.
3. **Backend execution actually halted**: never claimed. Every reply carries `backend_halt: "UNVERIFIED"`.
   `backend_notice: acknowledged` is only the backend's own reply to a message.

On a `reconcile` reply `ok` is true only for `EXACT_APPLIED`; `answered` says whether the query was evaluated. Always use `verdict`. No verdict other than a later signed ARM is permission to resume execution.

Review fixes: `reconcile` now also requires the durable record to equal the live latch head (rollback/substitution of anchor and store together gives `UNVERIFIABLE`, never `EXACT_APPLIED`), and authenticates before revealing any status.

## Residual execution window (documented, unchanged)

Code facts (`experimental_external_gate.py`): token TTL `DEFAULT_TOKEN_TTL = 5.0`; notice max age
`DEFAULT_NOTICE_MAX_AGE = 3.0`; heartbeat 0.1 s; synchronous notice push timeout 1.0 s.

- The gate issues no new permit once STOPPED.
- Once the backend applies the STOP notice, any already-issued permit is refused at once (`gate_not_armed`), so
  the 5 s TTL is *not* the exposure.
- If the notice does not reach the backend, issued permits keep working until the backend's last notice is older
  than 3.0 s (`gate_notice_stale`) — about 3 s, plus the 0.05 s watchdog interval and the interrupt deadline for
  in-flight work. Heartbeats retry the STOP notice every 0.1 s (each push can block up to 1.0 s).
- Tests: `test_residual_window_between_stop_and_backend_notice`, `test_issued_permit_refused_immediately_once_notice_arrives`.
  These use injected clocks and prove logic only, not real timing.

## Not proven / limitations

- Reconciliation tests use in-process fault injection; I6D adds process-exit
  recovery tests. Neither establishes real storage-stall bounds or physical
  power-loss behavior. Retained earlier diagnostics are observations, not
  durability guarantees.
- `EXACT_APPLIED` proves the gate's local files hold the command, not that the backend stopped, and local files cannot detect a coherent rollback of the anchor and store together.
- Only the head is stored: an older STOP superseded by a newer command can never be proven, hence `SUPERSEDED_UNVERIFIED`.
- Anyone holding any valid signed STOP envelope (even a superseded one) and control-socket access can read the head sequence and digest indefinitely; the query changes nothing. Each `already_applied` retry re-sends a notice (synchronous push, up to 1.0 s, counter increments): a DoS-only concern, unchanged. The control socket is protected only by same-UID simulation here.
- A crash before the anchor advance leaves no trace (`NOT_APPLIED` is "as of this read"; the command may still be in flight).
- No journal integration, no restart-persistent generation semantics, no independent halt evidence.

## I6D local transaction and restart contract

The gate now uses `GateTransaction` in `gvai/gate_transaction.py`. This is
separate from C1/C2/C3A and the STOP-generation journal. Signed command bytes,
identities and sequence ordering are unchanged. The transaction revision is
a separate bounded integer, not a STOP epoch or OPEN generation.

### Provisioning and ownership

Offline `GateTransaction.provision(new_directory, latch_id)` creates only a
new dedicated directory, genesis records and a private gate seed. It refuses
an existing directory, including legacy state; interrupted provisioning is
not automatically retried or migrated. The parent must already exist.
Ordinary `GateCore` startup never provisions or repairs state. Existing
deployment configurations are unchanged and must not be used without an
explicit provisioning/migration plan.

A lifetime nonblocking exclusive `flock` on `transaction.lock` permits one
local writer. `GateCore.close()` releases ownership; restart requires closing
or terminating the previous process. The lock is not cross-host fencing.
The lock inode is checked throughout the session. No independent writer
epoch, failover or operator recovery interface is implemented.

### On-disk schema

All records are bounded to 16 KiB; transaction JSON is canonical, duplicate
fields are rejected and integers have exact types.

- `anchor.json`: existing command sequence and digest.
- `store.json`: exact existing signed command envelope (null at genesis).
- `transaction.json`: exact fields `version` (1), `latch_id`, `revision`
  (0 through 2**53), `command`, `anchor_hash`, `store_hash`, `previous`.
  Genesis has null command/previous; later revisions bind the previous receipt
  digest. Hashes use `GVAI-GATE-TRANSACTION-V1\n` plus exact canonical bytes.
- `transaction.intent`: proposed receipt, created exclusively before modifying
  either command record. Its presence always denies recovery; startup never
  rolls it forward or deletes it.
- Each replacement uses a corresponding `.tmp` file. Any such leftover
  denies startup, even if the visible pair looks complete.

Receipts bind exact command signatures, local revision and both file hashes.
They are consistency metadata, not signatures or an independent hash-history
witness. Only the current receipt is retained.

### Ordering and confirmation

Under the existing latch lock and exclusive local writer ownership:

1. Validate the current clean receipt/pair and live revision.
2. Create/write intent; file-fsync; directory-fsync; exact retained-file
   readback. No anchor/store update occurs before this boundary.
3. Write anchor temporary file; file-fsync; replace; directory-fsync; exact
   readback using the retained descriptor and pathname/inode checks.
4. Repeat for the command store, then the committed receipt.
5. Remove intent; directory-fsync; synchronize and revalidate the final
   receipt/pair, file identities and absence of pending artifacts.
6. Only then return accepted. Exact STOP retries and reconciliation also
   require agreement with the confirmed live receipt and head.

Any exception once commit is attempted faults the live coordinator/latch and
returns `persistence_unknown`; the client classifies this as UNKNOWN, with
`durable=False`. There is no automatic command retry or uncertainty cleanup.
Failures before replacement retain intent/temp evidence. If unlink itself
succeeds and its subsequent barrier fails, the intent may already be absent:
the failed attempt remains UNKNOWN; a fresh process can only establish a new
confirmation after synchronizing and validating the entire clean state.

### Crash windows and restart

| Crash point | Recovery |
| --- | --- |
| Before intent creation | Previous confirmed sequence retained, execution denied |
| Partial/durable intent; any anchor/store/receipt write, sync or replacement | Pending artifacts remain: FAULT, no command replay |
| Receipt complete, intent still present | FAULT even when anchor/store match |
| Intent absent after unlink, cleanup barrier incomplete | Re-synchronize exact clean state; original attempt remains UNKNOWN |
| Final confirmation completed, response lost | Exact STOP may reconcile after new confirmation, without sequence advancement |

Missing/corrupt receipt, invalid signatures, malformed records and inconsistent
hashes deny startup. A clean recovered ARM record always starts **STOPPED**,
preserving sequence/digest but not its old execution permission. Only a fresh
authenticated contiguous ARM can reopen that clean state. A recovery FAULT
cannot be cleared by ordinary ARM. Pending STOP needs separately authorized
recovery, which is intentionally not implemented.

Confirmed STOP recovery performs fresh file/directory synchronization and exact
validation before it can return EXACT_APPLIED. It proves current local
confirmation, not that an earlier timed-out call succeeded or a backend halted.

### Evidence limits

Fault injection and process-exit tests cover each exposed persistence phase for
ARM and STOP, plus syscall failures, malformed receipts, exclusive ownership
and restart denial. Process exits do not model hardware write reordering or
power loss. Local fsync and hash receipts cannot resist coherent rollback,
malicious same-UID/root modification, hostile storage or compromised hardware.
No independent shutdown, remote persistence or bounded STOP latency is claimed.
The latch still holds its lock across synchronous storage I/O: stalls remain
unbounded and can delay STOP, reconciliation and notification.
