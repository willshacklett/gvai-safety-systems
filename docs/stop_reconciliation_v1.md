# STOP command reconciliation V1 (experimental)

Status: prototype in `gvai/experimental_stop_latch.py` and `gvai/experimental_external_gate.py`.
Not deployed, not wired to the STOP-generation journal, no timeout, heartbeat, token or ARM change.

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
| Client outcome | `GateClient.submit_stop` | `UNKNOWN` on any transport failure, never an acknowledgement. `STOP_RECORDED` / `ALREADY_APPLIED` set `durable=True`. `NOT_DURABLE` for anchor/store write failures (gate stops itself in memory). |
| Backend notice | `make_control_handler` | `backend_notice` is `acknowledged` only if the backend replied `ok` to the notice, else `unconfirmed`. A retry re-sends the notice. |

## Three distinct claims

1. **STOP accepted**: the gate returned `accepted`/`already_applied`.
2. **STOP durably recorded**: `durable=True` / verdict `EXACT_APPLIED` — gate anchor and store hold exactly this command.
3. **Backend execution actually halted**: never claimed. Every reply carries `backend_halt: "UNVERIFIED"`.
   `backend_notice: acknowledged` is only the backend's own reply to a message.

`ok` on a `reconcile` reply means the query was answered, not that a STOP exists; use `verdict`/`stop_recorded`.

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

- Tests are in-process fault injection (`tests/test_stop_reconciliation.py`); real-socket timing and Linux I/O stalls are untested.
- `EXACT_APPLIED` proves the gate's local files hold the command, not that the backend stopped, and local files cannot detect a coherent rollback of the anchor and store together.
- Only the head is stored: an older STOP superseded by a newer command can never be proven, hence `SUPERSEDED_UNVERIFIED`.
- Anyone holding a signed STOP envelope and control-socket access can query; the query changes nothing. The control socket is protected only by same-UID simulation here.
- A crash before the anchor advance leaves no trace (`NOT_APPLIED` is "as of this read"; the command may still be in flight).
- No journal integration, no restart-persistent generation semantics, no independent halt evidence.
