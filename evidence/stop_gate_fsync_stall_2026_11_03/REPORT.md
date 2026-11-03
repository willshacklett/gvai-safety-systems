# Phase 1 diagnostic: external STOP gate communication_failure (2026-11-03)

Base commit b15277ce1418f2ec9f89925d5200fb2a84acf5e2, detached worktree /tmp/wt_p1 (clean, removed afterwards).
Whole file tests/test_experimental_external_gate.py, 10 sequential repetitions, 2-core idle host, ext4 on /dev/vdb.
Out-of-tree instrumentation only: /tmp/diag2/diagplugin2.py (client phases, spawn-to-ready, failure snapshot, results)
and /tmp/diag2/child/sitecustomize.py (gate/backend child timing: fsync, anchor flock wait/hold, store save,
latch apply, gate handle, control handler total, notice push, backend notice apply, scheduler stalls).
No tracked file, timeout or behaviour changed. Key seed contents withheld; no envelopes/tokens logged.

## Result: failure REPRODUCED in 3 of 10 repetitions (runs 2, 5, 10); 7 clean (33 passed).
Each failing run had exactly 1 failed test, at tests/test_experimental_external_gate.py:125 (arm(1), first control command):
- run 2 test_store_rollback_between_restarts_faults
- run 5 test_omitting_verifier_call_cannot_bypass
- run 10 test_forged_notice_cannot_reopen_backend

## Failure phase (all 3): response wait, not connect/send/decode
gc.sock command: t_connect 0.0001-0.0002 s, t_send <=0.0001 s, t_wait 2.002-2.003 s -> response_timeout; socket existed.
Gate and backend processes alive; no exit codes; no orphans, stale sockets or temp dirs after the runs.

## Cause observed (runs 2 and 10, confirmed by child logs)
The gate's first fsync (of anchor.json.tmp inside FileTrustedAnchor.compare_and_advance) blocked: 8.036 s (run 2), 8.542 s (run 10).
anchor_lock_hold:op = 8.038 / 8.543 s; latch_apply 8.041 / 8.546 s (accepted). Every other gate stage was sub-20 ms:
notice push 1-2 ms, store_save 2.8-3.0 ms, flock wait ~0, scheduler stalls <=0.1 s elsewhere, spawn-to-ready 0.07-0.2 s.
=> I/O (fsync) stall, not CPU starvation, not startup, not backend notification, not lock contention.
Run 5: the same state signature (anchor.json.tmp 93 bytes, no anchor.json/store.json at snapshot; the 10 s probe also timed out)
and no completed gate record before the gate was killed ~12 s later. Consistent with the same fsync stall but NOT directly proven
(the fsync wrapper logs on completion only, and the stalled call never completed).

## Post-timeout application (confirmed twice)
Runs 2 and 10: the client had returned communication_failure at +2 s, yet the gate later completed the ARM (accepted, +8.04/+8.55 s)
and the read-only status probe then reported "armed". A timed-out command was applied after the client gave up.
Same code path as STOP; a timed-out STOP can therefore commit later. (Observed for ARM only; not exercised for STOP.)
Also: while apply held the latch lock, status/authorize requests blocked (status handled in 6.5 s) - they would time out client-side (deny).

## Timing distributions (all 10 runs)
client gc.sock command ok total (n=513): min 0.0001 med 0.0069 p95 0.0112 p99 0.0597 max 0.2154
fsync (n=710): med 0.0020 p95 0.0033 p99 0.0382 max 8.5417; slow >=50 ms: 8.54, 8.04, 0.19, 0.11, 0.055, 0.053, 0.05
control_handler_total (n=515): med 0.0062 p99 0.0836 max 8.5500
latch_apply (n=515): med 0.0051 p99 0.0589 max 8.5461; store_save (n=355): med 0.0019 max 0.1924
gate_handle:authorize (n=2793): med 0.0001 max 0.0074; notice_push:control (n=355): med 0.0009 max 0.0200
spawn_to_ready gate (n=319): med 0.078 max 0.2095; backend (n=270): med 0.0715 max 0.2287
Client outcomes elsewhere (expected-deny tests, not failures): BrokenPipe 13, FileNotFound 10, ConnectionReset 7.

## Limits
- Heartbeat contention measured only via notice_push:heartbeat (slow-only logging); no evidence of involvement.
- Queueing before handler entry (accept/recv) not measured. Handler entry not logged, so in-flight stalls are visible only on completion.
- Cause of the 8 s fsync stall (ext4/jbd2/writeback/virtualised disk) not identified; no strace or kernel/blk metrics taken.
- n=10; rate 30% is an estimate only. Instrumentation could in principle perturb timing; earlier un-instrumented runs showed the same failure class.
