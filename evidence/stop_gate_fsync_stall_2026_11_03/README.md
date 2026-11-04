# Phase 1 diagnostic: external STOP gate fsync stall (2026-11-03)

This is diagnostic evidence, not security approval. No application code, tests or timeouts were changed.

- Tested commit: `b15277ce1418f2ec9f89925d5200fb2a84acf5e2` (feature/stop-reconciliation-v1), detached worktree.
- Test: whole `tests/test_experimental_external_gate.py`, 10 sequential runs, disposable cloud VM (2 cores, ext4 on /dev/vdb). Not Lab-01.
- Instrumentation was out-of-tree (client plugin plus a `sitecustomize` loaded in spawned gate/backend children). Its source is NOT preserved here. Key seed contents were withheld.
- `REPORT.md` is the analysis. `run_N/` holds `events.jsonl` (client/test events), `child_<pid>.jsonl` (gate/backend timing), `pytest.txt`, `pytest.exit`. The `plumb/` instrumentation self-check was excluded. 620 files, byte-for-byte copies.

## Results
- 7 runs passed (33 tests). Runs 2, 5, 10 each had one failure at `tests/test_experimental_external_gate.py:125` (`arm(1)`): `response_timeout` after the client waited ~2.0 s, following an immediate connect and send.

## Confirmed (runs 2 and 10)
- The gate's anchor temp-file `fsync` (inside the anchor flock, inside the latch lock) blocked 8.036 s (run 2) and 8.542 s (run 10). All other measured stages were under ~0.2 s.
- Delayed ARM commits: the client had already reported `communication_failure`, yet the gate later applied the ARM (accepted at about +8.04 s and +8.55 s) and a status probe reported `armed`. A timed-out command can commit after the client gives up. Observed for ARM only; STOP uses the same path but was not exercised.
- While the lock was held, `status`/`authorize` blocked (client-side timeouts, i.e. denial). No wrongful ALLOW was observed.

## Unconfirmed
- Run 5 (third failure): same state signature (`anchor.json.tmp` present, no `anchor.json`/`store.json`, probe also timed out) but the stalled call never logged completion, so its fsync stall is NOT directly proven.
- The cause of the ~8 s I/O stall (ext4 journal, writeback, virtualised disk, host) is UNKNOWN; no strace or kernel/block metrics were captured.
- Not measured: accept/queue time before handler entry. n=10, so the 3/10 rate is only an estimate; instrumentation may have perturbed timing.
- Supervisor-side behaviour on real Linux/Lab-01 hardware is unverified.
