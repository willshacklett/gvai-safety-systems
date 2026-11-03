# Gate timing diagnostic (2026-11-03)

Evidence from a 30-repetition diagnostic of intermittent `communication_failure` in the experimental external STOP gate.

- Code under test: commit `6f922c0d56d62e08ce41639aa78845c1abd26a9b` (detached, clean temporary worktree).
- Test: `tests/test_experimental_external_gate.py::test_armed_operation_executes_through_gate`, 30 sequential runs, one fresh pytest process each.
- Environment: Linux 6.12.8+, 2 cores, Python 3.12.3, pytest 9.2.0, idle host. No CPU stress, no timeout or application changes.
- Instrumentation: out-of-tree pytest plugin (client-side connect/send/wait/decode timing and outcome classification; process exit and cleanup record). The plugin is not included in this directory.

## Result

30/30 runs passed (all exit 0); 120 client requests, all `ok`. **The intermittent failure was NOT reproduced.**
See `REPORT.md` for latency figures. `events.jsonl` has per-request timings; `pytest_N.txt`/`pytest_N.exit` are per-run output and exit codes.

## Not verified

- **Supervisor (gate/backend) internal timing** was not instrumented; only client-side timing was captured.
- **Post-timeout state transitions** (whether a timed-out command is applied anyway) remain unverified, since no timeout occurred.
- No root cause is established; the earlier ranked hypotheses are neither confirmed nor excluded.
- Gate flakiness remains unresolved; passing here does not show the hardening commits are regression-free.

Files are byte-for-byte copies of the temporary evidence (sha256 verified at copy time).
