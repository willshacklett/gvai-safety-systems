# Diagnostic experiment: communication_failure (2026-11-03)

Commit 6f922c0 in detached worktree /tmp/wt_diag (clean). Test: test_armed_operation_executes_through_gate,
30 sequential fresh-process repetitions, idle host (2 cores), no CPU stress, no timeout or code changes.
Instrumentation: out-of-tree pytest plugin /tmp/diag/diagplugin.py (client-side phase timing, outcome classification,
post-failure status/state probe, process exit/cleanup record). Gate/backend internals not instrumented.

Results: 30/30 passed (all exit 0). 120 client requests, all outcome=ok.
Latency (total, s): control command (gc.sock) 0.0053 / 0.0066 / 0.0099 (min/median/max);
authorize (g.sock) 0.0006 / 0.0016 / 0.0025; backend (b.sock) 0.0002 / 0.0006 / 0.0022.
Connection errors 0, response timeouts 0, decode errors 0, failed-arm state probes 0 (nothing to probe).
Cleanup: 30/30 gate and backend alive until teardown, killed (exit -9), none alive after, temp dirs removed.

Conclusion: the failure did NOT reproduce. The typical first-command latency is ~7 ms, ~300x below the 2.0 s budget,
so the intermittent failures are not a steady-state slowness; they need a rare stall or contention. This run cannot
confirm or exclude any ranked hypothesis, and gives no evidence about whether a timed-out command applies.
