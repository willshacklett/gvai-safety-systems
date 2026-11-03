# STOP journal hardening - regression comparison

Baseline 7c7106e vs hardening 851b384. Isolated detached worktrees, 6 interleaved sequential full-suite runs each
(`python -m pytest -p no:cacheprovider -q -rf tests/`, same venv, 2-core host, no PYTHONPATH). Logs: base_N.txt, hard_N.txt.

| Run | Base (exit, failed/passed/skipped) | Hardening |
|---|---|---|
| 1 | 1, 9/695/20 | 1, 3/729/20 |
| 2 | 1, 1/703/20 | 0, 0/732/20 |
| 3 | 0, 0/704/20 | 1, 1/731/20 |
| 4 | 1, 2/702/20 | 1, 3/729/20 |
| 5 | 0, 0/704/20 | 1, 3/729/20 |
| 6 | 1, 3/701/20 | 1, 2/730/20 |

Clean runs: base 2/6, hardening 1/6. Failing-test occurrences: base 15, hardening 12.
All failures in both: tests/test_experimental_external_gate.py (base 10, hard 12) and
tests/test_stop_gate_resilience.py (base 5, hard 0). Zero failures in tests/test_stop_generation_journal.py (109 tests).
Every inspected failure is `communication_failure` from Deployment.arm()/stop() (gate control socket, 2.0 s poll timeout,
gvai/experimental_external_gate.py:683-706) at test setup, i.e. a DENY, not a wrongful ALLOW.

Conclusion: same failure class and file on both commits, rate not distinguishable at n=6 (no significance).
No journal-attributable failure. NOT declared regression-free: the gate flakiness is unfixed, unexplained at root
cause, and the sample is too small to exclude a modest rate difference. The journal is not imported by the gate.
