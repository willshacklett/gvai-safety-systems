# STOP generation journal: regression comparison evidence (2026-11-03)

Evidence only. No application code, tests, or gate timeouts were changed to produce it.

## Compared commits
- Baseline: `7c7106ef943330cdc81c21b790f71d658177982f` (journal V1)
- Hardening: `851b384eb9314ac67392d391f9b6920c5c25234e` (journal_id / validity window / StopAck; WIP, unverified)

## Method and environment
Each commit in its own detached git worktree. Six sequential full-suite runs per commit, interleaved
(baseline then hardening), command `python -m pytest -p no:cacheprovider -q -rf tests/`, Python 3.12.3,
pytest 9.2.0, shared venv, 2-core Linux cloud host (Copilot Cloud; **not** Lab-01, no live services).
Files: `base_N.txt` / `hard_N.txt` (full pytest output), `*.exit` (exit codes), `REPORT.md` (summary).

## Result
- Zero failures in `tests/test_stop_generation_journal.py` on either commit.
- Failures on both commits are in `tests/test_experimental_external_gate.py` (and, on baseline,
  `tests/test_stop_gate_resilience.py`), almost all `communication_failure` at test setup (2.0 s control-client timeout).
  These are denies, not wrongful allows.
- Clean full runs: baseline 2/6, hardening 1/6. n=6 cannot distinguish the rates.

## Conclusion
**Existing gate flakiness remains unresolved and its root cause is not established.** The hardening is
not shown to introduce a regression, but it is **not declared regression-free**. This evidence supports no
enforcement or production-readiness claim.
