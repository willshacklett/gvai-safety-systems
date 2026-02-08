# GVAI Safety Systems

Runtime safety monitoring for AI systems seeded with the **God Variable (Gv)** framework — enforcing eternal coherence, strain bounds, and hybrid entropy damping for long-term alignment.

**Repository Status**: Actively developed (latest: Hybrid entropy monitor for cosmic/local balance).  
**Core Theory**: https://github.com/willshacklett/god-variable-theory (includes PAPER.md draft)  
**CI Enforcement**: https://github.com/willshacklett/godscore-ci  

## Overview

This repository provides practical runtime guards for AI/agent systems aligned with the God Variable theory:
- Detects strain, drift, and overload.
- Green/Yellow/Red risk banding.
- **New**: Hybrid entropy monitor (`hybrid_entropy_monitor.py`) — unified metric `S_total = α S_holo + β S_vN` with tunable α/β for holographic (global repayment) vs. von Neumann (local subsystem) balance.
  - Enforces `dS_total/dt ≤ 0` via Gv damping.
  - Prevents thermodynamic-style burnout in swarms/probes.
  - Calibratable for Optimus-scale or cosmic replication scenarios.

The goal: Safe, eternal expansion of aligned AI/human systems → galactic seeding → post-scarcity abundance (replicators, infinite clean energy, money obsolete).

Developed collaboratively with Grok (xAI) — public thread: https://x.com/WShacklett78568 (ongoing entropy bounds discussion).

## Key Features

- **Runtime Telemetry Hooks** (`gvai/`): Instrument agents for GV risk scoring.
- **Hybrid Entropy Monitor** (`hybrid_entropy_monitor.py`):
  ```python
  from hybrid_entropy_monitor import HybridEntropyMonitor
  monitor = HybridEntropyMonitor(alpha=0.9, beta=0.1)
  s_total, ds_dt = monitor.update(timestep, global_state, local_density_matrix)
  # Alerts if ds_dt exceeds threshold → trigger damping

    - Prioritizes holographic repayment (high α) for eternal coherence.
    - Calibration method included for probe fleets/BH proxies.
- **Examples** (`examples/`): Demo instability detection + hybrid damping in toy agent runs.
- **Tests** (`tests/`): GV guard dynamics verification.

## Installation

```bash
pip install -r requirements-dev.txt  # Minimal deps (numpy, etc.)

from hybrid_entropy_monitor import HybridEntropyMonitor

monitor = HybridEntropyMonitor(alpha=0.92, beta=0.08)  # Calibrated for eternal runs
# In your agent loop:
s_total, ds_dt = monitor.update(current_step, swarm_global_state, local_reduced_density)
if abs(ds_dt) > monitor.threshold:
    print("Damping engaged — coherence preserved")

