from __future__ import annotations

import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from typing import List, Sequence

from gvai.metrics import variance
from gvai.sentinel import GVSentinel, SentinelConfig


def evolve_unstable(values: Sequence[float], gain: float = 1.35) -> List[float]:
    vals = [float(v) for v in values]
    mu = sum(vals) / len(vals)
    return [mu + (v - mu) * gain for v in vals]


def run_without_intervention(initial: Sequence[float], steps: int = 10) -> None:
    print("=== WITHOUT INTERVENTION (COLLAPSE) ===")
    values = list(initial)

    for step in range(steps):
        var = variance(values)
        print(f"STEP {step}")
        print("VARIANCE:", round(var, 6))
        values = evolve_unstable(values)


def run_with_sentinel(initial: Sequence[float], steps: int = 10) -> None:
    print("\n=== WITH GV SENTINEL (STABILIZATION) ===")
    values = list(initial)

    sentinel = GVSentinel(
        SentinelConfig(
            variance_threshold=0.02,
            drift_slope_threshold=0.001,
            collapse_threshold=0.10,
            auto_apply=True,
            rebalance_strength=0.6,
            damp_strength=0.4,
            isolate_indices=[4, 5],
        )
    )

    for step in range(steps):
        out = sentinel.update(values)

        print(f"STEP {step}")
        print("VARIANCE:", round(out.variance_value, 6))
        print("STATUS:", out.status)
        print("ACTION:", out.recommended_action)
        print("APPLIED:", out.applied)

        if out.applied and out.post_action_values:
            values = out.post_action_values
        else:
            values = evolve_unstable(values)


if __name__ == "__main__":
    initial = [1.0, 1.2, 0.8, 1.3, 1.5, 0.7]

    run_without_intervention(initial)
    run_with_sentinel(initial)
