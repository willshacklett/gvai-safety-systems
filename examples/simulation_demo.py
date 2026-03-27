from __future__ import annotations

from typing import List, Sequence

from gvai.interventions import apply_action
from gvai.metrics import variance
from gvai.sentinel import GVSentinel, SentinelConfig


def evolve_unstable(values: Sequence[float], gain: float = 1.18) -> List[float]:
    """
    Push values away from the mean to simulate unstable divergence.
    """
    vals = [float(v) for v in values]
    mu = sum(vals) / len(vals)
    return [mu + (v - mu) * gain for v in vals]


def load_from_values(values: Sequence[float]) -> List[float]:
    """
    Simple synthetic load proxy derived from node values.
    """
    return [10.0 + max(0.0, (v - 1.0) * 20.0) for v in values]


def latency_from_values(values: Sequence[float]) -> List[float]:
    """
    Simple synthetic latency proxy derived from node values.
    """
    return [100.0 + max(0.0, (v - 1.0) * 60.0) for v in values]


def run_without_intervention(initial: Sequence[float], steps: int = 8) -> None:
    print("=== WITHOUT INTERVENTION ===")
    values = list(initial)

    for step in range(steps):
        var = variance(values)
        print(f"STEP {step}")
        print("VALUES:", [round(v, 6) for v in values])
        print("VARIANCE:", round(var, 6))
        print("-")

        values = evolve_unstable(values, gain=1.18)


def run_with_sentinel(initial: Sequence[float], steps: int = 8) -> None:
    print("\n=== WITH GV SENTINEL AUTO-APPLY ===")
    values = list(initial)

    sentinel = GVSentinel(
        SentinelConfig(
            variance_threshold=0.05,
            drift_slope_threshold=0.001,
            collapse_threshold=0.20,
            critical_delta_t=3.0,
            warning_delta_t=8.0,
            auto_apply=True,
            rebalance_strength=0.50,
            damp_strength=0.35,
            isolate_indices=[4, 5],
        )
    )

    for step in range(steps):
        load_values = load_from_values(values)
        latency_values = latency_from_values(values)

        out = sentinel.update(
            node_values=values,
            load_values=load_values,
            latency_values=latency_values,
        )

        print(f"STEP {step}")
        print("VALUES:", [round(v, 6) for v in values])
        print("VARIANCE:", round(out.variance_value, 6))
        print("STATUS:", out.status)
        print("DELTA_T:", None if out.delta_t_estimate is None else round(out.delta_t_estimate, 6))
        print("ACTION:", out.recommended_action)
        print("APPLIED:", out.applied)
        print("EVENTS:", [e.event_type for e in out.events])

        if out.applied and out.post_action_values is not None:
            values = list(out.post_action_values)
            print("POST ACTION VALUES:", [round(v, 6) for v in values])
        else:
            values = evolve_unstable(values, gain=1.18)

        print("-")


if __name__ == "__main__":
    initial = [1.00, 1.15, 0.90, 1.22, 1.35, 0.82]

    run_without_intervention(initial, steps=8)
    run_with_sentinel(initial, steps=8)
