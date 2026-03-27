from __future__ import annotations

import random
from typing import List, Sequence

from gvai.sentinel import GVSentinel, SentinelConfig
from gvai.interventions import apply_action


def delayed_update(values: Sequence[float], delay_buffer: List[List[float]], gain: float = 1.3) -> List[float]:
    new_vals: List[float] = []
    mu = sum(values) / len(values)

    for i, v in enumerate(values):
        history = delay_buffer[i]
        source = history.pop(0)
        history.append(float(v))

        updated = mu + (source - mu) * gain
        new_vals.append(updated)

    return new_vals


def run_async_sim(n: int = 8, steps: int = 25, delay: int = 3) -> None:
    values = [1.0 + random.uniform(-0.1, 0.1) for _ in range(n)]
    buffers = [[float(v)] * delay for v in values]

    sentinel = GVSentinel(
        SentinelConfig(
            variance_threshold=0.02,
            drift_slope_threshold=0.001,
            collapse_threshold=0.10,
            critical_delta_t=3.0,
            warning_delta_t=8.0,
            auto_apply=False,
            rebalance_strength=0.60,
            damp_strength=0.40,
            isolate_indices=[n - 2, n - 1],
        )
    )

    print("=== ASYNC LATENCY SIM ===")
    print(f"delay={delay}\n")

    for step in range(steps):
        values = delayed_update(values, buffers)

        out = sentinel.update(node_values=values)

        if out.recommended_action != "none":
            intervention = apply_action(
                out.recommended_action,
                values,
                rebalance_strength=0.60,
                damp_strength=0.40,
                isolate_indices=[n - 2, n - 1],
            )
            values = intervention.after
            print(f"[STEP {step}] ACTION: {out.recommended_action} | {intervention.note}")

        dt_str = "None" if out.delta_t_estimate is None else f"{out.delta_t_estimate:.4f}"
        print(
            f"[STEP {step}] "
            f"var={out.variance_value:.4f} "
            f"dt={dt_str} "
            f"status={out.status}"
        )


if __name__ == "__main__":
    run_async_sim()
