
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


def run(delay: int, n: int = 8, steps: int = 30):
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
        )
    )

    first_trigger = None

    for step in range(steps):
        values = delayed_update(values, buffers)

        out = sentinel.update(node_values=values)

        if out.recommended_action != "none" and first_trigger is None:
            first_trigger = step

        if out.recommended_action != "none":
            intervention = apply_action(out.recommended_action, values)
            values = intervention.after

    return first_trigger, out.status


def main():
    print("=== ASYNC LATENCY SWEEP ===\n")

    for d in [3, 6, 10, 15]:
        trigger, status = run(d)

        print(f"delay={d}")
        print(f" first_action_step={trigger}")
        print(f" final_status={status}")
        print("")

if __name__ == "__main__":
    main()
