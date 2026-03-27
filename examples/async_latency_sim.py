
from __future__ import annotations
import random
from typing import List, Sequence
from gvai.sentinel import GVSentinel
from gvai.interventions import apply_action

# -----------------------------
# Simulate async propagation lag
# -----------------------------

def delayed_update(values: Sequence[float], delay_buffer: List[List[float]], gain=1.3):
    new_vals = []
    for i, v in enumerate(values):
        history = delay_buffer[i]
        source = history.pop(0)
        history.append(v)

        mu = sum(values) / len(values)
        updated = mu + (source - mu) * gain
        new_vals.append(updated)

    return new_vals

# -----------------------------
# Run simulation
# -----------------------------

def run_async_sim(n=8, steps=25, delay=3):
    values = [1.0 + random.uniform(-0.1, 0.1) for _ in range(n)]
    buffers = [[v]*delay for v in values]

    sentinel = GVSentinel()

    print("=== ASYNC LATENCY SIM ===")
    print(f"delay={delay}\n")

    for step in range(steps):
        values = delayed_update(values, buffers)

        out = sentinel.step(values)

        if out.action:
            values, note = apply_action(values, out.action)
            print(f"[STEP {step}] ACTION: {out.action} | {note}")

        print(
            f"[STEP {step}] var={out.variance_value:.4f} "
            f"Δt={out.delta_t} status={out.status}"
        )

if __name__ == "__main__":
    run_async_sim()
