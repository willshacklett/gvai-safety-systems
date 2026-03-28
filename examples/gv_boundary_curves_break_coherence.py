from __future__ import annotations

import random
from statistics import mean

from gvai.sentinel import GVSentinel, SentinelConfig


def init_vals(n: int = 8):
    return [1.0] + [random.uniform(0.8, 1.2) for _ in range(n - 1)]


def evolve(values, gain, noise):
    mu = mean(values)
    return [mu + (v - mu) * gain + random.uniform(-noise, noise) for v in values]


def variance(values):
    mu = mean(values)
    return sum((v - mu) ** 2 for v in values) / len(values)


# controlled partial coupling
def mix_ws_partial(values, p_mix: float = 0.35):
    out = values[:]
    n = len(values)
    for i in range(n):
        if random.random() < p_mix:
            avg = (values[(i + 1) % n] + values[(i + 2) % n]) / 2.0
            out[i] = 0.75 * values[i] + 0.25 * avg
    return out


def run_case(gain, delay, noise: float = 0.05, steps: int = 60):
    random.seed(42)

    cfg = SentinelConfig(
        auto_apply=False,
        variance_threshold=0.05,
        collapse_threshold=0.20,
        variance_velocity_threshold=0.01,
        variance_acceleration_threshold=0.015,
        dt_stagnation_threshold=0.005,
    )
    sentinel = GVSentinel(cfg)

    values = init_vals()

    ever_warning = False
    ever_critical = False
    ever_irrecoverable = False

    for step in range(steps):
        values = evolve(values, gain, noise)

        # async delay / partial rewiring
        if delay == 0 or step % max(delay, 1) == 0:
            values = mix_ws_partial(values, p_mix=0.35)

        out = sentinel.update(values)

        if out.status == "warning":
            ever_warning = True
        if out.status == "critical":
            ever_critical = True
        if out.status == "irrecoverable":
            ever_irrecoverable = True

    if ever_irrecoverable or ever_critical:
        return "IRRECOVERABLE"
    if ever_warning:
        return "SOFT"
    return "RECOVERABLE"


def main():
    print("\\n=== BREAK COHERENCE (CONTROLLED) ===")

    for delay in [0, 1, 2, 3, 4, 5]:
        print(f"\\n--- delay={delay} ---")
        for g in [1.00, 1.02, 1.04, 1.06, 1.08]:
            result = run_case(g, delay)
            print(f"g={g:.2f} -> {result}")


if __name__ == "__main__":
    main()
