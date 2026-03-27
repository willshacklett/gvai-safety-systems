from __future__ import annotations

import random
from statistics import mean

from gvai.sentinel import GVSentinel, SentinelConfig


def evolve(values, gain, noise):
    mu = mean(values)
    return [
        mu + (v - mu) * gain + random.uniform(-noise, noise)
        for v in values
    ]


def init_vals(n=8):
    return [1.0] + [random.uniform(0.8, 1.2) for _ in range(n - 1)]


def mix_ws(values):
    out = values[:]
    n = len(values)
    for i in range(n):
        avg = (values[(i + 1) % n] + values[(i + 2) % n]) / 2
        out[i] = 0.7 * values[i] + 0.3 * avg
    return out


def run_case(gain, noise):
    random.seed(42)

    cfg = SentinelConfig(auto_apply=True)
    sentinel = GVSentinel(cfg)

    values = init_vals()

    ever_dt_positive = False
    ever_action = False
    ever_critical = False

    for step in range(1, 31):
        values = evolve(values, gain, noise)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

        if out.delta_t_estimate is not None and out.delta_t_estimate > 0:
            ever_dt_positive = True

        if out.recommended_action != "none":
            ever_action = True

        if out.status == "critical":
            ever_critical = True

    if ever_critical and not ever_dt_positive:
        return "IRRECOVERABLE"

    if ever_dt_positive or ever_action:
        return "RECOVERABLE"

    return "SOFT"


def main():
    print("=== LOW BOUNDARY SWEEP ===")

    gains = [1.05, 1.10, 1.15, 1.20, 1.25]
    noises = [0.03, 0.05, 0.08]

    for g in gains:
        for n in noises:
            result = run_case(g, n)
            print(f"gain={g:.2f}, noise={n:.2f} -> {result}")


if __name__ == "__main__":
    main()
