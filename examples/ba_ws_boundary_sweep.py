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
        avg = (values[(i+1)%n] + values[(i+2)%n]) / 2
        out[i] = 0.7 * values[i] + 0.3 * avg
    return out


def run_case(gain, noise):
    random.seed(42)

    cfg = SentinelConfig(auto_apply=True)
    sentinel = GVSentinel(cfg)

    values = init_vals()

    ever_dt_positive = False

    for step in range(1, 31):
        values = evolve(values, gain, noise)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

        if out.delta_t_estimate and out.delta_t_estimate > 0:
            ever_dt_positive = True

        if out.status == "critical" and (out.delta_t_estimate == 0 or out.delta_t_estimate is None):
            # early irrecoverable signal
            return "IRRECOVERABLE"

    return "RECOVERABLE" if ever_dt_positive else "SOFT"


def main():
    print("=== BOUNDARY SWEEP ===")

    gains = [1.15, 1.20, 1.25, 1.30, 1.35]
    noises = [0.05, 0.08, 0.10, 0.12]

    for g in gains:
        for n in noises:
            result = run_case(g, n)
            print(f"gain={g:.2f}, noise={n:.2f} -> {result}")


if __name__ == "__main__":
    main()
