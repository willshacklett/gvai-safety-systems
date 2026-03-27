from __future__ import annotations

import random
from statistics import mean

from gvai.sentinel import GVSentinel, SentinelConfig


def variance(vals):
    m = mean(vals)
    return sum((v - m) ** 2 for v in vals) / len(vals)


def evolve_chaotic(values, gain=1.35, noise=0.12):
    mu = mean(values)
    out = []
    for v in values:
        base = mu + (v - mu) * gain
        noisy = base + random.uniform(-noise, noise)
        out.append(noisy)
    return out


def init_ba_like(n=8):
    center = 1.0
    leaves = [random.uniform(0.8, 1.2) for _ in range(n - 1)]
    return [center] + leaves


def mix_ws(values, k=2):
    out = values[:]
    n = len(values)
    for i in range(n):
        neighbors = [(i + j) % n for j in range(1, k + 1)]
        avg = sum(values[j] for j in neighbors) / len(neighbors)
        out[i] = 0.7 * values[i] + 0.3 * avg
    return out


def run():
    random.seed(42)

    cfg = SentinelConfig(
        variance_threshold=0.02,
        drift_slope_threshold=0.001,
        collapse_threshold=0.10,
        critical_delta_t=3.0,
        warning_delta_t=8.0,
        auto_apply=True,
    )

    sentinel = GVSentinel(cfg)

    values = init_ba_like()

    print("=== BA -> WS CHAOS RUN (EDGE TEST) ===")
    print("gain=1.35 noise=0.12\n")

    for step in range(1, 31):
        values = evolve_chaotic(values, gain=1.35, noise=0.12)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

        print(
            f"[STEP {step}] "
            f"var={out.variance_value:.4f} "
            f"dt={out.delta_t_estimate} "
            f"status={out.status} "
            f"action={out.recommended_action}"
        )

    print("\nDone.")


if __name__ == "__main__":
    run()
