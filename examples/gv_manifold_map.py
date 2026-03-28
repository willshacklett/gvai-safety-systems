from __future__ import annotations

import csv
import os
import random
import sys
from pathlib import Path
from statistics import mean
from typing import List

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import matplotlib.pyplot as plt

from gvai.sentinel import GVSentinel, SentinelConfig


ROOT = Path(__file__).resolve().parent
OUT_CSV = ROOT / "gv_manifold_map.csv"
OUT_PNG = ROOT / "gv_manifold_map.png"


def init_vals(n: int = 8) -> List[float]:
    return [1.0] + [random.uniform(0.8, 1.2) for _ in range(n - 1)]


def evolve(values: List[float], gain: float, noise: float) -> List[float]:
    mu = mean(values)
    return [mu + (v - mu) * gain + random.uniform(-noise, noise) for v in values]


def mix_ws_partial(values: List[float], p_mix: float) -> List[float]:
    out = values[:]
    n = len(values)
    for i in range(n):
        if random.random() < p_mix:
            avg = (values[(i + 1) % n] + values[(i + 2) % n]) / 2.0
            out[i] = 0.75 * values[i] + 0.25 * avg
    return out


def run_case(gain: float, delay: int, p_mix: float, noise: float = 0.05, steps: int = 60):
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

    accel_trace = []
    ever_warning = False
    ever_irrecoverable = False

    for step in range(steps):
        values = evolve(values, gain, noise)

        if delay == 0 or step % max(delay, 1) == 0:
            values = mix_ws_partial(values, p_mix)

        out = sentinel.update(values)

        accel_trace.append(out.variance_acceleration)

        if out.status == "warning":
            ever_warning = True
        if out.status == "irrecoverable":
            ever_irrecoverable = True

    # JERK
    jerk = []
    for i in range(1, len(accel_trace)):
        jerk.append(accel_trace[i] - accel_trace[i-1])

    mean_abs_jerk = sum(abs(x) for x in jerk) / len(jerk) if jerk else 0.0

    # PHASE
    if ever_irrecoverable:
        phase = 3
    elif ever_warning:
        phase = 2
    else:
        phase = 1

    return phase, mean_abs_jerk


def main():
    gains = [1.00, 1.02, 1.04, 1.06, 1.08]
    delays = list(range(0, 11))
    pmixes = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]

    cliff = []
    jerk_map = []
    soft_mask = []

    for p in pmixes:
        cliff_row = []
        jerk_row = []
        soft_row = []

        for d in delays:
            cliff_gain = None
            jerk_val = 0
            soft = 0

            for g in gains:
                phase, jerk = run_case(g, d, p)

                if g == 1.04:
                    jerk_val = jerk

                if phase == 2:
                    soft = 1

                if phase == 3 and cliff_gain is None:
                    cliff_gain = g

            cliff_row.append(cliff_gain if cliff_gain else 0)
            jerk_row.append(jerk_val)
            soft_row.append(soft)

        cliff.append(cliff_row)
        jerk_map.append(jerk_row)
        soft_mask.append(soft_row)

    fig = plt.figure(figsize=(10, 12))

    # CLIFF
    ax1 = fig.add_subplot(3,1,1)
    im1 = ax1.imshow(cliff, origin='lower', aspect='auto')
    ax1.set_title("Cliff Surface")
    plt.colorbar(im1, ax=ax1)

    # SOFT BAND
    ax2 = fig.add_subplot(3,1,2)
    im2 = ax2.imshow(soft_mask, origin='lower', aspect='auto')
    ax2.set_title("Soft Band (Recoverable Zone)")
    plt.colorbar(im2, ax=ax2)

    # JERK RIDGE
    ax3 = fig.add_subplot(3,1,3)
    im3 = ax3.imshow(jerk_map, origin='lower', aspect='auto')
    ax3.set_title("Jerk Ridge (Fold Structure)")
    plt.colorbar(im3, ax=ax3)

    plt.tight_layout()
    plt.savefig(OUT_PNG, dpi=180)
    plt.close()

    print("Saved:", OUT_PNG)


if __name__ == "__main__":
    main()
