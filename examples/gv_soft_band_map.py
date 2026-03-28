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
OUT_CSV = ROOT / "gv_soft_band_map.csv"
OUT_PNG = ROOT / "gv_soft_band_map.png"


def evolve(values: List[float], gain: float, noise: float) -> List[float]:
    mu = mean(values)
    return [mu + (v - mu) * gain + random.uniform(-noise, noise) for v in values]


def init_vals(n: int = 8) -> List[float]:
    return [1.0] + [random.uniform(0.8, 1.2) for _ in range(n - 1)]


def mix_ws(values: List[float]) -> List[float]:
    out = values[:]
    n = len(values)
    for i in range(n):
        avg = (values[(i + 1) % n] + values[(i + 2) % n]) / 2.0
        out[i] = 0.7 * values[i] + 0.3 * avg
    return out


def delayed_update(values: List[float], buffers: List[List[float]], gain: float, noise: float) -> List[float]:
    mu = mean(values)
    out: List[float] = []
    for i, v in enumerate(values):
        history = buffers[i]
        source = history.pop(0)
        history.append(float(v))
        updated = mu + (source - mu) * gain + random.uniform(-noise, noise)
        out.append(updated)
    return out


def run_case(gain: float, delay: int, noise: float = 0.05, steps: int = 30) -> dict:
    random.seed(42)

    cfg = SentinelConfig(
        auto_apply=True,
        variance_velocity_threshold=0.02,
        variance_acceleration_threshold=0.015,
        dt_stagnation_threshold=0.01,
        rebalance_strength=0.60,
        damp_strength=0.40,
    )
    sentinel = GVSentinel(cfg)

    values = init_vals()
    buffers = [[float(v)] * max(1, delay) for v in values]

    ever_soft = False
    ever_irrecoverable = False
    ever_recoverable = False
    max_accel = 0.0
    max_vel = 0.0
    final_var = 0.0

    for step in range(1, steps + 1):
        values = delayed_update(values, buffers, gain=gain, noise=noise)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

        final_var = out.variance_value
        max_accel = max(max_accel, out.variance_acceleration)
        max_vel = max(max_vel, out.variance_velocity)

        if out.soft_regime_flag:
            ever_soft = True
        if out.status == "irrecoverable":
            ever_irrecoverable = True
        if out.delta_t_estimate is not None and out.delta_t_estimate > 0:
            ever_recoverable = True

    if ever_irrecoverable:
        phase = "IRRECOVERABLE"
        phase_code = 3
    elif ever_soft:
        phase = "SOFT"
        phase_code = 2
    elif ever_recoverable:
        phase = "RECOVERABLE"
        phase_code = 1
    else:
        phase = "STABLE"
        phase_code = 0

    return {
        "gain": round(gain, 3),
        "delay": delay,
        "phase": phase,
        "phase_code": phase_code,
        "final_variance": round(final_var, 6),
        "max_acceleration": round(max_accel, 6),
        "max_velocity": round(max_vel, 6),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = [
        "gain",
        "delay",
        "phase",
        "phase_code",
        "final_variance",
        "max_acceleration",
        "max_velocity",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def matrix(rows: List[dict], gains: List[float], delays: List[int], key: str) -> List[List[float]]:
    lookup = {(r["delay"], r["gain"]): r[key] for r in rows}
    return [[float(lookup[(d, round(g, 3))]) for g in gains] for d in delays]


def first_phase_gain(rows: List[dict], delay: int, phase_code: int) -> float | None:
    subset = sorted([r for r in rows if r["delay"] == delay], key=lambda x: x["gain"])
    for r in subset:
        if int(r["phase_code"]) >= phase_code:
            return float(r["gain"])
    return None


def plot_maps(rows: List[dict], gains: List[float], delays: List[int], path: Path) -> None:
    phase_mat = matrix(rows, gains, delays, "phase_code")
    accel_mat = matrix(rows, gains, delays, "max_acceleration")

    soft_boundary = [first_phase_gain(rows, d, 2) for d in delays]
    irr_boundary = [first_phase_gain(rows, d, 3) for d in delays]

    fig = plt.figure(figsize=(11, 10))

    ax1 = fig.add_subplot(2, 1, 1)
    im1 = ax1.imshow(
        phase_mat,
        aspect="auto",
        origin="lower",
        extent=[min(gains), max(gains), min(delays), max(delays)],
    )
    ax1.set_title("GV Phase Surface: Cliff to Soft-Band Transition")
    ax1.set_xlabel("Gain")
    ax1.set_ylabel("Async Delay")

    soft_x = [x for x in soft_boundary if x is not None]
    soft_y = [d for x, d in zip(soft_boundary, delays) if x is not None]
    irr_x = [x for x in irr_boundary if x is not None]
    irr_y = [d for x, d in zip(irr_boundary, delays) if x is not None]

    if soft_x:
        ax1.plot(soft_x, soft_y, marker="o", linewidth=1.5, label="Soft-band onset")
    if irr_x:
        ax1.plot(irr_x, irr_y, marker="x", linewidth=1.5, label="Irreversible cliff")

    ax1.legend()
    fig.colorbar(im1, ax=ax1, shrink=0.9)

    ax2 = fig.add_subplot(2, 1, 2)
    im2 = ax2.imshow(
        accel_mat,
        aspect="auto",
        origin="lower",
        extent=[min(gains), max(gains), min(delays), max(delays)],
    )
    ax2.set_title("Acceleration Surface (cliff intensity)")
    ax2.set_xlabel("Gain")
    ax2.set_ylabel("Async Delay")
    fig.colorbar(im2, ax=ax2, shrink=0.9)

    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def main() -> None:
    gains = [round(x, 3) for x in [1.00, 1.02, 1.04, 1.06, 1.07, 1.08]]
    delays = [0, 3, 6, 10, 15]

    rows: List[dict] = []
    for d in delays:
        for g in gains:
            rows.append(run_case(gain=g, delay=d))

    write_csv(rows, OUT_CSV)
    plot_maps(rows, gains, delays, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("\\nBoundaries:")
    for d in delays:
        soft = first_phase_gain(rows, d, 2)
        irr = first_phase_gain(rows, d, 3)
        print(f"delay={d}: soft={soft}, irrecoverable={irr}")


if __name__ == "__main__":
    main()
