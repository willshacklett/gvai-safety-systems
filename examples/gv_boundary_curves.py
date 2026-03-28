from __future__ import annotations

import csv
import os
import random
import sys
from pathlib import Path
from statistics import mean
from typing import List, Optional

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import matplotlib.pyplot as plt

from gvai.sentinel import GVSentinel, SentinelConfig


ROOT = Path(__file__).resolve().parent
OUT_CSV = ROOT / "gv_boundary_curves.csv"
OUT_PNG = ROOT / "gv_boundary_curves.png"


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


def classify_case(gain: float, delay: int, noise: float = 0.05, steps: int = 30) -> dict:
    random.seed(42)

    cfg = SentinelConfig(
        auto_apply=True,
        variance_velocity_threshold=0.01,
        variance_acceleration_threshold=0.015,
        dt_stagnation_threshold=0.005,
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

    for step in range(1, steps + 1):
        values = delayed_update(values, buffers, gain=gain, noise=noise)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

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
        "max_acceleration": round(max_accel, 6),
        "max_velocity": round(max_vel, 6),
    }


def first_gain(rows: List[dict], delay: int, minimum_phase_code: int) -> Optional[float]:
    subset = sorted((r for r in rows if r["delay"] == delay), key=lambda x: x["gain"])
    for r in subset:
        if int(r["phase_code"]) >= minimum_phase_code:
            return float(r["gain"])
    return None


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = ["gain", "delay", "phase", "phase_code", "max_acceleration", "max_velocity"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def plot_curves(rows: List[dict], delays: List[int], path: Path) -> None:
    soft_boundary = [first_gain(rows, d, 2) for d in delays]
    irr_boundary = [first_gain(rows, d, 3) for d in delays]

    fig = plt.figure(figsize=(10, 6))
    ax = fig.add_subplot(1, 1, 1)

    soft_x = [d for d, g in zip(delays, soft_boundary) if g is not None]
    soft_y = [g for g in soft_boundary if g is not None]
    irr_x = [d for d, g in zip(delays, irr_boundary) if g is not None]
    irr_y = [g for g in irr_boundary if g is not None]

    if soft_x:
        ax.plot(soft_x, soft_y, marker="o", linewidth=2, label="Soft-band onset")
    if irr_x:
        ax.plot(irr_x, irr_y, marker="x", linewidth=2, label="Irreversible cliff")

    ax.set_xlabel("Async delay")
    ax.set_ylabel("Gain")
    ax.set_title("GV Boundary Curves: soft band vs irreversible cliff")
    ax.legend()
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def main() -> None:
    gains = [round(x, 3) for x in [
        1.00, 1.005, 1.01, 1.015, 1.02, 1.03, 1.04, 1.05, 1.06, 1.07, 1.08, 1.09, 1.10
    ]]
    delays = list(range(0, 11))

    rows: List[dict] = []
    for d in delays:
        for g in gains:
            rows.append(classify_case(gain=g, delay=d))

    write_csv(rows, OUT_CSV)
    plot_curves(rows, delays, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("\nBoundary curves:")
    for d in delays:
        soft = first_gain(rows, d, 2)
        irr = first_gain(rows, d, 3)
        print(f"delay={d}: soft={soft}, irrecoverable={irr}")


if __name__ == "__main__":
    main()
