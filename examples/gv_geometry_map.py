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
OUT_CSV = ROOT / "gv_geometry_map.csv"
OUT_PNG = ROOT / "gv_geometry_map.png"


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

    accel_trace: List[float] = []
    var_trace: List[float] = []

    for step in range(1, steps + 1):
        values = delayed_update(values, buffers, gain=gain, noise=noise)

        if step > 10:
            values = mix_ws(values)

        out = sentinel.update(values)

        var_trace.append(out.variance_value)
        accel_trace.append(out.variance_acceleration)

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

    jerk_proxy = 0.0
    if len(accel_trace) >= 3:
        jerk_series = [accel_trace[i] - accel_trace[i - 1] for i in range(1, len(accel_trace))]
        jerk_proxy = max(abs(x) for x in jerk_series) if jerk_series else 0.0

    final_var = var_trace[-1] if var_trace else 0.0
    max_accel = max(accel_trace) if accel_trace else 0.0

    return {
        "gain": round(gain, 3),
        "delay": delay,
        "phase": phase,
        "phase_code": phase_code,
        "final_variance": round(final_var, 6),
        "max_acceleration": round(max_accel, 6),
        "jerk_proxy": round(jerk_proxy, 6),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = [
        "gain",
        "delay",
        "phase",
        "phase_code",
        "final_variance",
        "max_acceleration",
        "jerk_proxy",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def make_phase_matrix(rows: List[dict], gains: List[float], delays: List[int], key: str) -> List[List[float]]:
    lookup = {(r["delay"], r["gain"]): r[key] for r in rows}
    mat: List[List[float]] = []
    for d in delays:
        row = []
        for g in gains:
            row.append(float(lookup[(d, round(g, 3))]))
        mat.append(row)
    return mat


def make_boundary_trace(rows: List[dict], delays: List[int], gains: List[float]) -> List[Optional[float]]:
    lookup = {(r["delay"], r["gain"]): r["phase_code"] for r in rows}
    boundary: List[Optional[float]] = []
    for d in delays:
        hit = None
        for g in gains:
            if lookup[(d, round(g, 3))] >= 3:
                hit = g
                break
        boundary.append(hit)
    return boundary


def plot_maps(rows: List[dict], gains: List[float], delays: List[int], path: Path) -> None:
    phase_mat = make_phase_matrix(rows, gains, delays, "phase_code")
    jerk_mat = make_phase_matrix(rows, gains, delays, "jerk_proxy")
    boundary = make_boundary_trace(rows, delays, gains)

    fig = plt.figure(figsize=(11, 10))

    ax1 = fig.add_subplot(2, 1, 1)
    im1 = ax1.imshow(
        phase_mat,
        aspect="auto",
        origin="lower",
        extent=[min(gains), max(gains), min(delays), max(delays)],
    )
    ax1.set_title("GV Phase Map (gain × async delay)")
    ax1.set_xlabel("Gain")
    ax1.set_ylabel("Delay")
    ax1.plot(
        [b for b in boundary if b is not None],
        [d for b, d in zip(boundary, delays) if b is not None],
        marker="o",
        linewidth=1,
        label="Irreversible boundary",
    )
    ax1.legend()
    fig.colorbar(im1, ax=ax1, shrink=0.9)

    ax2 = fig.add_subplot(2, 1, 2)
    im2 = ax2.imshow(
        jerk_mat,
        aspect="auto",
        origin="lower",
        extent=[min(gains), max(gains), min(delays), max(delays)],
    )
    ax2.set_title("Jerk Proxy Map (fold / ridge detector)")
    ax2.set_xlabel("Gain")
    ax2.set_ylabel("Delay")
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

    print("\nBoundary trace:")
    by_delay = {}
    for r in rows:
        by_delay.setdefault(r["delay"], []).append(r)
    for d in delays:
        ordered = sorted(by_delay[d], key=lambda x: x["gain"])
        boundary = next((r["gain"] for r in ordered if r["phase"] == "IRRECOVERABLE"), None)
        print(f"delay={d}: boundary={boundary}")


if __name__ == "__main__":
    main()
