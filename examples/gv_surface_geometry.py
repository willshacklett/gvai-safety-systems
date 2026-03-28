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
OUT_CSV = ROOT / "gv_surface_geometry.csv"
OUT_PNG = ROOT / "gv_surface_geometry.png"


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


def run_case(gain: float, delay: int, p_mix: float, noise: float = 0.05, steps: int = 60) -> dict:
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
    ever_recoverable = False

    max_accel = 0.0
    max_vel = 0.0
    final_var = 0.0

    for step in range(steps):
        values = evolve(values, gain, noise)

        if delay == 0 or step % max(delay, 1) == 0:
            values = mix_ws_partial(values, p_mix=p_mix)

        out = sentinel.update(values)

        final_var = out.variance_value
        max_accel = max(max_accel, out.variance_acceleration)
        max_vel = max(max_vel, out.variance_velocity)

        if out.status == "warning":
            ever_warning = True
        if out.status == "critical":
            ever_critical = True
        if out.status == "irrecoverable":
            ever_irrecoverable = True
        if out.delta_t_estimate is not None and out.delta_t_estimate > 0:
            ever_recoverable = True

    if ever_irrecoverable or ever_critical:
        phase = "IRRECOVERABLE"
        phase_code = 3
    elif ever_warning:
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
        "delay": int(delay),
        "p_mix": round(p_mix, 2),
        "phase": phase,
        "phase_code": phase_code,
        "max_acceleration": round(max_accel, 6),
        "max_velocity": round(max_vel, 6),
        "final_variance": round(final_var, 6),
    }


def first_irrecoverable_gain(rows: List[dict], delay: int, p_mix: float, gains: List[float]) -> Optional[float]:
    subset = {
        r["gain"]: r["phase_code"]
        for r in rows
        if r["delay"] == delay and abs(r["p_mix"] - round(p_mix, 2)) < 1e-9
    }
    for g in gains:
        if subset.get(round(g, 3), 0) >= 3:
            return round(g, 3)
    return None


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = [
        "gain",
        "delay",
        "p_mix",
        "phase",
        "phase_code",
        "max_acceleration",
        "max_velocity",
        "final_variance",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def cliff_matrix(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float]) -> List[List[float]]:
    mat: List[List[float]] = []
    for p in pmixes:
        row = []
        for d in delays:
            cliff = first_irrecoverable_gain(rows, d, p, gains)
            row.append(float("nan") if cliff is None else cliff)
        mat.append(row)
    return mat


def accel_matrix(rows: List[dict], delays: List[int], pmixes: List[float]) -> List[List[float]]:
    mat: List[List[float]] = []
    for p in pmixes:
        row = []
        for d in delays:
            subset = [
                r["max_acceleration"]
                for r in rows
                if r["delay"] == d and abs(r["p_mix"] - round(p, 2)) < 1e-9
            ]
            row.append(max(subset) if subset else 0.0)
        mat.append(row)
    return mat


def plot_surface(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float], path: Path) -> None:
    cliff = cliff_matrix(rows, delays, pmixes, gains)
    accel = accel_matrix(rows, delays, pmixes)

    fig = plt.figure(figsize=(12, 10))

    ax1 = fig.add_subplot(2, 1, 1)
    im1 = ax1.imshow(
        cliff,
        aspect="auto",
        origin="lower",
        extent=[min(delays), max(delays), min(pmixes), max(pmixes)],
    )
    ax1.set_title("GV Cliff Surface (irrecoverable boundary gain)")
    ax1.set_xlabel("Async delay")
    ax1.set_ylabel("Coupling p_mix")
    fig.colorbar(im1, ax=ax1, shrink=0.9)

    ax2 = fig.add_subplot(2, 1, 2)
    im2 = ax2.imshow(
        accel,
        aspect="auto",
        origin="lower",
        extent=[min(delays), max(delays), min(pmixes), max(pmixes)],
    )
    ax2.set_title("Acceleration Surface (instability intensity)")
    ax2.set_xlabel("Async delay")
    ax2.set_ylabel("Coupling p_mix")
    fig.colorbar(im2, ax=ax2, shrink=0.9)

    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def main() -> None:
    gains = [1.00, 1.02, 1.04, 1.06, 1.08]
    delays = list(range(0, 11))
    pmixes = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]

    rows: List[dict] = []
    for p_mix in pmixes:
        for delay in delays:
            for gain in gains:
                rows.append(run_case(gain=gain, delay=delay, p_mix=p_mix))

    write_csv(rows, OUT_CSV)
    plot_surface(rows, delays, pmixes, gains, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("\\nCliff surface:")
    for delay in delays:
        print(f"delay={delay}")
        for p_mix in pmixes:
            cliff = first_irrecoverable_gain(rows, delay, p_mix, gains)
            print(f"  p_mix={p_mix:.2f} -> cliff={cliff}")


if __name__ == "__main__":
    main()
