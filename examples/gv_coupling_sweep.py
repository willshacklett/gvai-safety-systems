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
OUT_CSV = ROOT / "gv_coupling_sweep.csv"
OUT_PNG = ROOT / "gv_coupling_sweep.png"


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
    last_var = 0.0

    for step in range(steps):
        values = evolve(values, gain, noise)

        if delay == 0 or step % max(delay, 1) == 0:
            values = mix_ws_partial(values, p_mix=p_mix)

        out = sentinel.update(values)

        last_var = out.variance_value
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
        "final_variance": round(last_var, 6),
    }


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


def phase_matrix(rows: List[dict], gains: List[float], pmixes: List[float], delay: int) -> List[List[float]]:
    lookup = {
        (r["p_mix"], r["gain"]): r["phase_code"]
        for r in rows
        if r["delay"] == delay
    }
    mat = []
    for p in pmixes:
        row = []
        for g in gains:
            row.append(float(lookup[(round(p, 2), round(g, 3))]))
        mat.append(row)
    return mat


def first_irrecoverable_gain(rows: List[dict], delay: int, p_mix: float, gains: List[float]):
    subset = {
        r["gain"]: r["phase_code"]
        for r in rows
        if r["delay"] == delay and abs(r["p_mix"] - round(p_mix, 2)) < 1e-9
    }
    for g in gains:
        if subset.get(round(g, 3), 0) >= 3:
            return round(g, 3)
    return None


def plot_maps(rows: List[dict], gains: List[float], pmixes: List[float], delays: List[int], path: Path) -> None:
    fig = plt.figure(figsize=(12, 12))

    for idx, delay in enumerate(delays, start=1):
        ax = fig.add_subplot(len(delays), 1, idx)
        mat = phase_matrix(rows, gains, pmixes, delay)
        im = ax.imshow(
            mat,
            aspect="auto",
            origin="lower",
            extent=[min(gains), max(gains), min(pmixes), max(pmixes)],
        )
        ax.set_title(f"Delay = {delay}")
        ax.set_xlabel("Gain")
        ax.set_ylabel("Coupling p_mix")
        fig.colorbar(im, ax=ax, shrink=0.85)

    plt.tight_layout()
    plt.savefig(path, dpi=180)
    plt.close()


def main() -> None:
    gains = [1.00, 1.02, 1.04, 1.06, 1.08]
    pmixes = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    delays = [0, 2, 3, 5]

    rows: List[dict] = []
    for delay in delays:
        for p_mix in pmixes:
            for gain in gains:
                rows.append(run_case(gain=gain, delay=delay, p_mix=p_mix))

    write_csv(rows, OUT_CSV)
    plot_maps(rows, gains, pmixes, delays, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("\nIrreversible boundary by delay and coupling:")
    for delay in delays:
        print(f"\nDelay={delay}")
        for p_mix in pmixes:
            boundary = first_irrecoverable_gain(rows, delay, p_mix, gains)
            print(f"  p_mix={p_mix:.2f} -> cliff={boundary}")


if __name__ == "__main__":
    main()
