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
OUT_CSV = ROOT / "gv_jerk_geometry.csv"
OUT_PNG = ROOT / "gv_jerk_geometry.png"


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

    accel_trace: List[float] = []
    var_trace: List[float] = []
    ever_warning = False
    ever_irrecoverable = False

    for step in range(steps):
        values = evolve(values, gain, noise)

        if delay == 0 or step % max(delay, 1) == 0:
            values = mix_ws_partial(values, p_mix=p_mix)

        out = sentinel.update(values)

        var_trace.append(out.variance_value)
        accel_trace.append(out.variance_acceleration)

        if out.status == "warning":
            ever_warning = True
        if out.status == "irrecoverable":
            ever_irrecoverable = True

    jerk_series: List[float] = []
    if len(accel_trace) >= 2:
        for i in range(1, len(accel_trace)):
            jerk_series.append(accel_trace[i] - accel_trace[i - 1])

    max_jerk = max(jerk_series) if jerk_series else 0.0
    min_jerk = min(jerk_series) if jerk_series else 0.0
    jerk_span = max_jerk - min_jerk if jerk_series else 0.0
    mean_abs_jerk = sum(abs(x) for x in jerk_series) / len(jerk_series) if jerk_series else 0.0

    if ever_irrecoverable:
        phase = "IRRECOVERABLE"
        phase_code = 3
    elif ever_warning:
        phase = "SOFT"
        phase_code = 2
    else:
        phase = "RECOVERABLE"
        phase_code = 1

    return {
        "gain": round(gain, 3),
        "delay": int(delay),
        "p_mix": round(p_mix, 2),
        "phase": phase,
        "phase_code": phase_code,
        "max_jerk": round(max_jerk, 6),
        "min_jerk": round(min_jerk, 6),
        "jerk_span": round(jerk_span, 6),
        "mean_abs_jerk": round(mean_abs_jerk, 6),
        "final_variance": round(var_trace[-1] if var_trace else 0.0, 6),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = [
        "gain",
        "delay",
        "p_mix",
        "phase",
        "phase_code",
        "max_jerk",
        "min_jerk",
        "jerk_span",
        "mean_abs_jerk",
        "final_variance",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def matrix(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float], key: str, target_gain: float) -> List[List[float]]:
    lookup = {
        (r["delay"], r["p_mix"], r["gain"]): r[key]
        for r in rows
    }
    mat: List[List[float]] = []
    for p in pmixes:
        row = []
        for d in delays:
            row.append(float(lookup[(d, round(p, 2), round(target_gain, 3))]))
        mat.append(row)
    return mat


def cliff_lookup(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float]) -> List[List[float]]:
    mat: List[List[float]] = []
    for p in pmixes:
        row = []
        for d in delays:
            subset = sorted(
                [r for r in rows if r["delay"] == d and abs(r["p_mix"] - round(p, 2)) < 1e-9],
                key=lambda x: x["gain"],
            )
            cliff = None
            for r in subset:
                if r["phase_code"] >= 3:
                    cliff = r["gain"]
                    break
            row.append(float("nan") if cliff is None else float(cliff))
        mat.append(row)
    return mat


def plot_maps(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float], path: Path) -> None:
    target_gain = 1.04 if 1.04 in gains else gains[len(gains) // 2]
    jerk_mat = matrix(rows, delays, pmixes, gains, "mean_abs_jerk", target_gain)
    span_mat = matrix(rows, delays, pmixes, gains, "jerk_span", target_gain)
    cliff_mat = cliff_lookup(rows, delays, pmixes, gains)

    fig = plt.figure(figsize=(12, 13))

    ax1 = fig.add_subplot(3, 1, 1)
    im1 = ax1.imshow(
        cliff_mat,
        aspect="auto",
        origin="lower",
        extent=[min(delays), max(delays), min(pmixes), max(pmixes)],
    )
    ax1.set_title("GV Cliff Surface")
    ax1.set_xlabel("Async delay")
    ax1.set_ylabel("Coupling p_mix")
    fig.colorbar(im1, ax=ax1, shrink=0.9)

    ax2 = fig.add_subplot(3, 1, 2)
    im2 = ax2.imshow(
        jerk_mat,
        aspect="auto",
        origin="lower",
        extent=[min(delays), max(delays), min(pmixes), max(pmixes)],
    )
    ax2.set_title(f"Mean |jerk| at gain={target_gain}")
    ax2.set_xlabel("Async delay")
    ax2.set_ylabel("Coupling p_mix")
    fig.colorbar(im2, ax=ax2, shrink=0.9)

    ax3 = fig.add_subplot(3, 1, 3)
    im3 = ax3.imshow(
        span_mat,
        aspect="auto",
        origin="lower",
        extent=[min(delays), max(delays), min(pmixes), max(pmixes)],
    )
    ax3.set_title(f"Jerk span at gain={target_gain}")
    ax3.set_xlabel("Async delay")
    ax3.set_ylabel("Coupling p_mix")
    fig.colorbar(im3, ax=ax3, shrink=0.9)

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
    plot_maps(rows, delays, pmixes, gains, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)

    print("\\nJerk summary at gain=1.04:")
    for delay in delays:
        print(f"delay={delay}")
        for p_mix in pmixes:
            hit = next(
                r for r in rows
                if r["delay"] == delay and abs(r["p_mix"] - round(p_mix, 2)) < 1e-9 and abs(r["gain"] - 1.04) < 1e-9
            )
            print(
                f"  p_mix={p_mix:.2f} -> phase={hit['phase']}, "
                f"mean_abs_jerk={hit['mean_abs_jerk']}, jerk_span={hit['jerk_span']}"
            )


if __name__ == "__main__":
    main()
