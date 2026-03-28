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
OUT_CSV = ROOT / "gv_alignment_overlay.csv"
OUT_PNG = ROOT / "gv_alignment_overlay.png"


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
    ever_warning = False
    ever_irrecoverable = False
    ever_recoverable = False

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
        if out.delta_t_estimate is not None and out.delta_t_estimate > 0:
            ever_recoverable = True

    jerk = [accel_trace[i] - accel_trace[i - 1] for i in range(1, len(accel_trace))]
    mean_abs_jerk = sum(abs(x) for x in jerk) / len(jerk) if jerk else 0.0

    if ever_irrecoverable:
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
        "mean_abs_jerk": round(mean_abs_jerk, 6),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = ["gain", "delay", "p_mix", "phase", "phase_code", "mean_abs_jerk"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def first_gain(rows: List[dict], delay: int, p_mix: float, minimum_phase_code: int, gains: List[float]) -> Optional[float]:
    subset = {
        r["gain"]: r["phase_code"]
        for r in rows
        if r["delay"] == delay and abs(r["p_mix"] - round(p_mix, 2)) < 1e-9
    }
    for g in gains:
        if subset.get(round(g, 3), 0) >= minimum_phase_code:
            return round(g, 3)
    return None


def ridge_gain(rows: List[dict], delay: int, p_mix: float, gains: List[float]) -> Optional[float]:
    subset = [r for r in rows if r["delay"] == delay and abs(r["p_mix"] - round(p_mix, 2)) < 1e-9]
    if not subset:
        return None
    best = max(subset, key=lambda r: r["mean_abs_jerk"])
    return float(best["gain"])


def plot_overlay(rows: List[dict], delays: List[int], pmixes: List[float], gains: List[float], path: Path) -> None:
    fig = plt.figure(figsize=(12, 14))

    for idx, p in enumerate(pmixes[:4], start=1):
        ax = fig.add_subplot(4, 1, idx)

        soft = [first_gain(rows, d, p, 2, gains) for d in delays]
        cliff = [first_gain(rows, d, p, 3, gains) for d in delays]
        ridge = [ridge_gain(rows, d, p, gains) for d in delays]

        soft_x = [d for d, g in zip(delays, soft) if g is not None]
        soft_y = [g for g in soft if g is not None]
        cliff_x = [d for d, g in zip(delays, cliff) if g is not None]
        cliff_y = [g for g in cliff if g is not None]
        ridge_x = [d for d, g in zip(delays, ridge) if g is not None]
        ridge_y = [g for g in ridge if g is not None]

        if soft_x:
            ax.plot(soft_x, soft_y, marker="o", linewidth=2, label="Soft onset")
        if cliff_x:
            ax.plot(cliff_x, cliff_y, marker="x", linewidth=2, label="Cliff")
        if ridge_x:
            ax.plot(ridge_x, ridge_y, marker="s", linewidth=2, label="Jerk ridge")

        ax.set_title(f"Alignment overlay at coupling p_mix={p:.2f}")
        ax.set_xlabel("Async delay")
        ax.set_ylabel("Gain")
        ax.grid(True, alpha=0.3)
        ax.legend()

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
    plot_overlay(rows, delays, pmixes, gains, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)

    print("\\nAlignment summary:")
    for p in pmixes:
        print(f"\\np_mix={p:.2f}")
        for d in delays:
            soft = first_gain(rows, d, p, 2, gains)
            cliff = first_gain(rows, d, p, 3, gains)
            ridge = ridge_gain(rows, d, p, gains)
            print(f"  delay={d}: ridge={ridge}, soft={soft}, cliff={cliff}")


if __name__ == "__main__":
    main()
