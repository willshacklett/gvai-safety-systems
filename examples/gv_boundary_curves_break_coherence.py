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
OUT_CSV = ROOT / "gv_boundary_curves_break_coherence.csv"
OUT_PNG = ROOT / "gv_boundary_curves_break_coherence.png"


def init_vals(n: int = 8) -> List[float]:
    return [1.0] + [random.uniform(0.8, 1.2) for _ in range(n - 1)]


def init_gains(base_gain: float, n: int = 8, spread: float = 0.08) -> List[float]:
    return [base_gain + random.uniform(-spread, spread) for _ in range(n)]


def delayed_update(
    values: List[float],
    buffers: List[List[float]],
    gains: List[float],
    noise: float,
    shock_prob: float = 0.18,
) -> List[float]:
    global_mu = mean(values)
    out: List[float] = []

    shock_index = random.randrange(len(values)) if random.random() < shock_prob else None

    for i, v in enumerate(values):
        history = buffers[i]
        source = history.pop(0)
        history.append(float(v))

        # break global coherence: local state still matters
        local_mu = 0.7 * global_mu + 0.3 * v
        g = gains[i]

        updated = local_mu + (source - local_mu) * g + random.uniform(-noise, noise)

        if shock_index is not None and i == shock_index:
            updated += random.uniform(0.2, 0.5)

        out.append(updated)

    return out


def mix_ws_partial(values: List[float], p_mix: float = 0.20) -> List[float]:
    out = values[:]
    n = len(values)
    for i in range(n):
        if random.random() < p_mix:
            avg = (values[(i + 1) % n] + values[(i + 2) % n]) / 2.0
            out[i] = 0.82 * values[i] + 0.18 * avg
    return out


def classify_case(base_gain: float, delay: int, noise: float = 0.05, steps: int = 30) -> dict:
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
    gains = init_gains(base_gain, n=len(values), spread=0.08)
    buffers = [[float(v)] * max(1, delay) for v in values]

    ever_soft = False
    ever_irrecoverable = False
    ever_recoverable = False
    max_accel = 0.0
    max_vel = 0.0
    final_var = 0.0

    for step in range(1, steps + 1):
        values = delayed_update(values, buffers, gains=gains, noise=noise, shock_prob=0.18)

        if step > 10:
            values = mix_ws_partial(values, p_mix=0.20)

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
        "gain": round(base_gain, 3),
        "delay": delay,
        "phase": phase,
        "phase_code": phase_code,
        "final_variance": round(final_var, 6),
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
    fieldnames = ["gain", "delay", "phase", "phase_code", "final_variance", "max_acceleration", "max_velocity"]
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
    ax.set_ylabel("Base gain")
    ax.set_title("GV Boundary Curves with Coherence Breaking")
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
            rows.append(classify_case(base_gain=g, delay=d))

    write_csv(rows, OUT_CSV)
    plot_curves(rows, delays, OUT_PNG)

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("\\nBoundary curves:")
    for d in delays:
        soft = first_gain(rows, d, 2)
        irr = first_gain(rows, d, 3)
        print(f"delay={d}: soft={soft}, irrecoverable={irr}")


if __name__ == "__main__":
    main()
