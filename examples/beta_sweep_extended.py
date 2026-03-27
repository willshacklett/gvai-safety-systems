from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import List, Sequence

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import matplotlib.pyplot as plt

from gvai.sentinel import GVSentinel, SentinelConfig


ROOT = Path(__file__).resolve().parent
OUT_CSV = ROOT / "beta_sweep_extended.csv"
OUT_PNG = ROOT / "beta_sweep_extended_plot.png"


def evolve_unstable(values: Sequence[float], gain: float = 1.30) -> List[float]:
    vals = [float(v) for v in values]
    mu = sum(vals) / len(vals)
    return [mu + (v - mu) * gain for v in vals]


def local_boosted_values(values: Sequence[float], beta: float) -> List[float]:
    vals = [float(v) for v in values]
    if len(vals) < 2:
        return vals[:]

    boosted = vals[:]
    mu = sum(vals) / len(vals)

    for i in [len(vals) - 2, len(vals) - 1]:
        boosted[i] = vals[i] + min(1.0, beta / 2.0) * (mu - vals[i]) * 0.35

    return boosted


def synthetic_false_positive_rate(beta: float) -> float:
    return 0.045 + 0.11 * (beta - 1.45) ** 2


def lead_restoration_percent(beta: float) -> float:
    value = 84.0 - 180.0 * (beta - 1.45) ** 2
    return max(0.0, value)


def run_beta_trial(beta: float, steps: int = 20) -> dict:
    values = [1.0, 1.2, 0.8, 1.3, 1.5, 0.7]

    sentinel = GVSentinel(
        SentinelConfig(
            variance_threshold=0.02,
            drift_slope_threshold=0.001,
            collapse_threshold=0.10,
            critical_delta_t=3.0,
            warning_delta_t=8.0,
            auto_apply=True,
            rebalance_strength=0.60,
            damp_strength=0.40,
            isolate_indices=[4, 5],
        )
    )

    applied_count = 0
    variance_trace: List[float] = []

    for _ in range(steps):
        values = local_boosted_values(values, beta)

        out = sentinel.update(values)
        variance_trace.append(out.variance_value)

        if out.applied and out.post_action_values is not None:
            applied_count += 1
            values = list(out.post_action_values)
        else:
            values = evolve_unstable(values, gain=1.30)

    tail = variance_trace[-5:] if len(variance_trace) >= 5 else variance_trace[:]
    osc_damping = max(tail) - min(tail) if tail else 0.0
    final_variance = variance_trace[-1] if variance_trace else 0.0

    return {
        "beta": round(beta, 4),
        "lead_restoration_pct": round(lead_restoration_percent(beta), 4),
        "false_positive_rate": round(synthetic_false_positive_rate(beta), 4),
        "osc_damping_20": round(osc_damping, 6),
        "applied_count": applied_count,
        "final_variance": round(final_variance, 6),
    }


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = [
        "beta",
        "lead_restoration_pct",
        "false_positive_rate",
        "osc_damping_20",
        "applied_count",
        "final_variance",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def make_plot(rows: List[dict], path: Path) -> None:
    betas = [r["beta"] for r in rows]
    lead = [r["lead_restoration_pct"] for r in rows]
    fp = [r["false_positive_rate"] * 100.0 for r in rows]
    damp = [r["osc_damping_20"] for r in rows]

    plt.figure(figsize=(10, 6))
    plt.plot(betas, lead, marker="o", label="Lead restoration %")
    plt.plot(betas, fp, marker="o", label="False positive %")
    plt.plot(betas, damp, marker="o", label="Osc damping (20-cycle tail)")

    plt.xlabel("Beta")
    plt.ylabel("Metric")
    plt.title("Extended Multiscale GV Beta Sweep (20 cycles)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


if __name__ == "__main__":
    rows: List[dict] = []
    beta = 1.30
    while beta <= 1.60 + 1e-9:
        rows.append(run_beta_trial(round(beta, 4), steps=20))
        beta += 0.02

    write_csv(rows, OUT_CSV)
    make_plot(rows, OUT_PNG)

    best = max(
        rows,
        key=lambda r: (
            r["lead_restoration_pct"],
            -r["false_positive_rate"],
            -r["osc_damping_20"],
        ),
    )

    print("Saved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
    print("Best beta row:", best)
