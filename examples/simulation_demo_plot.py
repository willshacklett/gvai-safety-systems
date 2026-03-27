from __future__ import annotations

import csv
import os
import sys
from pathlib import Path
from typing import List, Sequence

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import matplotlib.pyplot as plt

from gvai.metrics import variance
from gvai.sentinel import GVSentinel, SentinelConfig


ROOT = Path(__file__).resolve().parent
OUT_CSV = ROOT / "simulation_demo_results.csv"
OUT_PNG = ROOT / "simulation_demo_plot.png"


def evolve_unstable(values: Sequence[float], gain: float = 1.35) -> List[float]:
    vals = [float(v) for v in values]
    mu = sum(vals) / len(vals)
    return [mu + (v - mu) * gain for v in vals]


def run_without_intervention(initial: Sequence[float], steps: int = 10) -> List[dict]:
    print("=== WITHOUT INTERVENTION (COLLAPSE) ===")
    values = list(initial)
    rows: List[dict] = []

    for step in range(steps):
        var = variance(values)
        print(f"STEP {step}")
        print("VARIANCE:", round(var, 6))
        print("-")

        rows.append(
            {
                "mode": "without_intervention",
                "step": step,
                "variance": var,
                "status": "uncontrolled",
                "action": "none",
                "applied": False,
            }
        )

        values = evolve_unstable(values)

    return rows


def run_with_sentinel(initial: Sequence[float], steps: int = 10) -> List[dict]:
    print("\n=== WITH GV SENTINEL (STABILIZATION) ===")
    values = list(initial)
    rows: List[dict] = []

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

    for step in range(steps):
        out = sentinel.update(values)

        print(f"STEP {step}")
        print("VARIANCE:", round(out.variance_value, 6))
        print("STATUS:", out.status)
        print("ACTION:", out.recommended_action)
        print("APPLIED:", out.applied)
        print("-")

        rows.append(
            {
                "mode": "with_sentinel",
                "step": step,
                "variance": out.variance_value,
                "status": out.status,
                "action": out.recommended_action,
                "applied": out.applied,
            }
        )

        if out.applied and out.post_action_values is not None:
            values = list(out.post_action_values)
        else:
            values = evolve_unstable(values)

    return rows


def write_csv(rows: List[dict], path: Path) -> None:
    fieldnames = ["mode", "step", "variance", "status", "action", "applied"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def make_plot(rows: List[dict], path: Path) -> None:
    without_rows = [r for r in rows if r["mode"] == "without_intervention"]
    with_rows = [r for r in rows if r["mode"] == "with_sentinel"]

    plt.figure(figsize=(10, 6))

    plt.plot(
        [r["step"] for r in without_rows],
        [r["variance"] for r in without_rows],
        marker="o",
        label="Without intervention",
    )
    plt.plot(
        [r["step"] for r in with_rows],
        [r["variance"] for r in with_rows],
        marker="o",
        label="With GV sentinel",
    )

    acted_rows = [r for r in with_rows if r["applied"]]
    if acted_rows:
        plt.scatter(
            [r["step"] for r in acted_rows],
            [r["variance"] for r in acted_rows],
            marker="x",
            s=100,
            label="Intervention applied",
        )

    plt.xlabel("Step")
    plt.ylabel("Variance")
    plt.title("GVAI Simulation Demo: Collapse vs Stabilization")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


if __name__ == "__main__":
    initial = [1.0, 1.2, 0.8, 1.3, 1.5, 0.7]

    rows = []
    rows.extend(run_without_intervention(initial, steps=10))
    rows.extend(run_with_sentinel(initial, steps=10))

    write_csv(rows, OUT_CSV)
    make_plot(rows, OUT_PNG)

    print("\nSaved CSV:", OUT_CSV)
    print("Saved plot:", OUT_PNG)
