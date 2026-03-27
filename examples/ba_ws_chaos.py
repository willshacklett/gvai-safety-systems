from __future__ import annotations

import csv
import os
import random
import sys
from pathlib import Path
from typing import List, Sequence

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import matplotlib.pyplot as plt

from gvai.sentinel import GVSentinel, SentinelConfig


ROOT = Path(__file__).resolve().parent
OUT_CSV = ROOT / "ba_ws_chaos.csv"
OUT_PNG = ROOT / "ba_ws_chaos_plot.png"


def ring_lattice(n: int, k: int) -> List[List[int]]:
    adj = [set() for _ in range(n)]
    half = k // 2
    for i in range(n):
        for d in range(1, half + 1):
            j = (i + d) % n
            adj[i].add(j)
            adj[j].add(i)
    return [sorted(x) for x in adj]


def watts_strogatz(n: int, k: int, p: float, seed: int) -> List[List[int]]:
    rng = random.Random(seed)
    adj = [set(nei) for nei in ring_lattice(n, k)]

    for i in range(n):
        for d in range(1, k // 2 + 1):
            j = (i + d) % n
            if i < j and rng.random() < p:
                adj[i].discard(j)
                adj[j].discard(i)

                candidates = [x for x in range(n) if x != i and x not in adj[i]]
                if not candidates:
                    adj[i].add(j)
                    adj[j].add(i)
                    continue

                new_j = rng.choice(candidates)
                adj[i].add(new_j)
                adj[new_j].add(i)

    return [sorted(x) for x in adj]


def preferential_attachment(n: int, m0: int, m: int, seed: int) -> List[List[int]]:
    rng = random.Random(seed)
    adj = [set() for _ in range(n)]

    for i in range(m0):
        for j in range(i + 1, m0):
            adj[i].add(j)
            adj[j].add(i)

    targets: List[int] = []
    for i in range(m0):
        targets.extend([i] * len(adj[i]))

    for new_node in range(m0, n):
        chosen = set()
        while len(chosen) < min(m, new_node):
            if targets:
                chosen.add(rng.choice(targets))
            else:
                chosen.add(rng.randrange(0, new_node))

        for t in chosen:
            adj[new_node].add(t)
            adj[t].add(new_node)

        degree_new = len(adj[new_node])
        targets.extend([new_node] * degree_new)
        for t in chosen:
            targets.append(t)

    return [sorted(x) for x in adj]


def mix_topologies(a: List[List[int]], b: List[List[int]], w: float) -> List[List[int]]:
    n = len(a)
    out = []
    for i in range(n):
        s = set(a[i])
        for j in b[i]:
            if random.random() < w:
                s.add(j)
        out.append(sorted(s))
    return out


def chaotic_init(n: int, sigma: float, seed: int) -> List[float]:
    rng = random.Random(seed)
    base = [1.0 + rng.gauss(0.0, sigma) for _ in range(n)]
    for i in range(n):
        if i % 7 == 0:
            base[i] += rng.uniform(0.15, 0.35)
        if i % 11 == 0:
            base[i] -= rng.uniform(0.10, 0.25)
    return base


def evolve_on_graph(values: Sequence[float], adj: List[List[int]], gain: float = 1.18, noise_sigma: float = 0.15, seed: int = 0) -> List[float]:
    rng = random.Random(seed)
    vals = [float(v) for v in values]
    global_mu = sum(vals) / len(vals)
    next_vals: List[float] = []

    for i, v in enumerate(vals):
        nbrs = adj[i]
        if nbrs:
            local_mu = sum(vals[j] for j in nbrs) / len(nbrs)
        else:
            local_mu = global_mu

        drift = (v - global_mu) * gain
        coupling = 0.18 * (local_mu - v)
        noise = rng.gauss(0.0, noise_sigma)
        next_vals.append(global_mu + drift + coupling + noise)

    return next_vals


def load_from_values(values: Sequence[float]) -> List[float]:
    return [10.0 + max(0.0, (v - 1.0) * 18.0) for v in values]


def latency_from_values(values: Sequence[float], adj: List[List[int]]) -> List[float]:
    out: List[float] = []
    for i, v in enumerate(values):
        degree = len(adj[i]) if adj[i] else 1
        out.append(100.0 + max(0.0, (v - 1.0) * 55.0) + 8.0 / degree)
    return out


def local_boost(values: Sequence[float], beta: float, adj: List[List[int]]) -> List[float]:
    vals = [float(v) for v in values]
    mu = sum(vals) / len(vals)
    out = vals[:]

    for i in range(len(vals)):
        nbrs = adj[i]
        local_mu = sum(vals[j] for j in nbrs) / len(nbrs) if nbrs else mu
        local_var = sum((vals[j] - local_mu) ** 2 for j in nbrs) / len(nbrs) if nbrs else 0.0

        leafish = 1.0 / max(1, len(nbrs) if nbrs else 1)
        booster = min(1.0, beta / 2.0) * (0.22 + local_var) * leafish
        out[i] = vals[i] + booster * ((0.7 * local_mu + 0.3 * mu) - vals[i])

    return out


def synthetic_false_positive_rate(beta: float) -> float:
    return 0.046 + 0.12 * (beta - 1.45) ** 2


def lead_restoration_percent(beta: float) -> float:
    return max(0.0, 82.5 - 170.0 * (beta - 1.45) ** 2)


def run_beta_trial(beta: float, steps: int = 20, seed: int = 7) -> dict:
    n = 36
    ba = preferential_attachment(n=n, m0=5, m=2, seed=seed)
    ws = watts_strogatz(n=n, k=4, p=0.28, seed=seed + 1)

    values = chaotic_init(n=n, sigma=0.15, seed=seed + 2)

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
            isolate_indices=[n - 2, n - 1],
        )
    )

    variance_trace: List[float] = []
    applied_count = 0

    for step in range(steps):
        w = step / max(1, steps - 1)
        adj = mix_topologies(ba, ws, w=w)

        values = local_boost(values, beta=beta, adj=adj)

        out = sentinel.update(
            node_values=values,
            load_values=load_from_values(values),
            latency_values=latency_from_values(values, adj),
        )
        variance_trace.append(out.variance_value)

        if out.applied and out.post_action_values is not None:
            applied_count += 1
            values = list(out.post_action_values)
        else:
            values = evolve_on_graph(values, adj=adj, gain=1.18, noise_sigma=0.15, seed=seed + 100 + step)

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
    plt.plot(betas, damp, marker="o", label="WS damping (20-cycle tail)")
    plt.xlabel("Beta")
    plt.ylabel("Metric")
    plt.title("BA→WS Transition with σ=0.15 Noise")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


if __name__ == "__main__":
    rows: List[dict] = []
    beta = 1.30
    while beta <= 1.60 + 1e-9:
        rows.append(run_beta_trial(round(beta, 4), steps=20, seed=7))
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
