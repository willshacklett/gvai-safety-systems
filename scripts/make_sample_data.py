from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd


def make_trace(kind: str, n: int = 220, seed: int = 7) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    t = np.arange(n)

    base = 1.0 + 0.03 * np.sin(t / 7.0) + rng.normal(0, 0.015, size=n)
    x = base.copy()

    if kind == "recoverable":
        shock_center = 95
        shock_width = 18
        shock = 0.28 * np.exp(-((t - shock_center) ** 2) / (2 * shock_width**2))
        x += shock
        for i in range(shock_center + 5, n):
            x[i] -= min(0.22, 0.0032 * (i - shock_center))
        outcome = ["recoverable"] * n

    elif kind == "irreversible":
        shock_center = 95
        shock_width = 18
        shock = 0.30 * np.exp(-((t - shock_center) ** 2) / (2 * shock_width**2))
        x += shock
        drift_start = 108
        for i in range(drift_start, n):
            x[i] += 0.0055 * (i - drift_start)
        outcome = ["irreversible"] * n

    else:
        raise ValueError("kind must be 'recoverable' or 'irreversible'")

    return pd.DataFrame(
        {
            "t": t,
            "metric": x,
            "outcome": outcome,
        }
    )


def main() -> None:
    outdir = Path("data")
    outdir.mkdir(parents=True, exist_ok=True)

    recoverable = make_trace("recoverable", seed=7)
    irreversible = make_trace("irreversible", seed=11)

    recoverable.to_csv(outdir / "sample_recoverable.csv", index=False)
    irreversible.to_csv(outdir / "sample_irreversible.csv", index=False)

    combined = pd.concat(
        [
            recoverable.assign(trace_id="recoverable_001"),
            irreversible.assign(trace_id="irreversible_001"),
        ],
        ignore_index=True,
    )
    combined.to_csv(outdir / "sample_combined.csv", index=False)

    print("Wrote:")
    print(" - data/sample_recoverable.csv")
    print(" - data/sample_irreversible.csv")
    print(" - data/sample_combined.csv")


if __name__ == "__main__":
    main()
