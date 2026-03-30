from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


def zscore(series: pd.Series, window: int) -> pd.Series:
    mean = series.rolling(window, min_periods=max(5, window // 2)).mean()
    std = series.rolling(window, min_periods=max(5, window // 2)).std(ddof=0)
    z = (series - mean) / std.replace(0, np.nan)
    return z.fillna(0.0)


def longest_true_run(values: np.ndarray) -> int:
    best = 0
    cur = 0
    for v in values:
        if v:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def first_true_index(values: np.ndarray):
    idx = np.flatnonzero(values)
    return int(idx[0]) if len(idx) else None


def rolling_slope(series: pd.Series, window: int) -> pd.Series:
    vals = series.astype(float).values
    out = np.zeros(len(vals), dtype=float)
    x = np.arange(window, dtype=float)

    for i in range(len(vals)):
        start = max(0, i - window + 1)
        y = vals[start:i + 1]
        if len(y) < 3:
            out[i] = 0.0
            continue
        xx = np.arange(len(y), dtype=float)
        slope = np.polyfit(xx, y, 1)[0]
        out[i] = slope

    return pd.Series(out, index=series.index)


def compute_gv(
    df: pd.DataFrame,
    metric_col: str = "metric",
    time_col: str = "t",
    var_window: int = 20,
    baseline_window: int = 30,
    var_z_threshold: float = 1.75,
    recovery_window: int = 18,
    recovery_tol: float = 0.08,
    gv_threshold: float = 0.78,
    persistence_window: int = 16,
    slope_window: int = 10,
):
    df = df.copy().reset_index(drop=True)

    x = df[metric_col].astype(float)
    t = df[time_col]

    rolling_var = x.rolling(var_window, min_periods=max(5, var_window // 2)).var(ddof=0)
    rolling_var = rolling_var.bfill().fillna(0.0)

    var_z = zscore(rolling_var, baseline_window)
    variance_breach = var_z > var_z_threshold

    baseline = x.rolling(baseline_window, min_periods=max(5, baseline_window // 2)).mean()
    deviation = (x - baseline).abs().fillna(0.0)
    deviation_norm = np.clip(deviation / max(recovery_tol, 1e-6), 0.0, 3.0) / 3.0

    slope = rolling_slope(x, slope_window)
    positive_slope = np.clip(slope, 0.0, None)
    slope_norm = np.clip(positive_slope / 0.01, 0.0, 1.0)

    persistence = (
        variance_breach.astype(float)
        .rolling(persistence_window, min_periods=1)
        .mean()
        .fillna(0.0)
    )

    recovery_failure = ((deviation > recovery_tol) & (slope > 0)).astype(float)
    recovery_failure_persist = (
        recovery_failure.rolling(persistence_window, min_periods=1).mean().fillna(0.0)
    )

    var_score = np.clip(var_z / max(var_z_threshold, 1e-6), 0.0, 2.0) / 2.0

    gv_composite = (
        0.25 * var_score
        + 0.20 * deviation_norm
        + 0.25 * persistence
        + 0.15 * slope_norm
        + 0.15 * recovery_failure_persist
    )

    early_warning = (
        (gv_composite >= gv_threshold)
        & (persistence >= 0.60)
        & ((slope_norm >= 0.30) | (recovery_failure_persist >= 0.50))
    )

    df["rolling_var"] = rolling_var
    df["var_z"] = var_z
    df["variance_breach"] = variance_breach.astype(int)
    df["deviation"] = deviation
    df["deviation_norm"] = deviation_norm
    df["slope"] = slope
    df["slope_norm"] = slope_norm
    df["persistence"] = persistence
    df["recovery_failure"] = recovery_failure.astype(int)
    df["recovery_failure_persist"] = recovery_failure_persist
    df["gv_composite"] = gv_composite
    df["early_warning"] = early_warning.astype(int)

    outcome_label = str(df["outcome"].iloc[-1]) if "outcome" in df.columns else "unknown"

    if outcome_label == "irreversible":
        tail = x.tail(max(20, len(x) // 8))
        collapse_threshold = float(tail.median())
        collapse_point_candidates = np.flatnonzero(x.values >= collapse_threshold)
        collapse_idx = int(collapse_point_candidates[0]) if len(collapse_point_candidates) else len(df) - 1
    else:
        collapse_idx = None

    first_warn_idx = first_true_index(early_warning.values)
    lead_time = None
    if collapse_idx is not None and first_warn_idx is not None and first_warn_idx <= collapse_idx:
        lead_time = int(collapse_idx - first_warn_idx)

    summary = {
        "rows": int(len(df)),
        "outcome": outcome_label,
        "variance_breach_count": int(df["variance_breach"].sum()),
        "max_gv_composite": float(df["gv_composite"].max()),
        "max_persistence": float(df["persistence"].max()),
        "max_slope_norm": float(df["slope_norm"].max()),
        "max_recovery_failure_persist": float(df["recovery_failure_persist"].max()),
        "first_warning_t": None if first_warn_idx is None else int(t.iloc[first_warn_idx]),
        "collapse_t": None if collapse_idx is None else int(t.iloc[collapse_idx]),
        "lead_time": lead_time,
        "warning_run_length": int(longest_true_run(early_warning.values)),
        "warned": bool(df["early_warning"].any()),
    }

    return df, summary


def make_plot(df: pd.DataFrame, summary: dict, out_png: Path, metric_col: str, time_col: str) -> None:
    fig, ax = plt.subplots(figsize=(11, 6))
    ax.plot(df[time_col], df[metric_col], label="metric")
    ax.plot(df[time_col], df["gv_composite"], label="gv_composite")
    ax.plot(df[time_col], df["persistence"], label="persistence", alpha=0.8)
    ax.plot(df[time_col], df["slope_norm"], label="slope_norm", alpha=0.8)

    warn_mask = df["early_warning"] == 1
    if warn_mask.any():
        ax.scatter(
            df.loc[warn_mask, time_col],
            df.loc[warn_mask, metric_col],
            label="early_warning",
            s=18,
        )

    if summary["first_warning_t"] is not None:
        ax.axvline(summary["first_warning_t"], linestyle="--", linewidth=1)

    if summary["collapse_t"] is not None:
        ax.axvline(summary["collapse_t"], linestyle=":", linewidth=1)

    ax.set_title(f"GV demo | outcome={summary['outcome']} | lead_time={summary['lead_time']}")
    ax.set_xlabel(time_col)
    ax.set_ylabel("value")
    ax.legend()
    ax.grid(True, alpha=0.25)

    out_png.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run minimal GV demo on a time-series CSV.")
    parser.add_argument("csv_path", help="Path to CSV with at least columns: t, metric")
    parser.add_argument("--metric-col", default="metric")
    parser.add_argument("--time-col", default="t")
    parser.add_argument("--outdir", default="outputs")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    csv_path = Path(args.csv_path)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(csv_path)

    required = {args.time_col, args.metric_col}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    enriched, summary = compute_gv(
        df=df,
        metric_col=args.metric_col,
        time_col=args.time_col,
    )

    stem = csv_path.stem
    enriched_csv = outdir / f"{stem}_gv_output.csv"
    summary_csv = outdir / f"{stem}_summary.csv"
    plot_png = outdir / f"{stem}_plot.png"

    enriched.to_csv(enriched_csv, index=False)
    pd.DataFrame([summary]).to_csv(summary_csv, index=False)
    make_plot(enriched, summary, plot_png, args.metric_col, args.time_col)

    print("")
    print("=== GV DEMO SUMMARY ===")
    for k, v in summary.items():
        print(f"{k}: {v}")

    print("")
    print("Wrote:")
    print(f" - {enriched_csv}")
    print(f" - {summary_csv}")
    print(f" - {plot_png}")


if __name__ == "__main__":
    main()
