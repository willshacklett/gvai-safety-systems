from __future__ import annotations
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd


def first_true(v):
    idx = np.flatnonzero(v)
    return int(idx[0]) if len(idx) else None


def rolling_slope(s, w=10):
    out = []
    vals = s.astype(float).values
    for i in range(len(vals)):
        y = vals[max(0, i - w + 1): i + 1]
        if len(y) < 3:
            out.append(0.0)
            continue
        x = np.arange(len(y), dtype=float)
        out.append(float(np.polyfit(x, y, 1)[0]))
    return pd.Series(out, index=s.index)


def compute(df: pd.DataFrame):
    x = df["metric"].astype(float)
    t = df["t"]

    dsdt = x.diff().fillna(0.0)

    # adaptive dS/dt gating
    dsdt_med = dsdt.rolling(20, min_periods=5).median().fillna(0.0)
    dsdt_mad = (dsdt - dsdt_med).abs().rolling(20, min_periods=5).median().fillna(0.0)
    adaptive_thr = dsdt_med + 2.2 * (1.4826 * dsdt_mad + 0.003)
    spike = dsdt > adaptive_thr

    # entropy velocity veto layer (transient filter only)
    d2sdt = dsdt.diff().fillna(0.0)
    vel_decay = d2sdt < -0.002
    spike = spike & (~vel_decay)

    persistence = spike.astype(float).rolling(16, min_periods=1).mean().fillna(0.0)

    baseline = x.rolling(30, min_periods=5).mean()
    deviation = (x - baseline).abs().fillna(0.0)
    dev_norm = (deviation / 0.08).clip(0, 3) / 3.0

    slope = rolling_slope(x, 10)
    slope_norm = (slope.clip(lower=0.0) / 0.01).clip(0, 1)

    rec_fail = ((deviation > 0.08) & (slope > 0)).astype(float)

    lag_vals = []
    cur = 0.0
    for v in rec_fail:
        if v:
            cur = min(1.0, 0.82 * cur + 0.28)
        else:
            cur = max(0.0, 0.82 * cur - 0.02)
        lag_vals.append(cur)
    lag = pd.Series(lag_vals, index=df.index)

    gv = (
        0.18 * spike.astype(float)
        + 0.24 * persistence
        + 0.18 * dev_norm
        + 0.18 * slope_norm
        + 0.22 * lag
    )

    # core untouched; velocity only filtered spike candidates above
    warn = (gv >= 0.65) & ((persistence >= 0.35) | (lag >= 0.20))

    collapse = None
    if "outcome" in df.columns and df["outcome"].iloc[-1] == "irreversible":
        collapse = int(np.argmax(x.values))

    first = first_true(warn.values)
    lead = None
    if collapse is not None and first is not None:
        lead = collapse - first

    enriched = df.copy()
    enriched["dsdt"] = dsdt
    enriched["adaptive_threshold"] = adaptive_thr
    enriched["spike_candidate"] = spike.astype(int)
    enriched["persistence"] = persistence
    enriched["deviation"] = deviation
    enriched["slope"] = slope
    enriched["recovery_lag"] = lag
    enriched["gv_signal"] = gv
    enriched["warning"] = warn.astype(int)

    summary = {
        "outcome": df["outcome"].iloc[-1] if "outcome" in df.columns else "unknown",
        "rows": int(len(df)),
        "max_gv": float(gv.max()),
        "max_persistence": float(persistence.max()),
        "max_lag": float(lag.max()),
        "warned": bool(warn.any()),
        "first_warning_t": None if first is None else int(t.iloc[first]),
        "lead_time": lead,
    }
    return enriched, summary


def main():
    ap = argparse.ArgumentParser(
        description="Minimal runtime irreversibility signal demo."
    )
    ap.add_argument("csv", help="Input CSV with at least columns: t, metric")
    ap.add_argument(
        "--emit-warnings",
        action="store_true",
        help="Print warning events in a runtime-style format",
    )
    ap.add_argument(
        "--write-output",
        action="store_true",
        help="Write enriched CSV + summary JSON to outputs/",
    )
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    required = {"t", "metric"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    enriched, summary = compute(df)

    print("")
    print("=== SUMMARY ===")
    for k, v in summary.items():
        print(f"{k} : {v}")

    if args.emit_warnings:
        warning_rows = enriched.loc[enriched["warning"] == 1, ["t", "gv_signal", "persistence", "recovery_lag"]]
        print("")
        print("=== WARNING EVENTS ===")
        if warning_rows.empty:
            print("No warnings emitted.")
        else:
            for _, row in warning_rows.iterrows():
                print(
                    f"t={int(row['t'])} WARNING gv={row['gv_signal']:.3f} "
                    f"persistence={row['persistence']:.3f} lag={row['recovery_lag']:.3f}"
                )

    if args.write_output:
        outdir = Path("outputs")
        outdir.mkdir(parents=True, exist_ok=True)

        stem = Path(args.csv).stem
        enriched_path = outdir / f"{stem}_enriched.csv"
        summary_path = outdir / f"{stem}_summary.json"

        enriched.to_csv(enriched_path, index=False)
        summary_path.write_text(json.dumps(summary, indent=2))

        print("")
        print("=== WROTE ===")
        print(enriched_path)
        print(summary_path)


if __name__ == "__main__":
    main()
