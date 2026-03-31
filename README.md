# GVAI Safety Systems — v1 Runtime Signal

Detects irreversible system trajectories before visible failure using a layered runtime signal.

## Core architecture

- spike -> candidate
- persistence + failed recovery -> confirmation
- adaptive dS/dt -> noise-aware spike gating
- entropy velocity -> transient veto only

This separation is the point:

- candidate detection is fast
- confirmation is structural
- veto only removes short-lived transients

## Why it matters

Most systems fail before they crash.

This slice is designed to detect when a system is no longer just noisy, but is actually drifting into a non-recoverable regime.

## Demo behavior

Expected demo split:

- irreversible trajectory -> warned
- recoverable trajectory -> no warning

## Quick start

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/make_sample_data.py

python run_gv_demo.py data/sample_irreversible.csv
python run_gv_demo.py data/sample_recoverable.csv

## Runtime-style warning output

python run_gv_demo.py data/sample_irreversible.csv --emit-warnings

Example output:

t=190 WARNING gv=0.775 persistence=0.250 lag=1.000

## Write enriched outputs

python run_gv_demo.py data/sample_irreversible.csv --emit-warnings --write-output

This writes:

- outputs/sample_irreversible_enriched.csv
- outputs/sample_irreversible_summary.json

## Signal framing

This is the current v1 runtime-signal boundary:

- persistence + failed recovery anchors the irreversible call
- adaptive dS/dt improves candidate detection under noise
- entropy velocity gates transients only

## Status

Minimal v1 runtime signal is locked as a stable boundary for further real-world pressure testing.
