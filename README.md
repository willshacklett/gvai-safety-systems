# GVAI Safety Systems — Minimal Demo

This is a minimal runnable demo for detecting **irreversible vs recoverable trajectories** in time-series data.

## What it does

Given a time series:

- Computes variance, recovery, persistence, slope
- Builds a composite GV signal
- Flags early warnings of irreversible behavior

## Key Result (demo)

- Recoverable trace → NO warning
- Irreversible trace → WARNING triggered
- Lead time ≈ 100+ steps before collapse

## Quick Run

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python scripts/make_sample_data.py

python run_gv_demo.py data/sample_irreversible.csv
python run_gv_demo.py data/sample_recoverable.csv

## Expected Behavior

Irreversible:
- warned: True
- lead_time: large positive value

Recoverable:
- warned: False

## Files

- run_gv_demo.py → main logic
- scripts/make_sample_data.py → generates demo traces
- data/ → input traces
- outputs/ → results (csv + plots)

