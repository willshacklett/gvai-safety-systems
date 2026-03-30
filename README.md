# GVAI Safety Systems — Minimal Demo

Detects irreversible system trajectories before failure using recoverability dynamics and adaptive entropy-style spike gating.

## Core shape

- spike -> candidate
- persistence + failed recovery -> confirmation
- adaptive dS/dt -> noise-aware candidate refinement

## Demo expectation

- irreversible: warned
- recoverable: no warning

## Quick run

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/make_sample_data.py
python run_gv_demo.py data/sample_irreversible.csv
python run_gv_demo.py data/sample_recoverable.csv
