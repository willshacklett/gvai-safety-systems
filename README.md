# gvai-safety-systems

Minimal GV demo runner for time-series traces.

What it does:
- reads a CSV with at least t and metric columns
- computes rolling variance
- computes variance breach
- computes recovery lag
- computes a GV composite
- computes early warning flags
- reports lead time when outcome is irreversible

Quick start:
1. python3 -m venv .venv
2. source .venv/bin/activate
3. pip install -r requirements.txt
4. python scripts/make_sample_data.py
5. python run_gv_demo.py data/sample_irreversible.csv
6. python run_gv_demo.py data/sample_recoverable.csv

Expected outputs in outputs/:
- *_gv_output.csv
- *_summary.csv
- *_plot.png

Input format example:
t,metric,outcome
0,1.02,recoverable
1,1.01,recoverable
2,1.03,recoverable

The outcome column is optional but helps with summary and lead-time reporting.
