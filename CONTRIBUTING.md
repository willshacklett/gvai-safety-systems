# Contributing to GvAI Safety Systems

Thanks for your interest in contributing.

## What we’re building
GvAI Safety Systems is runtime AI safety & security infrastructure:
- A continuous GV (Constraint Strain Score)
- Risk bands + recommended actions
- Integrations (LLM proxy, agent middleware, CI checks)
- Audit-friendly logging and reporting

## Quick start (dev)
```bash
pip install -e .
pip install -r requirements-dev.txt
pytest -q
