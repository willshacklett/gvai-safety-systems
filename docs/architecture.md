# Architecture

GvAI Safety Systems provides runtime monitoring for AI systems by computing a continuous GV (Constraint Strain Score)
from live operational signals (e.g., uncertainty, drift, policy pressure).

## Components

### GV Core
- Input: normalized risk signals (0.0–1.0)
- Output: GV score (0.0–1.0)
- Goal: provide an interpretable, model-agnostic safety signal

### Sentinel
- Wraps GV Core with:
  - system identity (`system_id`)
  - history tracking
  - evaluation record format (timestamped)
- Designed to run inside:
  - LLM proxies
  - agent runtimes
  - CI/CD checks

## Data Flow

1. Collect runtime signals
2. Compute GV score
3. Compare to thresholds (future)
4. Trigger actions (alert, throttle, halt) (future)
5. Log for audit/compliance

## Roadmap Additions

- Threshold policies + actions
- Structured event logging
- Pluggable signal adapters (LLM proxy, agent middleware)
- Dashboard + audit exports
