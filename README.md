![tests](https://github.com/willshacklett/gvai-safety-systems/actions/workflows/tests.yml/badge.svg)

# GvAI Safety Systems

**Runtime AI Safety & Security Infrastructure**

GvAI Safety Systems provides continuous, quantitative monitoring for AI systems in production.  
We detect when AI systems accumulate operational risk faster than constraints can control it — and intervene before failure occurs.

---

## Why GvAI

AI systems rarely fail all at once.

They drift.
They strain constraints.
They quietly accumulate risk.

Most tools tell you **what already happened**.  
GvAI tells you **when systems are becoming unsafe** — while you still have time to act.

---

## Core Concept: GV (Constraint Strain Score)

GV is a continuous signal that measures how much operational risk an AI system is accumulating relative to its controls.

It captures:
- Behavioral drift
- Rising uncertainty
- Policy boundary pressure
- Constraint erosion over time

GV is:
- **Model-agnostic**
- **Runtime, not retrospective**
- **Quantitative, not subjective**
- **Actionable by design**

---

## Product: GV Sentinel

**GV Sentinel** is a lightweight runtime safety monitor that sits between AI systems and real-world execution.

It provides:
- Live GV score
- Trend and acceleration detection
- Threshold-based alerts
- Automated intervention hooks
- Audit-ready safety logs

Think: **Datadog + circuit breaker for AI systems**

---

## Example

```python
from gvai import Sentinel

sentinel = Sentinel(system_id="agent-prod")

result = sentinel.evaluate({
    "uncertainty": 0.61,
    "drift": 0.19,
    "policy_pressure": 0.73
})

print(result["gv_score"])
