# GvAI Safety Systems

**GvAI** is a lightweight, open-source framework for **runtime AI safety** built around a simple idea:

> **Measure strain while systems are running — not just intent before deployment.**

At the core of GvAI is the **GV (God Variable)**: a bounded scalar that tracks accumulated
constraint strain in an AI system over time.

This repository provides practical, engineer-friendly tools for:
- Runtime risk signaling
- Agent safety instrumentation
- Constraint-aware observability
- Early intervention before runaway behavior

---

## Why GvAI?

Most AI safety work focuses on:
- Training-time alignment
- Static evaluations
- Pre-deployment controls

GvAI focuses on **runtime survivability**.

It answers questions like:
- *Is this agent starting to thrash?*
- *Are tool calls escalating?*
- *Is the system entering an error or recursion loop?*
- *Should we slow it down or halt execution?*

All without model introspection.

---

## GV Runtime Guard (MVP)

GvAI includes a lightweight **runtime guard** that computes a **GV risk signal**
from live agent / tool-loop telemetry.

### What it does
- Converts simple runtime signals into a `gv` score (0–100)
- Emits a risk band: `green | yellow | red`
- Recommends an action: `continue | slow | halt`
- Self-damps when behavior stabilizes

### Signals observed
- Token generation velocity
- Tool call frequency
- Error / exception rate
- Repeated identical actions
- Recursion depth
- Optional latency correlation

---

## Quick Demo (CLI)

```bash
echo '{"token_delta":800,"tool_calls_delta":2,"error_delta":1,"repeated_action_delta":2,"recursion_depth":1}' \
| python -m gvai.runtime_guard.cli
