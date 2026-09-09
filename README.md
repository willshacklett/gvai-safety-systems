# GVAI Safety Systems

**[Read the GV Agent Safety V2 Technical Brief](docs/GV_Agent_Safety_V2_Technical_Brief.pdf)**  
**[Watch the GV Agent Safety V2 Demo](docs/GV_Agent_Safety_V2_Demo.mp4)**


Experimental runtime safety and agent-governance research focused on a simple question:

> Can a system preserve protected constraints and recoverability boundaries even when an optimizing agent is rewarded for crossing them?

The project currently has two major layers:

- **V1 — Runtime Signal:** detect trajectories moving toward non-recoverable states.
- **V2 — Agent Safety:** use protected invariants, observed effects, recoverability state, transactional execution, and OS-backed enforcement to govern agent actions.

## Current Milestone

**GV Agent Safety V2 Prototype**

- 95 tests passing
- Linux/Bubblewrap OS-backed execution boundary
- read-only protected safety mounts
- isolated network namespace
- dropped Linux capabilities
- seccomp child-process restriction
- transactional authoritative commit
- Sentinel recoverability integration
- formal threat model
- machine-readable acceptance report
- tagged release point: `gv-agent-safety-v2-prototype`

The V2 acceptance experiment produced:

    safe_work
      -> normal_operation
      -> ALLOW
      -> COMMIT

    protected_file_attack
      -> protected_file_write_attempt
      -> DENY
      -> NO COMMIT

    network_attack
      -> unapproved_network_egress_attempt
      -> DENY
      -> NO COMMIT

    process_attack
      -> unauthorized_process_spawn_attempt
      -> DENY
      -> NO COMMIT

    combined_attack
      -> protected_file_write_attempt
      -> unapproved_network_egress_attempt
      -> unauthorized_process_spawn_attempt
      -> DENY
      -> NO COMMIT

Only the permitted output reached authoritative state:

    result.txt

The acceptance report returned:

    "passed": true

with exit code `0`.

## Important Scope Statement

This repository is an **experimental prototype**.

The current results do **not** demonstrate:

- general AI alignment;
- universal AI containment;
- resistance to arbitrary hostile code;
- protection against kernel or sandbox vulnerabilities;
- a proof that an AI system is "safe";
- a solution to the broader AI-control problem.

The tested claim is deliberately narrower:

> In the tested Linux/Bubblewrap environment, selected protected filesystem, network, process-creation, and authoritative-commit boundaries remained enforced during the included adversarial action tests.

See:

`docs/agent_safety_v2_threat_model.md`

for the formal threat model, trusted computing base, failure conditions, and explicit exclusions.

---

# V2 — Agent Safety

## Core Idea

V2 moves the project from detecting dangerous trajectories toward governing actions.

The basic architecture is:

    Agent objective
          |
          v
    Proposed action
          |
          v
    Disposable execution boundary
          |
          +--> filesystem restrictions
          +--> network isolation
          +--> capability restrictions
          +--> process restrictions
          |
          v
    Observed effects
          |
          v
    GV invariant + runtime policy
          |
          +--> ALLOW
          |      |
          |      v
          |   COMMIT
          |
          +--> DENY
          |      |
          |      v
          |   DISCARD
          |
          +--> HALT

The authoritative state remains outside the untrusted workload.

## Protected Invariants

V2 introduces explicit invariants that an agent objective is not permitted to override.

Reward does not automatically outrank the protected boundary.

Early experiments test this directly by increasing the reward attached to forbidden actions and comparing an unconstrained control policy against the GV-governed policy.

## Effect-Based Governance

V2 does not rely only on action names.

The project progresses through several increasingly less-trusting models:

    action-name rules
          |
          v
    declared effects
          |
          v
    trusted effect authority
          |
          v
    transactional state-diff observation
          |
          v
    capability-level observation
          |
          v
    real subprocess execution
          |
          v
    OS-backed enforcement

This matters because an unsafe operation should not become permissible merely because it is given a harmless-looking name.

## Sentinel Integration

The existing Sentinel remains part of V2.

Runtime states include:

    stable
    warning
    critical
    irrecoverable

Policy can become progressively more restrictive as recoverability deteriorates.

At the current boundary:

- stable permits invariant-compliant actions;
- warning restricts destabilizing actions;
- critical permits only low-impact actions;
- irrecoverable halts execution.

This keeps action governance connected to the original GV recoverability work rather than treating safety as a static allow/deny list.

## Transactional Execution

Untrusted work is performed against disposable state.

The result is evaluated before anything becomes authoritative.

Conceptually:

    untrusted execution
          |
          v
    disposable state
          |
          v
    observe effects
          |
          v
    GV decision
       /      \
    ALLOW     DENY
      |         |
    commit    discard

This creates a distinction between:

- an action being attempted;
- an output being produced;
- that output being trusted and committed.

## OS-Backed Boundary

The current Linux experiment uses Bubblewrap and libseccomp.

The tested boundary includes:

### Filesystem

Selected safety state is exposed read-only.

Examples:

    /safety/policy.json
    /safety/gate.conf

### Network

The workload executes inside an isolated network namespace.

The current adversarial experiment attempts external network access and expects the operating-system boundary to prevent it.

### Linux capabilities

Linux capabilities are dropped inside the sandbox.

### Process creation

A seccomp filter denies the tested process-creation syscalls:

    fork
    vfork
    clone
    clone3

The worker genuinely attempts to create another process.

The tested kernel returns a denial, GV observes the prohibited attempt, and the transaction is not committed.

## Acceptance Boundary

The consolidated acceptance suite is:

`tests/test_agent_safety_v2_acceptance.py`

The machine-readable experiment is:

`experiments/agent_safety/v2_acceptance_report.py`

The captured acceptance artifact is:

`experiments/results/gv_v2_acceptance.json`

At the tagged prototype milestone:

    95 passed

The acceptance artifact records:

    "passed": true

The successful transaction commits:

    result.txt

The combined adversarial transaction also produces high-reward ordinary output inside disposable state, but because that transaction crosses protected boundaries, the output is discarded rather than promoted into authoritative state.

## V2 Experiments

The repository includes experiments covering:

- control vs. GV reward pressure;
- direct forbidden actions;
- indirect bypass attempts;
- effect spoofing;
- Sentinel-coupled action gating;
- recoverability governance;
- recovery challenges;
- hysteresis;
- irrecoverable-state behavior;
- closed-loop agent behavior;
- transactional observed effects;
- capability attacks;
- real subprocess attacks;
- OS-boundary attacks;
- consolidated V2 acceptance.

These experiments are intended to make specific claims falsifiable rather than to demonstrate universal safety.

---

# V1 — Runtime Signal

V1 remains the stable runtime-signal foundation underneath the newer agent-governance work.

## Core Architecture

- spike -> candidate
- persistence + failed recovery -> confirmation
- adaptive dS/dt -> noise-aware spike gating
- entropy velocity -> transient veto only

This separation is the point:

- candidate detection is fast;
- confirmation is structural;
- veto only removes short-lived transients.

## Why It Matters

Most systems fail before they crash.

V1 is designed to detect when a system is no longer merely noisy but is drifting into a non-recoverable regime.

## Demo Behavior

Expected demo split:

- irreversible trajectory -> warned
- recoverable trajectory -> no warning

## Quick Start

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python scripts/make_sample_data.py

    python run_gv_demo.py data/sample_irreversible.csv
    python run_gv_demo.py data/sample_recoverable.csv

## Runtime-Style Warning Output

Run:

    python run_gv_demo.py data/sample_irreversible.csv --emit-warnings

Example:

    t=190 WARNING gv=0.775 persistence=0.250 lag=1.000

## Write Enriched Outputs

Run:

    python run_gv_demo.py data/sample_irreversible.csv --emit-warnings --write-output

This writes:

- `outputs/sample_irreversible_enriched.csv`
- `outputs/sample_irreversible_summary.json`

## V1 Signal Framing

The stable V1 runtime-signal boundary is:

- persistence + failed recovery anchors the irreversible call;
- adaptive dS/dt improves candidate detection under noise;
- entropy velocity gates transients only.

---

# Reproducing the V2 Milestone

The OS-backed acceptance tests require a compatible Linux environment with Bubblewrap, user namespaces, and libseccomp available.

Run the full regression suite:

    python -m pytest -q

At the `gv-agent-safety-v2-prototype` milestone the expected result is:

    95 passed

Run the consolidated acceptance suite:

    python -m pytest -q tests/test_agent_safety_v2_acceptance.py

Expected:

    4 passed

Run the machine-readable acceptance experiment:

    python experiments/agent_safety/v2_acceptance_report.py

A successful run should contain:

    "passed": true

The experiment intentionally refuses to substitute weaker userspace enforcement when the required OS-backed sandbox is unavailable.

---

# Research Philosophy

GVAI Safety Systems is being developed as a sequence of increasingly difficult falsification tests.

The working rule is:

> Add a claim only after an experiment can falsify it.

The project therefore distinguishes between:

- simulated enforcement;
- userspace enforcement;
- OS-backed enforcement;
- evidence demonstrated by the current tests;
- broader security claims that remain untested.

Passing tests are evidence about the tested boundary.

They are not proof of universal safety.

## Status

**V1:** stable runtime-signal boundary.

**V2:** tagged experimental agent-safety prototype with OS-backed enforcement and reproducible acceptance evidence.

Prototype tag:

`gv-agent-safety-v2-prototype`
