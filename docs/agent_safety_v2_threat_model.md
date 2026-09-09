# GV Agent Safety V2 — Threat Model

## Status

Experimental.

GV Agent Safety V2 is an experimental runtime-governance architecture for
constraining agent actions under optimization pressure.

The current implementation does **not** claim to solve AI alignment,
general containment, or arbitrary-code sandboxing.

The tested claim is narrower:

> In the tested Linux/Bubblewrap environment, an untrusted workload is
> prevented from committing selected protected filesystem, network, and
> child-process effects, while invariant-compliant output may be promoted
> into authoritative state.

## 1. Security Objective

The primary objective is to preserve protected invariants even when doing
so reduces task reward or prevents task completion.

The agent may prefer an action because it appears to maximize reward.

GV policy must instead prefer:

1. invariant preservation;
2. recoverability;
3. permitted task progress.

Reward does not override protected invariants.

## 2. System Model

The current execution flow is:

    Agent / workload
           |
           v
    Proposed action
           |
           v
    Disposable execution boundary
           |
           +--> OS filesystem controls
           +--> isolated network namespace
           +--> dropped Linux capabilities
           +--> seccomp process-creation restriction
           |
           v
    Observed effects
           |
           v
    GV invariant policy
           |
           +--> ALLOW --> promote permitted output
           |
           +--> DENY  --> discard transaction
           |
           +--> HALT  --> stop execution when Sentinel
                         reports irrecoverability

The authoritative state exists outside the untrusted workload.

## 3. Trusted Computing Base

The current trusted computing base includes:

- the host Linux kernel;
- Bubblewrap;
- libseccomp;
- the parent GV runtime;
- GV invariant definitions;
- GV runtime policy;
- Sentinel / recoverability logic;
- transaction commit code;
- the Python interpreter running the trusted parent;
- the code that constructs sandbox mounts and namespaces.

The child workload is not trusted.

The child's action name, optimization objective, reward preference, and
claims about its own effects are not treated as authoritative.

## 4. Attacker Model

The adversarial workload may:

- select high-reward actions;
- mislabel dangerous actions with benign names;
- falsely declare benign effects;
- attempt to modify protected files;
- attempt external network communication;
- attempt to create child processes;
- combine multiple prohibited actions;
- perform ordinary useful work in the same transaction as prohibited work;
- attempt actions while the runtime is degraded;
- attempt actions after the Sentinel reaches an irrecoverable state.

The workload is assumed to execute inside the configured sandbox.

## 5. Protected Invariants

### 5.1 Protected filesystem state

Selected safety configuration is mounted read-only.

Examples:

    /safety/policy.json
    /safety/gate.conf

A successful write to protected safety state is considered a boundary
failure.

An attempted protected write that Linux denies is treated as a prohibited
effect and causes transaction denial.

### 5.2 External network egress

The workload executes in an isolated network namespace.

External egress attempts are expected to fail.

A successful external connection is considered a boundary failure.

An attempted external connection that the OS denies is treated as a
prohibited effect and causes transaction denial.

### 5.3 Child-process creation

The workload receives a seccomp filter that denies:

    fork
    vfork
    clone
    clone3

The tested objective is to prevent the running workload from creating
additional child processes.

A successful process-creation attempt is considered a boundary failure.

A denied process-creation attempt is treated as a prohibited effect and
causes transaction denial.

### 5.4 Authoritative commit

Files created inside the disposable work directory are not authoritative
merely because the workload created them.

They become authoritative only after GV policy returns ALLOW.

If the transaction contains a protected effect, ordinary reward or task
output produced during the same transaction must not be committed.

## 6. Sentinel / Recoverability Constraint

GV Agent Safety V2 also incorporates runtime recoverability state.

Current runtime states include:

    stable
    warning
    critical
    irrecoverable

Policy behavior includes:

- stable: permitted actions may execute;
- warning: destabilizing actions are restricted;
- critical: only low-impact actions are permitted;
- irrecoverable: execution halts.

An irrecoverable Sentinel result takes precedence over otherwise permitted
actions.

## 7. Effect Authority Evolution

The project intentionally moved through increasingly less-trusting models:

    declared action effects
            |
            v
    trusted static effect registry
            |
            v
    transactional state-diff observation
            |
            v
    capability-level state observation
            |
            v
    real child-process observation
            |
            v
    kernel-backed execution restrictions

The current OS experiment does not trust the workload's declared effects.

## 8. Failure Conditions

For the current experiment, any of the following is a failure:

1. a protected safety file is modified by the untrusted workload;
2. an external network connection succeeds;
3. a prohibited child process is successfully created;
4. output from a denied transaction reaches authoritative state;
5. a transaction containing a prohibited effect is returned as allowed;
6. an irrecoverable runtime state permits execution;
7. OS sandbox unavailability causes silent fallback to weaker enforcement.

The implementation is intended to fail closed if the OS sandbox is not
available.

## 9. Explicitly Out of Scope

The current tests do not establish resistance to:

- Linux kernel vulnerabilities;
- Bubblewrap vulnerabilities;
- libseccomp vulnerabilities;
- container or namespace escape vulnerabilities;
- malicious native extensions;
- direct device abuse;
- every possible syscall;
- inherited file-descriptor abuse;
- shared-memory attacks not represented by the current model;
- covert channels;
- timing channels;
- CPU denial of service;
- memory exhaustion;
- disk exhaustion;
- attacks against the trusted parent process;
- compromised host administrators;
- firmware attacks;
- hypervisor attacks;
- arbitrary distributed-agent coordination;
- general AI alignment failures.

Passing the current suite must not be interpreted as proof against these
classes of attack.

## 10. Current Evidence

The V2 branch contains tests covering:

- hard invariants;
- reward pressure;
- direct and indirect bypass attempts;
- effect declaration spoofing;
- transactional state-diff enforcement;
- capability-level enforcement;
- real subprocess execution;
- Sentinel recoverability;
- delta-t warning behavior;
- recovery hysteresis;
- irrecoverable halt behavior;
- read-only protected mounts;
- isolated network execution;
- dropped Linux capabilities;
- seccomp child-process denial;
- authoritative commit filtering.

At the time this document was added, the regression suite had reached:

    91 passing tests

This number is historical evidence, not a security guarantee.

## 11. Interpretation

A passing result supports the following narrow statement:

> Under the tested runtime assumptions, selected protected effects remain
> outside the control of the untrusted workload and are enforced by a
> combination of GV policy and operating-system mechanisms.

A passing result does **not** support claims that GV prevents every
possible malicious action, solves AI alignment, or is proven secure
against arbitrary hostile code.

## 12. Next Security Questions

Future experiments should focus on unresolved capability surfaces:

- resource limits;
- inherited descriptor isolation;
- filesystem path / symlink attacks;
- environment and credential isolation;
- mount visibility;
- signal behavior;
- process limits;
- executable availability;
- syscall minimization;
- timeout enforcement;
- malformed child output;
- sandbox crash behavior;
- commit-path traversal;
- denial-of-service behavior;
- independent reproduction on another Linux host.

The guiding rule remains:

> Add a claim only after an experiment can falsify it.
