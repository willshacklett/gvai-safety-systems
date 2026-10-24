# Trusted setup and mandatory worker entry contract

## Disposition

Source-only, dormant, deny-by-default contract. No loadable policy, launcher,
runtime verifier, systemd transport, execution or publication API is supplied.
No kernel acceptance has occurred. **STOP for human review.**

The architectural choice is separate setup confinement followed by mandatory
worker confinement, never unconfined execution between them. The compiler at
`e8d2ac51ec99321a64cfc88a1affdc9167827551` is preserved unchanged. Its mandatory
`AppArmorProfile=gvai-worker` is NOT suitable for launching setup under the
historical worker policy. Integrating a separate setup service/entry contract
requires another reviewed change; this module does not override that property.

## Lifecycle and trust boundary

The [contract](../gvai/launcher_worker_contract.py) models:

```text
STOPPED -> SETUP_PENDING -> SETUP_CONFINED -> NAMESPACES_ESTABLISHED
  -> INPUT_AND_SECCOMP_VERIFIED -> WORKER_CONFINEMENT_VERIFIED
  -> READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION
```

Only adjacent steps are permitted. Skips, repetition, bad evidence and failures
enter `FAILED_CLOSED`. The worker-confinement step currently ALWAYS enters
`FAILED_CLOSED`, even with a perfect offline fixture. No configuration flag or
verifier response enables it. The final two forward states describe requirements
but are intentionally unreachable.

STOP from every state latches intent and enters `TERMINATION_PENDING`, except
that an already `TERMINATED` state stays terminated. It invalidates prior
evidence requests. Complete, independently assessed cleanup is required for
`TERMINATED`. Failure cannot resume setup; STOP can retry cleanup with fresh
evidence. No restart/unstop method exists. Recording STOP here does NOT signal
processes or persist a STOP journal; the existing external supervisor owns those
operations. Errors are returned explicitly and survive cleanup retries.

### STOP concurrency and callback limits

Verifier callbacks and interpretation of their results run outside the lifecycle
mutex. A short locked reservation increments the revision and provisionally
fails closed; accepting a result requires that same revision under the mutex.
STOP latches monotonically, increments the revision, and records termination
intent without waiting for the callback. Late successes and expected failures
cannot overwrite STOP or newer cleanup results. Reentrant STOP is supported;
reentrant/concurrent advancement invalidates the outstanding result and cannot
reopen setup. Duplicate STOP is safe and invalidates older cleanup observations.
Fresh cleanup verification can proceed while an older setup verifier is blocked.

This is not cancellation of a Python callback: the thread calling `advance`
may remain blocked until its synchronous verifier returns. No detached threads,
thread interruption, signal delivery or physical worker termination are
implemented. Unexpected callback exceptions propagate, but cannot restore old
state; expected failures and reported timeouts fail closed unless superseded
by a newer state. The contract creates no watchdog and cannot enforce callback
deadlines. A future external trusted termination mechanism must operate without
waiting for this callback or the Python process, enforce bounded evidence age,
and survive supervisor loss. Python scheduling/GIL starvation and a callback
that compromises the supervisor are outside these offline guarantees.
The short state mutex is still required; it never spans external callbacks.
The neighboring source-boundary regression permits only the exact import of
`WorkerSpec` and its validator in this dormant module. It still rejects STOP
controller and containment-authority imports, including mixed imports.

The verifier is a supervisor-owned TCB dependency, never worker-selected.
There is no production implementation. Without one, evidence-dependent steps
fail closed. Tests inject a fixture oracle to exercise the contract; its states
are **model progress, not runtime facts**. All reports remain false in boolean
context and return false for runtime verification, execution authorization and
publication authorization, including READY and TERMINATED.

Evidence assessments are not credentials. Python object identity, dataclass
construction, a configured profile name, a check enum, or matching correlations
cannot authenticate a runtime observation. A malicious verifier or compromised
supervisor process is outside this model's trust boundary. Do not expose the
contract object or verifier installation to workers. Future integration must
authenticate the observer and prevent replay before returning any assessment.

Each request binds the complete worker spec (attempt, boot, unique UID/GID,
service, cgroup device/inode and resource limits), session, revision, source
state and target state. Assessments must match that request exactly. Cumulative
checks must be freshly re-observed for each phase, not copied from old success
bits. Revision binding prevents cross-phase/retry replay; it is not a wall-clock
freshness proof. A future verifier must enforce bounded observation age and
process lifetime identity, race-resistant descriptor pinning and authenticated
challenge/response using independently trusted runtime data.

## Required observations

| Phase | Independent evidence required |
| --- | --- |
| Setup confined | External manager authorized exact unit; pinned trusted launcher binary/hash/ownership and fixed invocation; exact setup profile enforcing; `NoNewPrivs`; dedicated cgroup identity and limits; manager outside containment with termination authority. |
| Namespaces established | All prior checks plus actual user, PID, mount, network, UTS and IPC identities; both UID/GID mapping stages and verified connected procfs provenance; trusted PID namespace reaper. |
| Input/seccomp verified | All prior checks plus canonical input beneath `/var/lib/gvai/inputs`, no-symlink resolution and pinned descriptor identity; read-only root/runtime/input; no writable host-backed mount; private `/scratch` tmpfs with exact size and `0700` mode; installed approved seccomp; descriptor isolation. |
| Worker confinement verified | All prior checks plus exact enforcing final label before any untrusted instruction, no effective setup/control authority, accepted kernel transition, `NoNewPrivs`, and empty effective/permitted/inheritable/bounding/ambient capability sets. |
| Terminated | Durable supervisor STOP, whole-cgroup kill request, independently observed pinned cgroup empty and every descendant reaped; external manager identity/authority still established. |

The exact approved seccomp identity remains
`gvai-worker-no-spawn-no-sockets-v1`. A filename, descriptor number or policy-ID
string is not proof. Authenticate filter bytes, architecture/ABI coverage and
trusted descriptor provenance; prove installation before worker code. Deny
fork/vfork/clone/clone3 and socket creation (including socketpair and applicable
compatibility ABIs). Audit alternate kernel interfaces and inherited sockets.
The older no-spawn builder is not this policy. Trusted setup and reaper creation
must precede the final no-spawn filter. No filter is generated or installed here.

No historical `/work` or writable `/tmp` allowance is reused. Runtime mounts
must follow the compiler's read-only plan. Input is not mounted by the compiler;
safe descriptor resolution and mounting remain explicit runtime obligations.
No manager, STOP, publication, cgroup-control, host socket or setup descriptor
may reach the worker. Stdio must also have explicit trusted provenance.

## AppArmor mechanism: supported upstream, unaccepted on target

Proposed identities, **not installed profiles**:

* Setup requirement: `gvai-setup`, distinct from `gvai-worker`.
* Candidate final stacked label: `gvai-setup//&gvai-worker`.
* Retaining a setup component is not retaining setup authority: every operation
  must satisfy both profiles. Worker denials must remove all setup operations.
  A setup-only label, standalone worker label or complain-mode label is not the
  proposed final identity.

The candidate mechanism is an exec-boundary mandatory stack, with a named
worker target and no inherit/unconfined fallback. Review an `rPx`-style
sanitizing named exec transition to `&gvai-worker` for the fixed trusted entry
binary, using the exact target parser grammar. This is a mechanism description,
not a policy rule ready to load. Missing target or denied exec must terminate
setup, never retry under a less confined label. No untrusted script, loader
hook, interpreter startup input or environment-controlled code may run before
the final stack. Worker confinement must forbid reverse transitions and policy
administration.

[Linux v6.8 domain.c](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/domain.c)
checks the new exec label against the confinement recorded for `no_new_privs`
using `aa_label_is_unconfined_subset`. Its comments explicitly describe stacked
subsets as permitted reductions. This is a label/subset constraint, not proof
that arbitrary replacement profiles will pass merely because their rules look
stricter. Keep `NoNewPrivileges` enabled; do not use an unconfined intermediate
or clear it to permit a transition. `Px` environment sanitization alone is not
a containment verifier or a guarantee about inherited descriptors.

[Ubuntu Noble aa_change_profile(2)](https://manpages.ubuntu.com/manpages/noble/man2/aa_change_profile.2.html)
describes immediate versus next-exec changes, permissions, descriptor caveats
and `EPERM` with confined `no_new_privs`. Its generic error description is not
enough to settle the target's stacking/subset behavior. Immediate replacement
does not create an address-space barrier; on-exec requests override ordinary
exec rules and need separate review. No `aa_change_profile`, change-hat,
on-exec override or privileged helper is implemented here.

[Ubuntu Noble apparmor.d(5)](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html)
documents profile transitions and exec modes. Verify parser grammar, named
stacking, target existence, profile namespaces, feature ABI and actual labels
on the exact Ubuntu kernel/package set. Upstream v6.8 source is not evidence
of the distribution-patched `6.8.0-142-generic` kernel's acceptance.

An exec boundary cannot be verified by untrusted worker self-report. A reviewed
trusted entry stub under the final label must validate containment before it
loads any untrusted code, with independent supervisor corroboration and no
path that bypasses the stub. Seccomp timing must accommodate only that fixed
trusted entry and must not permit later arbitrary exec. This trusted entry and
its verification channel do not exist yet.

## UID-map boundary remains unresolved

Historical stderr: `bwrap: setting up uid map: Permission denied`.
The prior source investigation attributes the fatal AppArmor open denial to
disconnected procfs path resolution through a pre-namespace retained mount FD.
It occurs before pathname permission matching; more `/proc` permissions are
not a repair. Both mapping stages can print the same error.

A separately reviewed connected-procfs launcher design must validate filesystem
type, mount identity and current namespace provenance at BOTH mapping stages,
preserve UID/GID and deny-setgroups semantics, and close setup references before
entry. Do not blindly replace the global proc FD used by other setup logic.
No broad procfs permissions, `attach_disconnected`, unrestricted userns,
unconfined mapping service or extra host privilege is proposed.

## Unresolved acceptance checklist (not executed)

Human authorization and an independently pinned disposable guest are required:

- Reconcile historical kernel `.147` with reported current `.142`; pin exact
  OS, kernel patches, parser/features, Bubblewrap and entry binary hashes.
- Review separate setup-unit versus final worker-unit compiler integration,
  including `NoNewPrivileges` and capability behavior during nested userns.
- Compile without loading first; reject missing features, unexpected grammar
  and profile conflicts. Parsing is not kernel acceptance.
- Prove exact setup and final stacked labels in enforce mode and denial of
  missing target, unsupported stack, failed exec, standalone/setup-only labels,
  complain mode, alternate interpreter and reverse transition.
- Prove no unconfined interval and no untrusted constructor/interpreter code
  before the trusted entry checks; test denial while `NoNewPrivileges=1`.
- Verify both mapping stages, connected procfs identities, private PID/reaper,
  mounts, root/cwd, cgroup, unique credentials, scratch limits, capabilities,
  seccomp bytes/installation and every inherited descriptor.
- Test file-write, socket, spawn, namespace, mount, ptrace, control-descriptor
  and publication denials from an independently authorized adversarial fixture.
- STOP at every setup/entry phase and during verification; supervisor loss,
  stale evidence, partial mapping and verifier errors must prevent entry.
  Observe whole-cgroup termination and complete reaping, not just leader exit.

**Next implementation:** define and review the fixed trusted-entry ABI and its
independent observation protocol, including process-lifetime identity and
pre-untrusted-code gating. Do not generate loadable policies until that design
and its relationship to the compiler have been reviewed.

## Preserved provenance

Base: `e8d2ac51ec99321a64cfc88a1affdc9167827551`;
branch: `feature/iron-switch-apparmor-reconciliation`.
Historical files in the primary worktree and draft PRs #16, #17 and #19
were not changed.

| Preserved source | SHA-256 |
| --- | --- |
| Historical `security/apparmor/usr.bin.bwrap.gvai` and untracked export in primary worktree | `b2dbb4efa689d85425491cb225a821779de965876bff5199cb10dbf22f7d38af` |
| Original policy at `668f30b8d561892f07431dea576fd40aed37235f` | `eaec1e1dc62f8f760e0fa24f15e839f220a97c71d3edbf9746cda46c5c34b4c6` |
| Unchanged worker-profile compiler | `3d488ba0b67062e2c1f28f22a7e6be493ea1457ba7c19ff958006db90c839111` |
