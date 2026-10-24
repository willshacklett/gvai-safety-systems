# Read-only Linux self-observation runbook

## Scope and status

This is a proposed, controlled observation of the Python process running the
module itself. It does not inspect a worker, launch a worker, enter a
namespace, invoke Bubblewrap, change a service, or load a policy. It creates no
worker identity and makes no confinement claim. Every report is
`UNVERIFIED`; all authentication, runtime-verification, execution, and
publication fields are false.

The runbook has **not been executed**. A successful command means only that
some read-only kernel interfaces returned parseable observations. It is not
worker acceptance or evidence that the DigitalOcean lab, AppArmor policy,
Bubblewrap configuration, or lifecycle transition is safe.

## Preconditions

Before any controlled Linux observation:

1. Obtain human approval for the specific lab host, time window, and operator.
2. Confirm a known-good recovery snapshot and an independently tested
   out-of-band recovery path. Do not rely on SSH alone.
3. Confirm this exact source-only branch and reviewed commit are present.
4. Use an unprivileged shell. Do not use `sudo`, a service unit, a container,
   or an automation runner for this observation.
5. Ensure the terminal is private. Output includes process credentials,
   namespace inode identifiers, cgroup path, and open descriptor targets;
   those may disclose sensitive local paths.
6. Do not run while handling production secrets or other sensitive files.
   The descriptor inventory is for the observer process only, but can include
   paths to files it has open.

If any precondition cannot be established, do not run the command.

## Proposed command (do not execute during source-only preparation)

From the repository root on the specifically approved Linux test host:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m gvai.linux_self_observation
```

Do not add arguments, privilege escalation, `strace`, `tee`, redirection,
service management, or a wrapper that starts other processes. The command
prints one JSON report to the terminal and creates no intended files. Do not
save or distribute the output without a separate data-handling approval.
An exit status of zero means only that the report was emitted; it is never an
acceptance or authorization signal.

## Expected observations

The report always has `state: "unverified"` and contains only self-observation:

- PID and `/proc/self/stat` start-time ticks, with a pidfd status when the
  kernel and Python expose `pidfd_open`.
- Procfs status fields: real/effective/saved/filesystem UID and GID,
  `NoNewPrivs`, seccomp mode, and capability sets.
- UID/GID maps and `setgroups`.
- Effective AppArmor label, only if the kernel interface is available and
  explicitly reports an enforcing label.
- Inode/device pairs for the current process' namespace handles.
- The kernel-reported cgroup path and, where safely resolvable below the fixed
  `/sys/fs/cgroup` descriptor, cgroup-v2 inode/device and whether the process
  PID appears in `cgroup.procs`.
- Bounded open-FD target and flags inventory for this Python process.

Fields can be absent or checks can be marked `UNVERIFIED` when interfaces are
missing, denied, unavailable, unsupported, inconsistent, or inconclusive.
The procfs/cgroup reads use fixed paths, descriptor-relative traversal,
no-follow checks for ordinary components, nonblocking flags where supported,
and fixed byte/count limits. The report is not an atomic kernel snapshot.

## Failure and abort conditions

Do not retry with elevated privileges or weakened controls. Stop and preserve
the terminal output locally only if approved for incident handling when:

- procfs or cgroup-v2 cannot be verified at the fixed paths;
- pidfd support or PID correlation is unavailable;
- any check is `UNVERIFIED`, an observation is missing, or values change
  between reads;
- an AppArmor label, namespace handle, descriptor target, or cgroup path is
  unexpected;
- the command raises an error, hangs, or produces output other than one JSON
  report;
- the host recovery path or baseline changes unexpectedly.

No state produced by this tool authorizes execution, worker entry, STOP, or
publication. In particular, do not interpret an apparently expected
AppArmor label or seccomp mode as proof of a loaded/approved policy.

## Cleanup and recovery

The reader closes the descriptors it opens on normal exit. No service, policy,
kernel setting, namespace, or file is intentionally changed, and no cleanup
command should be necessary. If interrupted, allow the Python process to exit
normally; the kernel closes its descriptors. Do not use forceful process
termination, service restarts, policy reloads, or filesystem cleanup as part
of this observation.

If host state appears altered or the command does not exit, stop. Use only the
preapproved human recovery procedure; this harness provides no recovery or
termination authority.

## Kernel-interface limitations

- A pidfd is optional and does not authenticate the process to an independent
  verifier. A numeric PID and start time are observations, not trust anchors.
- Reads are byte/count bounded and commonly use `O_NONBLOCK`, but Python cannot
  impose a reliable deadline on every kernel `open`, `read`, `fstatfs`,
  directory enumeration, or namespace-handle operation. A stalled kernel or
  filesystem call may not be cancellable safely. Do not run where a strict
  wall-clock deadline is mandatory.
- `/proc/self` exposes the caller as resolved by procfs; namespace and cgroup
  views may be relative to the caller's namespaces or mount configuration.
- The `/sys/fs/cgroup` mapping can differ from the path reported by procfs.
  A mismatch or inaccessible descendant is unverified; no fallback path is
  searched.
- Descriptor enumeration races with descriptor changes, and target strings
  do not prove retained open-file identity.
- Proc status values for capabilities, seccomp, and `NoNewPrivs`, and the
  AppArmor current label, are self-observations. They do not prove policy
  provenance, enforcement correctness, or absence of earlier unconfined code.
- UID/GID maps do not prove how or by whom the mapping was installed.
- Repeated reads detect some inconsistency but do not form an atomic snapshot.

## Why this is not worker acceptance

The tool observes only itself and does not receive independently pinned
worker handles or an approved `WorkerSpec`. It does not authenticate a
supervisor, launcher, process handle, cgroup descriptor, seccomp program, or
AppArmor profile. It does not test the worker entry transition, UID-map setup,
input pinning, scratch isolation, cleanup, or STOP behavior. It cannot make
the existing worker-entry gate pass and must never be wired to do so.

Any later worker acceptance requires a separately reviewed design and
independent trusted runtime verifier, followed by a distinct approved test
plan.
