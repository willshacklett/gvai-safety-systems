# I8B disposable-VM STOP-veto acceptance contract

Status: TEST-ONLY PLAN. No VM, unit, profile, authority state or workload is
created or activated by this document. No host guarantee has been established.
Baseline: `cfa7f3a9cf9a17c439ef4bff5fc87db0ddc5ef11`. Any later executable
candidate needs its own recorded SHA, review and explicit execution approval.
PR #48 remains Draft.

This contract separates three claims:

- **A: admission denial** by an independently authenticated backend STOP veto.
- **B: local durable recording** and reconciliation of an exact signed STOP.
- **C: externally observed termination** of an uncooperative process tree and
  its complete experiment cgroup.

Passing one does not imply either of the others. See the
[I7B mechanism and limits](external_stop_gate_v1.md#i7b-independent-backend-stop-only-veto).
The older [Lab-01 runbook](lab01_stop_gate_validation_runbook_v1.md) is not an
execution procedure for this milestone: its armed-work assumptions and
provisioning sequence do not establish the I6D/I7B prerequisites. Lab-01,
production activity and production identities are outside this contract.

## 1. Authorization and containment prerequisites

Execution is blocked until every prerequisite has affirmative evidence:

1. A newly allocated, genuinely disposable VM has a recorded provider resource
   ID, boot ID, disk IDs and expiry. It is not a shared Codespace, production
   host or restored production snapshot. No customer data or real credentials
   may be copied into it.
2. Use synthetic keys, synthetic downstream credentials and reversible local
   synthetic effects only. STOP and ARM signers, gate, backend, untrusted client
   and observer have distinct roles and identities. Private signing keys are
   inaccessible to workload identities; logs contain public fingerprints only.
3. There are no production/private-network attachments, production DNS
   dependencies, shared storage, forwarded agents or production routes.
   Provider firewall and guest routing policies deny workload ingress/egress
   except the explicitly inventoried local experiment channels. No public STOP
   or workload endpoint is permitted.
4. An operator outside the VM has verified provider-console/power-off/destroy
   access, a bounded expiry teardown and a second way to identify the VM.
   Teardown must not depend on guest SSH, gate health or the tested filesystem.
   Any narrowly allowed evidence-export path is separately inventoried.
5. Before starting, approve a manifest of exact experiment unit names, sockets,
   directories, UIDs/GIDs, AppArmor profiles, mounts, network rules and cgroup
   paths. Refuse collisions with preexisting resources; do not overwrite them.
   Record the guest boot ID and systemd invocation IDs as resources appear.
6. Preapprove load limits, deadlines, case count, fault-release mechanism,
   observer placement, evidence destination and rollback operator. Faults use
   disposable storage only, never the VM root disk or observer evidence store.

All preparation and activation require a later, separately authorized milestone.
This plan does not authorize package installation, user creation, provider API
changes, profile loading, unit installation or any host experiment.

## 2. Known implementation dependencies and inhibition boundary

The checked-in systemd backend currently has no dedicated STOP listener or
trusted STOP-key provisioning. Local `backend_process_main` has an optional
listener; it is not evidence that the deployment entrypoint supports STOP.
Before execution, a separately reviewed disposable-only adapter must wire the
listener, key configuration and observer evidence. Do not silently substitute
the local entrypoint for the real systemd path being claimed.

Production startup remains unconditionally recovery-inhibited. No gate ARM,
notice, permit, sequence, counter, boot change or restart may clear inhibition.
Do not add a production rearm/repair API, environment toggle or deployed private
field assignment to satisfy this plan.

Two explicitly labeled test tracks are required:

- **Unmodified startup track:** the ordinary backend must remain inhibited,
  including after replacement and socket activation. This proves denial on
  startup, not interruption of an executing workload.
- **Synthetic preauthorized-session track:** a reviewed test-only harness may
  model a session admitted before the case starts, using the existing private
  setup concept. It must not be installed as a production entrypoint or exposed
  to requests. Record its exact diff and the preauthorization event. Never use
  that seam after STOP or on a replacement process. Its results support only
  this synthetic-session claim, not production admission/rearm readiness.

C also requires a reviewed trusted termination controller outside the workload
cgroup, able to terminate every descendant without workload cooperation.
The backend's own exit callback is not that controller. Controller identity,
trigger authentication, resource budget and kill authority remain unresolved;
without them, C is UNKNOWN and host shutdown readiness is NO-GO.

## 3. Measurement and verdict rules

These are proposed acceptance thresholds for the disposable experiment, not
existing service guarantees. Freeze them before execution; do not relax them
after a failure. Changes require a new contract revision and fresh runs.

Use one trusted host observer's monotonic clock for comparisons. Record boot
IDs, clock resolution and event-capture uncertainty. Cross-host wall-clock
differences cannot establish a bound. The observer/effect sink must be outside
the workload cgroup and blocked storage, inaccessible to workload writes except
through its defined synthetic-effect protocol.

| Measurement | Definition | Required threshold |
|---|---|---|
| A1 | Observer releases signed STOP to the client until the exact authenticated-endpoint denial reply is observed, including connect/send/receive | At most 1.0 s |
| A2 | Independently observed veto installation to cooperative operation cessation/cancellation observation | At most 0.5 s |
| A3 | Attempts submitted after confirmed installation | Zero newly admitted operations/effects; test for at least 10 s |
| B1 | Confirmed release of injected storage blockage to exact durable confirmation and reconciliation under healthy storage | At most 5.0 s |
| C0 | Observer releases the signed STOP trigger to trusted controller authenticated acceptance | At most 1.0 s |
| C1 | Trusted controller accepts the authenticated termination trigger to all recorded descendants gone and cgroup empty | At most 2.0 s |
| C2 | After termination, including attempted reactivation | No synthetic effects or unauthorized execution for at least 10 s |

Capture trigger times, veto installation, operation admission/start/completion,
effect requests/receipts, cancellation, controller actions, process exits,
cgroup state and client outcomes. A2/A3 require reviewed instrumentation; do
not infer installation time from a delayed reply. For B1 no bounded durability
is asserted before blockage release. B1 is a test-specific healthy-storage
budget, not a bound for arbitrary disk failures.

For any claimed upper bound, the measured interval plus worst-case capture and
clock uncertainty must meet the threshold. Unbounded uncertainty is UNKNOWN.
C0 and C1 together require at most 3.0 s from trigger release to complete
termination; a fast kill after unbounded trigger delay does not PASS C.

For each claim and case:

- **PASS:** prerequisites and positive controls pass, all required observations
  are complete, identity-bound and within bounds, and adversarial attempts
  preserve the specified invariant.
- **FAIL:** an observed unauthorized effect, privilege escape, successful
  substitution, cleared veto/inhibition, false confirmation or deadline breach
  with functioning measurement. One counterexample fails that claim.
- **UNKNOWN:** missing/truncated evidence, observer loss, failed positive
  control, unsupported host feature, ambiguous identity/time, skipped case or
  unresolved dependency. Missing events never mean success or non-application.
  If a failure was observed, missing later evidence does not erase it.

Every mandatory case must PASS for that scoped claim. FAIL or UNKNOWN blocks
promotion and triggers rollback. Retain the three separate verdicts; no single
"STOP succeeded" field. A transport timeout is UNKNOWN for that submission;
later independent evidence may establish state but cannot rewrite its outcome.
Historical test counts and green CI are not host acceptance evidence.

## 4. Required test cases and positive controls

Each timing-sensitive matrix cell requires at least 20 clean repetitions at
idle and at the preapproved maximum load, with every result retained and no
averaging away misses. This supports only the tested host/configuration/load,
not universal availability. Use fresh disposable case state, or a fresh VM
where crash/fault cleanup cannot be trusted; never clear a veto to reuse a case.

### A. Independent STOP admission denial

1. Prove the synthetic preauthorized workload produces externally counted
   effects before STOP. Hold permits/notices fresh with recorded validity;
   verify a no-STOP control continues executing under the same storage fault.
   Denial caused only by stale notices, expiry or startup inhibition fails the
   independent-veto positive control.
2. Exercise ARM-first, STOP-first, simultaneous and same-sequence cases, with
   ARM held at read, write, fsync and replacement boundaries. Event injection
   and real disposable-filesystem stalls are separate cases. Prove ARM remains
   blocked throughout A1/A2, without blocking observer or backend storage.
3. Observe authentic signed STOP acknowledgment, installation, rejection of
   otherwise-valid fresh operations and cancellation of already-active
   cooperative work. Replay historical authentic STOP idempotently; it must
   not require sequence storage or change durable gate history.
4. Try delayed notices, higher sequences/counters, new/old boot IDs and late
   ARM completion. No path may clear denial. Test backend replacement, gate
   restart and socket-triggered startup using the unmodified inhibited track.
5. Wrong target, ARM command, wrong role/key, request-supplied key substitution,
   malformed/duplicate-field/oversize input and signature/body tampering must
   not change authority. In a separate no-STOP control session, valid work must
   still succeed after each rejected input; otherwise rejection could mask
   unrelated denial. Malformed input need not have identical error text.
6. Drop requests, lose replies, abandon the caller, fill the socket backlog,
   delay connect/send/read and sever the notice channel. The observer records
   actual state separately. The client must not label ambiguous transport as
   confirmed denial, confirmed non-application or durable recording.

Effects started before veto may be irreversible; record their admission/start
times. A forbids new admission after installation, not retroactive undo.
Any required absence of continuing uncooperative effects belongs to C, not A.

### B. Durable signed STOP recording and reconciliation

1. Submit the exact signed STOP through the gate's authenticated control path,
   separately from A. Record its public signed envelope digest, target, key ID,
   sequence and transaction identity. Never interpret a veto receipt as B.
2. While persistence is blocked, report UNKNOWN. After release, require exact
   signed-command, anchor, store and transaction-receipt agreement following
   file/directory synchronization and readback. Reconcile the same digest, then
   restart and re-confirm. A positive control must demonstrably persist and
   reconcile a distinct fresh case on healthy storage.
3. Exercise every I6D transaction barrier with process exit and syscall faults;
   include lost replies, torn/missing/duplicate metadata, symlink/hardlink
   substitution, conflicting commands and legacy state. Ambiguous/pending
   state must deny recovery and must not report exact application.
4. Exact replay may confirm the matching durable head; wrong target/role/key
   must be rejected. A superseded STOP is not proven by a newer head.
   Record UNVERIFIABLE/UNKNOWN without automatic repair or reprovisioning.

B proves only the tested local persistence/recovery contract. Process crashes
and fsync receipts do not prove physical power-loss durability, independent
rollback resistance or termination. Those require separate storage assumptions
and fault campaigns; do not weaken the wording to imply they were exercised.

### C. Uncooperative process-tree/cgroup termination

1. Establish a synthetic worker plus child/grandchild tree that ignores
   cooperative cancellation and, in separate cases, normal termination
   signals. The external observer must see effects from each worker first.
   Identify processes by boot ID, PID plus start time or pidfd, unit invocation
   and cgroup membership; a PID or empty audit list alone is insufficient.
2. Invoke the separately authenticated trusted controller. Capture its trigger
   receipt, cgroup-wide action, every recorded exit and cgroup membership/event
   snapshots. Include fork/exec, reparenting, attempted cgroup escape and PID
   reuse. Workload identities must lack delegation/permissions to escape.
   The reviewed adapter must bind the automatic controller action to the exact
   authentic signed STOP and target, independently of an untrusted backend
   reply. A manual operator kill after STOP proves cleanup only, not C.
3. Require C0/C1/C2, including no surviving descendants, an empty original cgroup,
   and all replacement invocations remaining inhibited. Exercise restart
   policy, queued socket traffic and attempted manual/socket activation.
4. Test cooperative cancellation and application self-exit separately as
   controls; neither satisfies C. Kernel-uninterruptible tasks or missing
   cgroup observations cannot count as termination. A measured overrun fails
   the deadline; invoke out-of-band teardown instead of extending it.

## 5. Isolation, authority and pressure matrix

| Boundary | Required observation and adversarial cases |
|---|---|
| Socket paths | Root-controlled, non-client-writable ancestors; lstat/stat ownership, mode 0600, socket type, device/inode and lifecycle evidence. Attempt symlink, rename, unlink/rebind and stale-socket substitution as each untrusted identity. Any untrusted replacement succeeds: FAIL. |
| Socket peers | Record actual SO_PEERCRED UID/GID/PID and identity binding on accepted connections and trusted client-to-server connections, including PID reuse handling. A substituted server must not manufacture a trusted confirmation. Root/kernel compromise remains out of scope. |
| Listener routing | Verify each actual activated FD's socket/path, name and owner. Service/notice listeners reject STOP and STOP ingress rejects ARM/execute/notice. The authorized operator connects; client/gate/backend identities receive only their approved access. Possession without a trusted signature never grants STOP authority. |
| Signed authority | Root-controlled public-key/config provenance, target and role binding, distinct STOP/ARM/gate keys, pinned fingerprints, negative unknown-key controls. Define rotation/revocation and historical replay policy before execution; no request-provided trust roots or private keys in the backend. |
| Files and credentials | Distinct non-login users/groups, immutable candidate code/config for workload UIDs, protected I6D transaction state and synthetic downstream credential accessible only to its intended owner. Attempt reads/writes/renames, ptrace, signals, procfs access and descriptor leaks; owner-positive controls must succeed. |
| AppArmor | Parse reviewed experiment profiles, explicitly select distinct role labels, and capture enforce mode on every process/descendant. Both drafts attach to the same interpreter pattern: do not infer correct role attachment. Complain mode or an absent label is not acceptance. |
| systemd/cgroups | Capture effective merged units/drop-ins, actual UIDs, capabilities, namespaces, mount restrictions, credential delivery, control-group kill and restart behavior. Verify nondelegated cgroup v2 membership, limits and controller isolation, not just unit text or a security score. |
| Network | Verify provider policy, guest routes/namespaces and effective AF_UNIX-only role restrictions. Test denied IPv4/IPv6 creation/connect, inherited network FDs, Unix peer access and synthetic downstream bypass. Use owned disposable endpoints only; require positive reachability controls outside the restricted role. |
| Resource pressure | Predeclare finite CPU, memory, task/thread, FD and backlog limits and reserved observer/controller resources. Test idle clients, malformed/partial frames, floods, slow consumers and concurrent work at each approved limit. Capture usage, throttling, OOM and scheduling evidence; apply A/C deadlines or report FAIL/UNKNOWN. No guarantee under arbitrary exhaustion. |

Independent observers need positive liveness/effect controls before and after
each case. Workloads must not forge, truncate or selectively drop observer
records. A gap in observation cannot prove absence of effects. Synthetic
effect delivery/acknowledgment latency must be measured and included in timing
uncertainty; polling intervals cannot hide a deadline breach.

## 6. Python 3.11 and evidence bundle

Use CPython 3.11 for the candidate, every spawned interpreter, observer adapters
and activated units. Record exact executable paths, versions, environment,
with secret values redacted, package versions/hashes and installation source.
Install only reviewed
dependencies in a later authorized preparation step. Do not copy native
cryptography/cffi extensions between interpreters or assume `/usr/bin/python3`
matches the invoking environment.

Before any host claim, the later milestone must run focused I7A/I7B, I6D
recovery, socket, subprocess and resilience tests plus broad regressions on
that 3.11 environment. Capture collection, PASS/FAIL, every skip/xfail/XPASS and
exit status. Existing ARM V2 proposal xfails remain visible, not evidence that
those properties work. Mandatory host cases cannot be replaced by CI, skipped
root tests or the historical Python 3.14.7 totals.

The evidence manifest must include:

- Approved scope, operator, case IDs, VM/resource identifiers, candidate SHA,
  harness diff/hashes, clean-source inventory and per-artifact SHA-256.
- OS/image, architecture, kernel, Python/dependencies, systemd, AppArmor and
  cgroup versions; boot IDs, clock/observer calibration and case load limits.
- Effective unit/socket/profile/config hashes, public authority fingerprints,
  ownership/ACLs, peer credentials, process start identities, namespace and
  mount layouts, cgroup membership/limits, firewall/routes and allowed paths.
- Raw timestamped requests/replies, public signed-command digests, independently
  observed effects, barrier transitions, cancellation/controller/exit evidence,
  restart attempts, readback/reconciliation verdicts and relevant system logs.
- All positive/adversarial case results, repetitions and latency maxima,
  missing evidence, deviations, rollback actions and provider teardown receipt.

Exclude private keys, credential values and customer data from every artifact.
Use bounded, preallocated evidence storage independent of faulted mounts.
Hash and export an allowlisted redacted bundle to an operator-controlled
destination; that destination and its trust boundary are part of approval.
Do not claim tamper-proof evidence against a compromised observer/root/kernel.

## 7. Failure rollback and final teardown

This is the required order, not an executable command recipe:

1. On any FAIL, UNKNOWN, deadline breach, identity mismatch, unexpected route,
   lost observer or expiry, stop new cases. Close synthetic ingress at its
   trusted boundary; do not wait for gate reconciliation.
2. Prevent reactivation before killing workloads: stop and block the manifest's
   experiment socket units, queued activation and service restart paths,
   including timers/path units if present. Verify that only those inventoried
   units are affected. Ordinary shutdown alone is insufficient.
3. Reconfirm boot/unit/cgroup identities, then have the trusted controller
   terminate only the recorded experiment cgroups and all descendants.
   Never use name-based global kills, wildcard deletion or PID-only matching.
   Do not target observer/controller until their bounded evidence capture ends.
4. If identity cannot be confirmed, the guest stalls, tasks survive or cleanup
   exceeds a 5.0 s guard, do not broaden guest cleanup. Use the independent
   provider power-off/destroy path for the recorded VM. Best-effort evidence
   capture must not postpone containment; lost evidence leaves claims UNKNOWN.
5. Preserve the allowlisted evidence and faulted authority artifacts read-only
   when possible, without secrets. Do not clear vetoes, restore an armed
   snapshot, delete transaction history, auto-repair state or reuse credentials.
   Retain failure outcomes even if cleanup later succeeds.
6. Destroy the disposable VM and its manifest-listed disks, temporary network
   resources and synthetic secrets through the approved provider mechanism.
   Obtain an out-of-band deletion receipt and confirm no experiment endpoints,
   instances, disks or scheduled restarts remain. Retain only approved evidence.

Success also ends with teardown, not promotion to service. Until destruction
is independently confirmed, cleanup is UNKNOWN and the operator must continue
out-of-band containment/escalation. Never recover service by disabling denial.

## 8. Next authorization gate

The next candidate milestone is a separately reviewed TEST-ONLY implementation
of this contract's missing harness/adapter, observer and termination controller,
followed by an explicit disposable-VM execution approval. Resolve key custody,
socket peer policy, role-profile attachment, cgroup controller authority,
resource envelope, fault mechanism and evidence-export policy first.

I8B passes as planning only when those dependencies are listed, the three claim
criteria remain distinct, production inhibition remains untouched and rollback
is mandatory. No host claim can PASS from this document alone.
