Disconnected STOP ownership foundation v1
========================================

Scope
-----

``gvai/supervisor_stop.py`` and ``gvai/linux_containment_stop.py`` are dormant,
trusted-parent-only components. No existing runtime imports them. They provide
no launcher, attachment, migration, admission, approval, publication, reset or
unstop operation. Every report is false in boolean context and explicitly
denies admission and authentication. HARD GATE, the executor, model egress,
encrypted storage, authentication, human approvals, audit configuration,
Linux policy, deployment and the public website are unchanged.

Never let the thing behind the switch own the switch. Python object privacy
and exact-type checks are not authentication or an OS security boundary.
Workers must have neither access to these objects nor access to their process,
descriptors, journal directory, credentials or control IPC. Future integration
requires a separately privileged supervisor identity and protected IPC.

Journal contract
----------------

``StopJournal(directory_fd)`` duplicates a trusted parent's directory descriptor,
checks directory ownership and absence of group/other write permission, and
holds a nonblocking exclusive ``flock`` on ``stop.lock`` until ``close``.
The parent must independently protect the directory and all ancestors against
replacement, bind mounts, descriptor theft and deletion. Use a local filesystem
with reliable atomic rename, fsync and advisory-lock semantics, not a shared
network filesystem. A second owner is rejected; callers must still attempt
emergency cleanup if construction itself fails.

``stop.json`` contains exactly ``version`` (integer 1), ``stopped`` (true),
``generation`` (a nonnegative integer through 2**63-1, or null for unknown),
and ``uncertain`` (boolean). Records must be private regular files with one
link. Duplicate keys, invalid types, unsafe files and oversized records are
rejected. No sensitive workload data, prompts or credentials are recorded.

Missing state yields STOP with unknown generation and permanent uncertainty,
not generation zero. A STOP request can persist this unknown-generation
tombstone. Invalid existing state or a crash-left ``stop.pending`` or
``stop.intent`` is preserved
and cannot be repaired automatically. Valid historical STOP snapshots retain
their generation; repeated STOP requests are idempotent. The maximum generation
is permanently uncertain and never wraps. This component cannot advance to a
new execution epoch or establish an initial authoritative execution generation.
Tests seed valid historical snapshots; no production provisioning or permissive
recovery API is provided.

``latch`` first exclusively creates and syncs a private ``stop.intent`` and
its directory, then exclusively creates a private ``stop.pending``, handles short
writes, fsyncs the file, atomically replaces ``stop.json`` and fsyncs the directory.
Only after the record is durable is the intent removed. A failure to sync
that final intent deletion cannot invalidate the already-durable record; a
resurrected intent on restart conservatively causes uncertainty.
A write/sync/rename failure permanently poisons that journal instance.
Crash-left intent is not deleted on reopen. A record directory-sync failure may
leave renamed bytes visible after restart, but the previously durable intent
still prevents certainty; visible bytes alone do not prove the failed commit
was durable. Startup always remains stopped regardless.
Storage loss or malicious deletion cannot be diagnosed from a surviving old
snapshot; external trusted storage/recovery controls remain necessary.

``durable`` means this STOP record's write and synchronization completed under
the assumed filesystem semantics, not that storage is tamper-proof or a
distributed fencing service. No missing/corrupt state grants permission.
Journal closure attempts each owned descriptor once even if an earlier close
fails, then propagates the first close error without retrying any descriptor.

Containment ownership contract
------------------------------

``OwnedContainment(kill_fd=..., events_fd=..., child_pidfds=(...,))`` accepts
only distinct, already-open parent-owned descriptors and retains non-inheritable
duplicates. It accepts no paths, numeric PIDs, worker acknowledgements or target
lookup instructions. The parent may close its originals after construction;
it must not mutate shared file descriptions or race construction with closure.
``close`` is serialized against ``stop`` and permanently invalidates the handle.

Before construction the trusted parent MUST independently establish:

* The kill and events descriptors belong to the same dedicated cgroup v2
  attempt; ``cgroup.kill`` is supported and the events descriptor is readable.
* All untrusted execution was placed in that cgroup before any untrusted
  instructions, with no migration, cgroup administration or inherited control
  handles available to workers.
* Each pidfd identifies an unreaped direct child owned by this sole reaper;
  the nonempty set completely covers trusted launchers/namespace init processes.
* A trusted namespace init/reaper accounts for descendants. Cgroup emptiness
  alone does not prove that all zombie descendants were reaped.
* Descriptors are genuine kernel control handles, not writable ordinary files,
  substituted event streams, sockets or worker-controlled descriptions.
* The cgroup is never reused for a new attempt or repopulated after cleanup;
  no competing reaper consumes the retained children's wait results.

The adapter does NOT authenticate descriptor provenance, common membership,
reaper completeness, kernel support or the parent itself. Passing integers or
constructing an object proves none of these prerequisites. This interface must
never be exposed to customers or workers. A future independently reviewed
host-side provisioning boundary must establish the above invariants.
Containment closure likewise attempts each retained descriptor once, propagates
the first close error after all attempts, and never retries an ambiguous number.

``stop`` writes only ``1`` to the retained kill descriptor, seeks/reads the
retained events descriptor and uses nonblocking ``waitid(P_PIDFD, WEXITED |
WNOHANG)`` on retained child pidfds. Reaped children are cached so duplicate
STOP never waits on a reused numeric PID. Missing kernel interfaces and
operation failures remain uncertain; no weaker process-group fallback exists.
Kill failure does not skip observation or reaping; one containment failure does
not skip another. Worker messages cannot mark cleanup complete.

Controller and evidence
-----------------------

``StopController`` starts stopped. ``register`` is trusted ownership registration,
not process attachment: it immediately stops every registered containment even
if registration precedes the first explicit STOP. ``request_stop`` serializes
with registration, latches STOP in memory, attempts all cleanup before storage
IO, then persists the STOP record. Storage failure therefore cannot prevent the
termination attempt. There is no live work or publication operation to race.
Future dispatch and publication require additional authoritative ordering.

Cleanup evidence has three states:

* ``pending``: the kill write succeeded, but population or owned-child reaping
  is not yet complete.
* ``terminated``: the kill write succeeded, cgroup events reported
  ``populated 0``, and all specified direct children had kernel-observed exit
  results consumed by this reaper, subject to the provisioning contract above.
* ``uncertain``: missing containment, unsupported interfaces, malformed
  observations, failed kill, storage failure or ambiguous reaping.

The report retains separate cleanup evidence and journal state. Its aggregate
status is uncertain whenever journal state or durability is uncertain, even
if cleanup evidence says terminated. Terminated is evidence for the specified
handles only, never permission to execute or a claim of verified host safety.
``ECHILD`` is not accepted as successful reaping. Uninterruptible tasks may
remain pending indefinitely. Calls are not a watchdog, lost-message detector,
authenticated cancellation channel or bounded-time shutdown service.

Validation, deferred acceptance and rollback
-------------------------------------------

The two focused test modules use real temporary-file journal IO and injected
Linux syscall boundaries. They do not signal real processes, write real cgroups,
launch sandbox workloads, contact model APIs or change infrastructure.
They measure Python control flow, syscall arguments, restrictive restart and
fault handling, not actual descendant containment or production cleanup.

Before any integration, separately approved disposable-host tests must verify
descriptor provenance, pre-exec placement, migration resistance, descendant
and zombie cleanup, PID namespace behavior, supervisor/manager death, crash
reconciliation, persistence cuts, independent authenticated STOP and atomic
STOP-fenced output publication. Durable generations shared with dispatch,
revocation, expiry, control leases/watchdogs, cross-host coordination and host
service-manager configuration remain deferred.

Rollback of this disconnected increment removes its five additions only.
Never roll back deployed control state by deleting STOP records, resetting
generations or enabling a weaker cleanup mechanism.
