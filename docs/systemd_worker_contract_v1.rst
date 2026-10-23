Independent supervisor / systemd worker contract v1
=================================================

Scope
-----

``gvai/systemd_worker_contract.py`` is dormant, deny-only research. It contains
no D-Bus client, unit definition, launch operation, approval verifier, reset,
unstop or publication operation. No production caller imports it. Its tests
use a fake manager and real temporary STOP journal files, never workers.

Authority and identity
----------------------

Only the trusted supervisor may construct specifications and supply the manager
adapter. Each specification binds an exact UUID attempt, host boot UUID, pinned
cgroup device/inode, positive non-root UID/GID, and positive memory, task, CPU
quota and scratch limits. The fixed unit name is derived from the attempt UUID;
no arbitrary unit name or command enters the interface. Attempts cannot be
rebound or share a UID/cgroup within a controller's retained history.

The supervisor, host manager and publication authority remain outside worker
containment. Workers must have no access to their credentials, journals, IPC,
control descriptors, cgroup administration, configuration or authoritative output.
Worker dictionaries and acknowledgements are not manager evidence.

Fresh UUID session/request correlation rejects cached observations across calls
and supervisor restarts. It is NOT authentication. A future adapter must obtain
evidence from an authenticated, exclusively administered manager and verify
effective kernel state, not merely configured unit properties. This module
cannot discover a dishonest manager, hidden worker or forged in-process record.
The offline observation validator shares the contract's structural checks. Its
result is explicitly non-authoritative: even a complete, correctly correlated
record does not authenticate the manager, authorize execution or publication,
or establish runtime isolation.

Reaping and compatible reuse
---------------------------

The trusted manager owns direct-child waiting and a trusted descendant-reaper
arrangement. It must account for ALL descendants before attesting terminal
cleanup. Unit inactivity, main-process exit and cgroup ``populated=0`` alone
do not prove reaping. There is no ``waitid`` or pidfd binding in this contract.
The existing Linux STOP adapter and validator's ``bind_stop`` require the
supervisor to be sole reaper and are deliberately not reused for manager children.

The existing StopJournal, StopState, CleanupEvidence and ContainmentIdentity
value type are reused. The identity value is NOT descriptor validation.
The caller retains ownership of the journal and closes it after the contract
is no longer in use; the contract opens or retains no additional descriptors.
A future host adapter may use the existing descriptor validator for pinned
cgroup checks, but must not attach its supervisor-owned-child reaping adapter.
Systemd remains the cgroup lifecycle owner; no second cgroup administrator is
introduced here.

Required isolation
------------------

All six existing namespace separations (user, PID, mount, network, UTS, IPC)
remain mandatory. Zero capabilities, no-new-privileges, enforcing AppArmor,
socket/spawn-denying seccomp, private read-only runtime/input and bounded scratch,
no host sockets/control FDs, no migration and placement before untrusted execution
are required observations. Resource limits must exactly match the fixed spec.
Unknown restriction names, missing restrictions or contradictory cleanup fields
are rejected. These labels express obligations, not a mapping to systemd settings.

Ubuntu 24.04's systemd facilities alone have NOT been shown to implement this
entire contract, especially PID/user isolation and complete descendant reaping.
No namespace is dropped to make the backend appear compatible. If maintained
facilities cannot satisfy these requirements, the backend remains unavailable.

STOP, restart and output
------------------------

Registration always cancels; STOP cancels every known worker before journal IO.
Manager failures do not skip other cancellations. Missing/uncertain journal state
never initializes an admission generation. No cleanup-only result admits work.
Manager calls are synchronous under the contract lock; this offline model makes
no bounded-latency guarantee. A future transport must bound observation and
cancellation requests and provide manager-side supervisor-loss cleanup. A hung
adapter is not covered by Python exception handling or the fake-manager tests.

Every controller restart has a fresh session and requires a complete, correlated
inventory of the fixed worker-service namespace and successful cleanup before
it reports reconciliation. Omitted known attempts, duplicate entries and unknown
responses fail closed. An empty inventory can establish no known live work only
when explicitly complete. A supervisor cannot independently prove inventory
completeness; that is an adapter trust obligation. Previous-boot resources,
cross-instance exclusive ownership and durable attempt-name non-reuse need host
reconciliation; mismatched boot identities are rejected, never silently adopted.
The manager must clean up on supervisor loss without relying on its crash handler.

OutputFence is correlation metadata, NOT a credential. Session plus local revision
changes invalidate earlier fences on every STOP/registration/reconciliation.
``check_output`` always returns a denial, including for a current fence. There
is no output path, byte stream or publisher callback. A future publisher must
atomically serialize authoritative promotion against the durable STOP fence;
checking this interface and then renaming a file would be an unsafe TOCTOU.
The local revision is not a durable distributed fencing generation.

Offline and host acceptance gates
---------------------------------

Fake-manager tests establish only restrictive control flow. Before any separately
authorized Linux test, independently verify emergency recovery, protected manager
IPC/identities, immutable unit configuration, all effective restrictions and
resources, dedicated cgroup identity/membership, complete manager inventory,
reaper ownership, absence of worker controls and inherited authority, and
supervisor-loss cleanup. Demonstrate STOP deadlines (uncertainty on timeout),
descendant termination AND reaping, boot/restart reconciliation and atomic output
fencing separately. No host test, policy relaxation or execution ALLOW is
authorized by this increment.
