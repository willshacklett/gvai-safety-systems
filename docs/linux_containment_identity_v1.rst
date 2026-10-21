Dormant cgroup descriptor provenance v1
======================================

Scope
-----

``gvai/linux_containment_identity.py`` validates a narrowly defined set of
parent-supplied descriptors. No existing caller imports it. It is not wired to
the STOP adapter or sandbox executor and provides no launch, attachment,
migration, approval, reset, stop, publication or execution-ALLOW operation.
All existing deny-only gates and STOP semantics remain unchanged.

Never let the thing behind the switch own the switch. This API is exclusively
for a trusted parent operating outside the governed worker's security identity.
Its Python objects and caller-supplied expected identity do not authenticate
the caller. Never expose descriptor selection or expected identity to workers,
customers or arbitrary IPC requests.

Inputs and checks
-----------------

``ContainmentIdentity(device, inode)`` identifies a cgroup directory independently
selected and pinned by the trusted parent. ``ValidatedContainmentDescriptors``
requires that identity and three distinct descriptor numbers: ``directory_fd``,
``kill_fd`` and ``events_fd``. It accepts no filesystem paths or PIDs.

The implementation:

* Retains non-inheritable duplicates with ``F_DUPFD_CLOEXEC`` before inspecting
  them. Later checks never use the original descriptor numbers.
* Requires the directory to match the expected device/inode and be an actual
  directory on cgroup v2, as reported by descriptor-based ``fstatfs``.
* Requires both supplied control files to be regular cgroup v2 files on the
  same device, with distinct identities, owned by the current effective UID,
  linked and not writable by group/other.
* Requires the directory to have the same ownership/protection properties.
  The directory and events descriptor must be readable; kill must be writable.
  ``O_PATH`` descriptors are rejected, even when their access bits resemble
  read-only descriptors.
* Opens only fixed ``cgroup.kill`` and ``cgroup.events`` names relative to the
  retained directory, with no symlink following, close-on-exec and nonblocking
  flags. Checks their filesystem/type/ownership/access and compares their
  device/inode to the supplied retained controls.
* Rejects unsupported interfaces, failed checks and ambiguous identity without
  falling back to paths, worker assertions or a weaker filesystem check.

Opening a writable kill reference checks open access without writing to it.
No cgroup contents are read, no process is signaled and no membership is changed.
The libc ``fstatfs`` binding supports only Linux x86_64/aarch64 with 64-bit
pointers and longs. Other ABIs fail closed; support requires separate review.
No new dependency is used.

Lifetime
--------

On success the object retains all three descriptors until explicit ``close``.
The public API exposes only immutable identity metadata and idempotent closure,
not raw handles, a handoff to STOP or an authorization flag. Reading identity
after closure rejects. Construction failures close all retained duplicates and
temporary reference handles without closing the caller's originals. Close errors
do not trigger retries against potentially reused descriptor numbers.

The parent must not close/reuse originals during duplication or mutate their
shared open-file descriptions. Retention protects against subsequent numeric
FD reuse, not concurrent malicious activity inside the supervisor process.
Explicitly close successful objects; there is no garbage-collection cleanup
contract. Fork inheritance and process-wide descriptor access require independent
OS controls; close-on-exec alone does not prevent either.

What this does not prove
-----------------------

This is point-in-time descriptor correspondence, not independently verified host
enforcement. Expected device/inode must come from an independently trusted,
still-pinned directory; numbers alone are not durable identities across reboot
or cgroup deletion/recreation. Mount namespace/admin authority must be trusted
and stable during validation: device/inode checks do not authenticate mount
policy, reject every bind-mount arrangement or prevent privileged substitution.

The parent remains responsible for pre-execution placement, non-migration,
non-repopulation/non-reuse, safe cgroup delegation, worker exclusion from control
files, complete pidfd membership, exclusive reaping, descendant zombie cleanup,
independent STOP delivery, crash recovery and durable attempt-bound evidence.
No pidfds are accepted or validated here. File mode/UID checks do not prove
absence of ACL grants, writable ancestors, descriptor leaks, privileged attackers
or a shared worker UID. A root-only parent-owned laboratory configuration is a
future operational prerequisite, not an automatic result of these checks.

The existing STOP adapter still assumes provenance when called directly.
This dormant validator does not make that adapter, a lifecycle simulation or
HARD GATE into an operational approval system.

Evidence and deferred acceptance
-------------------------------

``tests/test_linux_containment_identity.py`` fakes all descriptor, filesystem
and libc syscall boundaries. It tests matched/mismatched identities, ordinary
and non-cgroup filesystems, substitutions, access modes, unsupported checks,
retention under original-FD reuse and partial-construction cleanup. The ctypes
boundary is tested with fake libc results, not live kernel observations.

Passing tests establish the check logic and resource ownership under those
fakes. Disposable-host acceptance must separately demonstrate actual cgroup v2
file identities/access, supported ABI behavior and resistance to unauthorized
substitution, before any integration. Bubblewrap/AppArmor UID-map resolution,
loaded-policy provenance and emergency recovery remain unresolved prerequisites.
No host experiment, policy load, positive admission, production configuration
change or deployment is authorized by this increment.
