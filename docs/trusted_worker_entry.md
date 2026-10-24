# Trusted worker-entry evidence contract

## Disposition

Source-only, deny-only protocol model built from
`308d496d25f945eed131eb0d99588913d9aeab51` on
`feature/iron-switch-trusted-entry`. No production authenticator, authenticated
process pinning/runtime collector, policy, transport, worker entry or launcher is implemented.
No kernel or AppArmor acceptance has occurred. **Stop for human review.**

[The exchange](../gvai/trusted_worker_entry.py) is compatible with the
[lifecycle request](../gvai/launcher_worker_contract.py) as a correlation model,
not a production `TrustedLifecycleVerifier` implementation. The lifecycle source,
its unconditional worker-entry block, STOP ownership and publication boundaries
remain unchanged.

The separate [Linux collector foundation](../gvai/linux_worker_evidence.py)
uses fixed process-field keys and parent-provided pinned descriptors. It does
not install a lifecycle verifier or convert collection into acceptance.

## Identity and trust boundary

Every challenge and response binds:

* Exact boot and worker attempt identities and their fixed systemd service name.
* The complete lifecycle request: session, revision, previous/target state,
  unique UID/GID, resource limits and cgroup identity.
* Process lifetime: PID hint, start ticks, pinned PID-namespace device/inode,
  and a 32-byte binding to an independently retained lifetime handle.
* Pinned cgroup device/inode, consistent with the worker specification.
* Trusted launcher artifact device/inode and SHA-256.
* Expected verifier artifact and independently provisioned trust-anchor digest.

These are expected identities and claims, **not proof of authentication**.
A PID, start time, UUID, pathname, descriptor number, digest, handle-binding
bytes or a response repeating the challenge cannot prove that a trusted observer
actually pinned anything. A future trusted collector must retain a suitable
kernel lifetime handle, verify liveness and actual membership, prevent PID and
inode reuse, and authenticate observations against independently provisioned
trust roots. Pin tokens are correlation references, not worker-created handles.

The supervisor alone constructs the exchange with an independently approved,
complete lifecycle `EvidenceRequest`, expected identities, mapping plan, clock
and authenticator. Every issued request must exactly equal that bound request;
the caller and callback cannot choose or redefine its spec, UID/GID, resource
limits, cgroup, session or revision. A new approved revision requires a new
exchange. Do not expose these construction paths to workers. An injected Python
authenticator or clock is part of a test/TCB seam, not a cryptographic trust
bootstrap. Same-process compromise or Python reflection is not contained by
dataclass immutability.

## Evidence body

The response requires exactly one fresh observation per cumulative requirement
for `WORKER_CONFINEMENT_VERIFIED`, reusing the lifecycle's requirement enum:

| Evidence | Required independent origin |
| --- | --- |
| Authorized attempt | Supervisor authorization for the exact fixed spec, session and revision |
| Launcher | Pinned executable, ownership, invocation and authenticated artifact provenance |
| Namespaces | Actual user/PID/mount/network/UTS/IPC namespace handles; PID namespace must match the process-lifetime identity |
| UID/GID maps | Both initial and final stages; verified connected current-namespace procfs and setgroups sequence; actual maps must match supervisor-selected intent |
| AppArmor | Exact enforcing proposed stacked label before any untrusted code; configured names and worker self-reports are insufficient |
| Seccomp | `gvai-worker-no-spawn-no-sockets-v1`, approved filter bytes/ABI coverage, trusted descriptor provenance and actual installation |
| Privilege | Actual `NoNewPrivs` and all five capability sets empty |
| Input | Race-resistant resolution beneath the fixed input root and independently pinned descriptor identity |
| Scratch/mounts | Exact bounded private tmpfs at `/scratch`, required mode, read-only runtime/input/root, no writable host-backed mount |
| Descriptors | Complete inherited FD inventory, including stdio; no manager/STOP/publication/setup/unauthorized socket descriptors |
| Reaper | Trusted namespace init lifetime, liveness, namespace and descendant accounting |
| External STOP | Independently owned manager outside containment with working termination and loss-cleanup authority |
| Transition | Independently reviewed and accepted target-kernel transition, with no effective setup authority |

Each observation includes its process-lifetime binding, time, explicit
observed/unverified/failed disposition and provenance digest. The digest refers
to a future authenticated evidence artifact; it is not an implementation of the
underlying measurement. Wrong or missing dispositions/provenance fail structural
validation. Namespace and both mapping-stage details are additionally modeled
explicitly. Expected mappings originate in supervisor configuration, not in
fields supplied by the responding worker.

The model cannot inspect actual FDs, scratch, capabilities, installed BPF or
reaper liveness. An authenticator must authenticate the full body, and a future
independent runtime verifier must validate the underlying claims and artifacts,
not just trust check names or digests. Fixture consistency is never kernel truth.

## Challenges, replay and freshness

1. The supervisor requests worker-entry evidence only for
   `INPUT_AND_SECCOMP_VERIFIED -> WORKER_CONFINEMENT_VERIFIED`.
2. The exchange generates a fresh 256-bit random nonce and incrementing epoch.
   A new challenge invalidates the previous outstanding challenge.
   Configured lifetimes must be positive integers no greater than
   `MAX_CHALLENGE_LIFETIME_NS` (5 seconds); booleans and larger values are
   rejected.
3. The request, expected identities, mapping intent, issue time and exclusive
   expiry are bound into the challenge. Session/spec changes, revision rollback
   and issue-clock reversal are rejected. Retries may use the same lifecycle
   revision but must use a newly issued one-use challenge.
4. Assessment consumes the challenge **before** calling any authenticator,
   including on malformed replies, failed authentication and exceptions.
   Replays and concurrent duplicate consumption fail closed.
5. Observations must be no earlier than challenge issuance and no later than
   the response observation time; the response cannot be in the future.
   The supervisor monotonic clock is checked before and after authentication.
   Reversed time or reaching expiry rejects the response.
6. Response identity, full request, nonce, verifier and epoch must correlate.
   Correct fields alone do not authenticate it. No authenticator exists by
   default; the exchange fails closed without one.

A future transport needs canonical bounded encoding, domain separation,
authenticated peer identity, full-message integrity, challenge binding, replay
protection across reconnects/restarts and protected trust-root provisioning.
This module defines no wire codec, signature scheme, socket or network service.
No filename, socket path or claimed UUID is accepted as an authentication method.
The 5-second ceiling bounds the validity window, not the number of issue
attempts over the life of the exchange; state remains bounded to one pending
challenge and a monotonic integer epoch.

The exchange is process-local. Create a fresh exchange on restart, boot,
process lifetime, launcher, mapping-plan or cgroup change; do not reuse old
observations. A report is an inert snapshot, not a lasting capability.
Previously returned reports cannot change when STOP later arrives; therefore
they must never be cached or used as runtime acceptance. Runtime consumers would
need fresh independent checks and lifecycle revision revalidation.

## STOP and non-authorization

`request_stop()` only invalidates evidence and latches the exchange. It does not
replace, signal, journal or alter supervisor STOP authority. New challenges
are forbidden after STOP; outstanding and in-flight results become unusable.
The external supervisor must notify both the lifecycle and this exchange.
Either notification can happen first: the unchanged lifecycle's epoch checks
and unconditional worker-entry gate still deny entry.

## Linux collector foundation

`KernelEvidenceCollector` accepts a `ProcessHandleContext` containing the
parent-provided pidfd, process-directory FD, cgroup-directory FD, fixed request,
expected namespace/map identities and exact FD inventory. The Linux reader
duplicates these FDs, marks its copies non-inheritable, validates procfs and
cgroup-v2 filesystem identities, and closes its retained duplicates explicitly.
The reader chooses only enum-backed files (`stat`, `status`, maps, `setgroups`,
`cgroup`, and `attr/current`), uses descriptor-relative, component-at-a-time
`O_NOFOLLOW` traversal for ordinary files, follows only fixed proc namespace
magic links, and limits content, FD count and target size. Namespace descriptors
must be nsfs; cgroup descriptors must be cgroup v2. PID/start time are checked
against pidfd information and process liveness is polled without waiting before
and after collection. Changed/malformed FD inventories fail closed.

It parses credentials, all five capability sets, NNP, seccomp mode, enforcing
AppArmor label, current UID/GID maps, cgroup identity/membership, namespace
identities and descriptors. The report remains `UNVERIFIED` even when facts
match: supplied FDs are not themselves proof of independent provenance, and
the collector does not authenticate the handle owner or policy bytes. Injected
readers are marked `INJECTED_TEST_READER` and can never produce verified
evidence. Fixed pseudo-file reads have byte caps and no observer wait loop;
an injected synchronous test reader is trusted test code and is not forcibly
cancelled if it blocks.

The current-process interfaces do not prove the historical initial and final
UID-map setup stages, setup-FD closure before worker entry, installed seccomp
program bytes, or that no untrusted instruction ran before observation. Those
require an independently trusted, bounded evidence collector/launcher protocol
and authenticated source records. This foundation does not inspect the actual
host in tests and is not a host-acceptance tool.

No authenticator, clock callback or response interpretation runs under the
exchange mutex. STOP does not wait for collection/authentication completion.
Late replies cannot reverse STOP or a newer challenge. Authentication can call
STOP reentrantly. A callback may block its own synchronous caller; Python cannot
forcibly cancel it here. No threads, watchdogs, signals or termination mechanism
are created by the module. External termination must not depend on callback
completion or on this Python process surviving.

`EntryReport.consistent` means only that structural checks and the injected
authenticator seam passed in this model. Every report is false in boolean
context and **always** reports `authenticated=False`, `runtime_verified=False`,
`execution_authorized=False`, and `output_publication_authorized=False`.
No adapter converts reports into lifecycle acceptance. Tests even supply a
fixture report to a fixture lifecycle verifier: worker entry still fails closed.

## Tests and remaining acceptance gates

Offline tests cover lifetime reuse, cgroup/attempt/launcher mismatches, verifier
forgery, authentication failure, replay, expiration during authentication,
missing observations, incomplete/disconnected mapping evidence, wrong maps and
labels, stale provenance, namespace mismatch, missing seccomp/control-FD/reaper
checks, exceptions, STOP during collection/authentication, and late replies.
Blocking fixtures have explicit releases and bounded joins; no worker runs.

Neither these tests nor model authentication establish:

* AppArmor stacking/exec semantics on the exact Ubuntu kernel under NNP.
* Any loaded/enforcing profiles, namespace setup or actual process pin.
* Resolution of the historical disconnected-procfs UID-map failure.
* Correct actual UID/GID maps or cleanup of setup FDs at both stages.
* Installed seccomp, external termination/reaping or publication isolation.

The historical policy/export and prior compiler/lifecycle are preserved.
No policies, existing branches or draft PRs are modified.

**Next integration step:** review a concrete independent collector/authenticated
observer ABI, including retained process-lifetime handles, canonical signed
evidence contents and supervisor-owned trust provisioning. Keep it disconnected
from execution until kernel acceptance and separate authorization exist.
