# Disposable Bubblewrap / AppArmor reproduction design

## Disposition and scope

Prepared on 2026-10-19 from `87a47d68c34e2e1b0683cd8d63e2aebcbc4f486d`,
on `investigate/disposable-apparmor-repro`. This is a **design and local
regression preparation**, not a built/accepted VM or launcher fix. Nothing
here authorizes execution on DigitalOcean, changes to either existing draft,
AppArmor weakening, external model API calls, merge, or deployment. Findings
were reported before committing. The operator subsequently authorized
publishing only this plan, its runbook link and focused tests as a new draft
against `investigate/bwrap-disconnected-procfs`, following draft #17.

Use the [candidate runbook](ubuntu_bwrap_apparmor.md) for the supplied October
19 evidence: both profiles enforced, baseline restored and verified by the
operator, first loopback failure followed by a disconnected UID-map open
with the launcher-only Unix-datagram candidate, and **no host acceptance**.
The full preserved server log was not inspected. Do not collect it from the
server during this task; accept an independently authorized export instead.

## Technical review of the drafts

| Review item | Finding |
| --- | --- |
| [Draft #16](https://github.com/willshacklett/gvai-safety-systems/pull/16), head `cf3c771` | Proposes enforcing launcher/worker policy and fail-closed production handling; broad launcher setup/mount grants remain a documented residual surface. It is not an accepted sandbox. Its PR-body test counts describe an earlier revision, not the latest acceptance state. |
| [Draft #17](https://github.com/willshacklett/gvai-safety-systems/pull/17), head `87a47d6` | Correctly limits its diff to docs/tests and keeps the no-safe-correction stop. Upstream source supports a foreign procfs mount reference before pivots; no exact Ubuntu-kernel reproduction establishes that FD on the reported host. |
| Claims requiring qualification | `O_RDWR` explains `wr`, not a successful write. An outer PID in a procfs name does not prove PID-isolation failure. Both mapping passes print the same error. A mount ID absent from current mountinfo supports foreign/detached provenance but alone does not distinguish foreign namespace, detachment, races, or a mismatched procfs view. |
| Missing regression/evidence | Mocked stderr cases are failure handling, not tests of both mapping stages. Namespace identities at worker entry do not verify intermediate maps. Neither embedded syntax compilation nor a local unrestricted-kernel run proves AppArmor enforcement. No existing assertion proves setup-FD/mount cleanup after a redesigned launcher. |
| Diagnostic feasibility | Policy allows trusted-host `readby`, not unrestricted `tracedby`; the worker explicitly denies the latter. Do not treat `strace -f`/debugger attachment as read-only observation permitted by this policy. |
| Prerequisite gap | The fixture previously accepted any positive namespace limit and did not require the stacking feature. This branch pins 3692 and `domain/stack=yes`; kernel, package revision, OS, ownership and loaded-policy provenance still require the administrator checklist below. |

No high-confidence contradiction was found in #17's central mechanism.
Avoid turning its source-supported hypothesis into a claim of a verified
Ubuntu defect, safe patch, or successful namespace initialization.

Source anchors:
[pre-clone proc FD](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L2816),
[mapping helper](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L950),
[first mapping](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L3067),
[second mapping](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L3244),
[open flags](https://github.com/containers/bubblewrap/blob/v0.9.0/utils.c#L447),
[mount copying](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L3760),
[AppArmor resolution](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/path.c),
[permission short-circuit](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/file.c#L249).
These are upstream references, not the target's distribution patch set.

## 1. Reproducible guest, not a shared-kernel container

Use a dedicated local x86-64 QEMU/KVM VM with its own Ubuntu 24.04 kernel.
Docker, a devcontainer, chroot, or an Ubuntu userspace on another kernel is not
an equivalent AppArmor test. Do not change this workspace host's LSM/sysctls.
No VM was provisioned or booted in preparing this design.

Before provisioning, create an administrator-reviewed, immutable artifact
manifest containing all of the following. **Missing pins block a claim of
reproducibility; do not guess versions or replace them with `latest`.**

* Ubuntu base image URL/release, SHA-256 verified against authenticated release
  checksums, image architecture, boot configuration, QEMU version/CPU model.
* Exact kernel package/build `6.8.0-147-generic`, package checksums and matching
  source/config/Ubuntu patches. Ubuntu 24.04.5 is the operator-supplied target,
  not a version verified from an image in this task.
* Bubblewrap full distribution package revision reporting 0.9.0, binary and
  source-package hashes, build flags, patches and linked libc/libselinux
  versions. AppArmor full package revision reporting parser 4.0.1, parser
  config, ABI 4.0 includes and kernel feature tree. Parser version is not the
  version of the kernel LSM implementation.
* Hashes of the reviewed repository revision, policy source, compiled policy,
  Python 3.12 and the complete resolved Python dependency wheel set. The
  repository's lower-bound requirements alone are not a dependency lock.
* Root-owned provisioning inputs, package closure from a signed Ubuntu archive
  snapshot, all commands/build logs, and an explicit no-secret input inventory.

If exact target artifacts cannot be obtained, label a different pinned Noble
kernel/package set as a **mechanism experiment**, not a host-matching
reproduction. Stop host-equivalence claims until the exact manifest is filled.
Do not resolve package conflicts by removing vendor confinement.

The guest has two identities: a trusted console administrator and `gvaitest`
UID/GID 1000 without sudo or privilege-bearing groups. Provision reviewed
source at root-owned `/opt/gvai-safety-systems` with a root-owned `.venv`;
all path components must be non-worker-writable. Keep signing keys,
credentials, production data and control-plane storage out of the image.

Create a disposable copy-on-write overlay from an immutable base. Supply
reviewed packages/source on a read-only input ISO. Example hypervisor commands
for an administrator, **not executed here**, after creating that manifest:

```bash
qemu-img create -f qcow2 -F qcow2 \
  -b /srv/gvai-lab/base.qcow2 /srv/gvai-lab/run.qcow2
qemu-system-x86_64 -enable-kvm -cpu qemu64 -m 4096 -smp 2 \
  -nic none -display none -serial stdio -monitor none \
  -drive file=/srv/gvai-lab/run.qcow2,format=qcow2,if=virtio \
  -drive file=/srv/gvai-lab/inputs.iso,format=raw,media=cdrom,readonly=on
```

The base must already support serial-console administration; do not add an
unauthenticated console or hard-code a password. No port forwarding,
host-directory sharing, agent socket, SSH keys, clipboard, guest device
passthrough or cloud credentials. The disconnected VM NIC is defense in
depth, **not** a substitute for Bubblewrap `--unshare-net` or worker socket
denial assertions. Export reviewed evidence through an administrator-owned
artifact disk or console after stopping the run. Preserve hashes before
destroying only the named guest overlay; never unload policy under workers.

Inside the new guest only, provision restrictions at the required values:
AppArmor enabled/enforcing, `apparmor_restrict_unprivileged_userns=1`,
`unprivileged_userns_clone=1`, `max_user_namespaces=3692`.
Use the runbook's **fresh-install**, compile-first, human-approved procedure
for the unchanged two-profile candidate. Abort on an existing attachment
conflict rather than replacing it. Record the full loaded profile list before
and after; neither profile is allowed in complain/unconfined mode.

Use separate clean overlays for the restored-baseline policy (without the
historical datagram rule) and the UID-map candidate (unchanged current
policy). Record an explicit one-rule launcher-only diff and identical worker
hashes. The candidate is a separately authorized lab experiment, not a
recommendation to reinstall it on the restored server.

## 2. Minimal run and read-only diagnostic protocol

The minimal supported-command reproduction is the existing single
`test_supported_host_namespaces_and_enforcing_stack` case, not a new wrapper
which changes mapping flags or mounts. It retains the fixed proc/dev setup,
all five explicit unshare flags plus Bubblewrap's mount namespace, cap drop,
seccomp, and mandatory worker stack. A historical-baseline run may stop at
loopback; only the candidate run can test whether execution reaches UID-map
open. Neither expected failure counts as acceptance.

Separate **the experiment** (Bubblewrap necessarily creates namespaces and
writes its own maps) from **the collector** (no target writes, injection,
profile changes, target FD replacement, namespace joining, or forced pauses).
"Read-only diagnostic plan" does not mean Bubblewrap performs no writes.

1. Start with the unmodified, untraced binary. Record boot ID, UTC/monotonic
   time bounds, policy/package hashes, argv, test identity, stdout/stderr and
   exit code. Save complete kernel audit records by serial, not grep-only
   snippets. Include audit loss/rate-limit counters; missing events make
   attribution inconclusive, not a pass.
2. As guest administrator, read existing permitted process metadata when
   available: PID plus start time (avoid PID reuse), label, namespace links,
   root link, mountinfo, FD symlink targets and fdinfo mount IDs. For the
   inherited `/proc` FD and its `self` dirfd, compare IDs against **that same
   process's current mount namespace**. A reused FD number or metadata read
   after process exit is not valid correlation. If `fdinfo` access is denied
   or races the short-lived failure, record unavailable; do not add a rule.
3. If passive metadata cannot capture the stage, separately review a
   guest-administrator observational kernel collector (tracepoints/fentry or
   probes appropriate to the pinned kernel). Its bounded scope is the
   launcher process tree, and it may emit events only: clone flags/results;
   mount/user namespace transitions; successful/failed openat dirfds,
   flags and returned FDs; map-write bytes/counts/results; pivot/unmount
   events; exec/exit; kernel mount/namespace identity at relevant opens.
   Record collector source/hash, filtering, event loss and overhead. No
   register/return-value override, signal injection, target memory writes,
   BPF enforcement program or new worker privilege. Kernel lockdown,
   unavailable hooks, or existing denial is a stop for that collector,
   not permission to disable protections. Do not run an unreviewed generic
   privileged tracing script or assume ordinary syscall logs expose mounts.
4. First compare traced and untraced stock failures. If the collector changes
   the outcome, preserve both and stop causal/acceptance claims. If no
   permitted collector can identify the call, report mapping stage unknown.
   An observation-only instrumented source build is a possible separately
   scoped follow-up, not a stock-binary reproduction and not implemented here.
5. Never use `strace`, debugger attach, or `nsenter` as a silent fallback.
   Reading `readby`-authorized metadata does not authorize ptrace attachment.
   Keep all diagnostic authority in the trusted guest administrator, not the
   worker or a mapping service.

Classification requires correlated evidence, not errno alone:

| Observation | Interpretation |
| --- | --- |
| Mapping open audit has `Failed name lookup - disconnected path`, correct launcher label and serial/time correlation | AppArmor name resolution failed before ordinary pathname matching; map write was not reached for that open |
| The actual dirfd's mount belongs to the parent, not current child mount namespace, before first pivot | Supports inherited foreign-mount explanation for stage 1 |
| Disconnected mount only after a pivot/detach | Requires stage-specific attribution; cannot assume the first mapping failed |
| Connected absolute mapping path denied without name-lookup error | Investigate ordinary rule matching, loaded-policy provenance and DAC independently; no automatic allow |
| Open succeeds but write fails | Investigate map contents/order, credentials, setgroups and kernel mapping authorization; not the reported disconnected-open failure |
| Same filesystem/inode/path spelling, but mount identity unknown | Insufficient to establish connectivity |

Do not add a permissive "control" profile. A connected-path comparison must
use existing permissions and verified object provenance; if unavailable in
the stock run, leave it unknown. Do not write a map twice as a control:
mapping files are one-shot interfaces and later errors are not comparable.

## 3. Possible initialization change: design review only

The narrow candidate remains an independently scoped, short-lived,
connected mapping FD at each `pid=-1` mapping invocation. No implementation
or safe-fix claim is made. Before considering it, review these obligations:

* Stage 1 occurs after `CLONE_NEWNS` but before pivots. Re-resolving current
  `/proc` may select the copied connected mount; prove procfs type, mount
  membership, PID interpretation and self identity without symlink races.
* Stage 2 follows both pivots and nested userns creation. A newly mounted
  worker procfs may have different PID and userns provenance; a fresh path
  alone is not proof it can authorize the intended self-map writes.
* Leave the global proc FD's other users (bind-mount helpers, fdwalk, PID
  lookups, cleanup) unchanged until individually reviewed. A mapping-only
  correction may expose another fatal disconnected operation.
* Fail closed on verification failure; no inherited-FD fallback. Preserve
  map contents/order, deny-setgroups inheritance, device setup, capability
  bounding-set re-drop after nested userns, NNP, seccomp/exec order and stack.
* Prove all setup FDs and host/setup mount references are gone before Python
  worker entry. Apart from stdin/stdout/stderr, only the parent's approved
  seccomp FD may enter Bubblewrap; this parent FD allowlist does not itself
  prove Bubblewrap cleanup.

No new executable/profile path, host-capable mapping helper, worker authority,
global-FD replacement, disabled namespace, or permanent UID 0 is approved.
The immediate next engineering action is to freeze the guest manifest and
reproduce the **stock** candidate with loss-accounted passive evidence.
Only then separately scope an upstream/distribution launcher design review.

## 4. Stage and namespace pass/fail matrix

All maps below are interpreted relative to their immediate parent user
namespace. A guest observer in a different userns may see translated values;
record the viewing namespace rather than treating translated output as the
map-write bytes.

| Gate | Required evidence | Fail / blocked |
| --- | --- | --- |
| First clone | New user/PID/mount/network/UTS/IPC namespaces; intended clone flags and no external namespace FD override | Shared required namespace, missing flag or unknown provenance |
| Stage 1 | UID map write `0 1000 1\n`, then `setgroups` write `deny\n`, then GID map `0 1000 1\n`; each open/write succeeds, full write length and resulting maps agree | Any failed/short write, unexpected map/order or skipped setgroups; errno alone is insufficient |
| Root construction | Intended proc/dev setup, both pivots and old-root detach complete; old root absent from final mount tree, final FD cleanup checked at worker entry | Changed mounts to bypass mapping, unresolved setup denial or old root retained in final mount tree |
| Stage 2 | Nested userns distinct from stage 1; bounding-set cleanup; UID then GID writes `1000 0 1\n`, full lengths; no second setgroups write, effective restriction stays deny | Only stage 1 observed, reused userns, wrong map, setgroups re-enabled or unknown cleanup |
| Worker identity | UID/GID 1000, expected inner PID 1/2, maps `1000 0 1` from worker view | Root identity, missing map or isolation |
| All six namespaces | User/PID/mnt/net/UTS/IPC differ from trusted parent; userns stage 2 also differs from stage 1 | Any shared required namespace |
| Worker authority | Exact enforcing two-profile stack before/after attacks; five capability sets zero; NNP=1; seccomp=2 | Missing stack, recovered capability or successful profile escape |
| Negative/fixed-worker tests | All socket families denied at creation; file/map writes, spawn, userns/mount/re-exec blocked; safe output exact, attack output never promoted | Egress-only failure substituted for socket denial, boundary failure, unauthorized output or skipped test |

Reproduction success means repeated stock failures match the documented
stage/denial under the frozen baseline. It is **not** acceptance success.
A stock failure in stage 1 makes stage 2 **unreached**, not passed or an
invitation to bypass stage 1. Establishing both stages requires a separately
reviewed future implementation and fresh untraced acceptance.

## 5. Exact guest acceptance checklist

These steps apply only to the approved disposable guest. All unchecked items
block acceptance; the stock reproduction is expected to stop at setup.

- [ ] Manifest complete; guest boot/kernel/package/binary/source/policy/dependency
  hashes match; immutable-base and run overlay IDs recorded.
- [ ] Kernel `6.8.0-147-generic`, AppArmor enabled, parser 4.0.1/ABI 4.0,
  stack feature yes, all three sysctls exact; record complete feature tree.
- [ ] `gvaitest` UID/GID 1000, no privileged groups/sudo; root-owned non-setuid,
  no-capabilities `/usr/bin/bwrap` reports 0.9.0; interpreter resolves to
  `/usr/bin/python3.12`; trusted path ownership checked with `namei -l`.
- [ ] Runbook compile-only command passes warnings-as-errors; exact reviewed
  policy loaded into this guest only; both GVAI names enforce; no conflicting
  attachment or changes to unrelated policies. Save loaded-policy provenance.
- [ ] Guest NIC disconnected; no host secrets/shares/sockets; no surviving
  workers from prior run. Audit collector ready with no unexplained loss.
- [ ] As administrator in the guest, record start/end times and retain full
  exit status/stdout/stderr for each command below. Run tests as `gvaitest`,
  never root. Do not pipe through a command which hides pytest failure.

```bash
cd /opt/gvai-safety-systems
sudo -u gvaitest env -i PATH=/usr/bin:/bin HOME=/home/gvaitest \
  PYTHONDONTWRITEBYTECODE=1 GVAI_APPARMOR_ACCEPTANCE=1 \
  /opt/gvai-safety-systems/.venv/bin/python -m pytest \
  -q -rs -x -p no:cacheprovider tests/test_apparmor_sandbox.py \
  -k test_supported_host_namespaces_and_enforcing_stack
```

For reproduction, retain this expected failure and correlate the complete
audit event; repeat from **three fresh overlays**, keeping per-run IDs.
Uncorrelated or nondeterministic failures are inconclusive. Do not repeatedly
retry setup with altered flags. For a separately reviewed future launcher,
only after the diagnostic case succeeds, run without early stopping:

```bash
sudo -u gvaitest env -i PATH=/usr/bin:/bin HOME=/home/gvaitest \
  PYTHONDONTWRITEBYTECODE=1 GVAI_APPARMOR_ACCEPTANCE=1 \
  /opt/gvai-safety-systems/.venv/bin/python -m pytest \
  -q -rs -p no:cacheprovider tests/test_apparmor_sandbox.py
sudo -u gvaitest env -i PATH=/usr/bin:/bin HOME=/home/gvaitest \
  PYTHONDONTWRITEBYTECODE=1 \
  /opt/gvai-safety-systems/.venv/bin/python -m pytest \
  -q -rs -p no:cacheprovider tests/test_os_sandbox.py \
  tests/test_external_commands.py tests/test_external_control.py \
  tests/test_identity.py tests/test_runtime_policy.py
```

- [ ] Eight mandatory host cases executed, zero skips/failures/errors; OS and
  control regressions zero skips/failures/errors. Reject nonzero pytest exit
  status or empty collection. Synthetic unit cases are not host cases.
- [ ] Both map-stage records satisfy the matrix; fresh untraced runs verify
  final maps, all six namespace identities, labels, privilege state and
  negative cases without outcome changes from diagnostic runs.
- [ ] Independently review FD/mount cleanup evidence; current tests alone do
  not prove absence of every host/setup reference. Any unknown blocks a
  redesigned launcher's acceptance.
- [ ] Capture complete audit interval, loss counters, final enforcing profile
  list/sysctls and attributable intentional worker denials; unexplained
  fatal launcher/disconnected denials block acceptance.
- [ ] Supervisor process cancellation/startup-promotion-race acceptance remains
  a separate integration gate. No supervisor implementation exists on this
  branch; do not claim workload/deployment readiness without it.
- [ ] Stop and reap guest test processes, export/hash evidence, power down and
  discard the named overlay. No profile unload under live workers, no server
  changes, no merge/deployment.

## 6. Explicit stop conditions and remaining unknowns

Stop on any need for `attach_disconnected` (including prefixed variants),
complain/unconfined target execution, broad procfs permissions, new worker
capabilities, network-isolation removal, setuid/helper authority, conflicting
vendor policy replacement, or any production/test-server action.

Also stop causal or acceptance claims on artifact mismatch, absent enforcement,
unavailable tracing under existing restrictions, audit loss, PID/FD/mount
correlation races, observer-induced behavior change, unexplained denial,
stage 2 unreached, partial writes, extra inherited FDs, surviving setup mounts,
missing namespace isolation, or skipped security tests. Keep evidence; do not
turn these conditions into success-shaped fallbacks.

Unknowns remain the exact installed distribution patches and loaded policy,
which mapping call produced the supplied host audit event, later fatal
operations, a safe connected-FD verification algorithm, complete setup-FD
cleanup and the behavior of a future launcher under restricted enforcement.
No safe initialization change has yet been established.

Local tests on this branch cover baseline preflight rejection and seccomp-FD
cleanup/no retry after mapping failures. They do not exercise guest provisioning,
the observational collector, the two mapping stages or an implementation fix.

## Local validation record

The editor test tool reported no discovered tests, so validation used the
existing pytest runner in the previously restored session-only Python 3.14.2
virtualenv. No dependencies were installed during this task.

| Check | Result |
| --- | --- |
| Focused AppArmor and OS sandbox pytest files | **57 passed, 8 skipped**, no failures/errors |
| Newly added preflight cases | Six passed: matching synthetic baseline and rejection of each of five mismatched enforcement/namespace prerequisites |
| Mapping-failure cases | Existing five execution-failure cases additionally assert exactly one launch, sole seccomp FD, FD cleanup and preserved namespace flags |
| Policy and production code versus `87a47d6` | Identical |
| `git diff --check` | Passed |
| Disposable guest boot, collector, exact restricted/enforcing reproduction | **Not performed** |

All eight skips are explicit opt-in host acceptance cases. All 16 existing
OS sandbox regressions ran, but this workspace's restriction sysctl is 0;
neither those tests nor mocked preflight cases establish the required guest
state. No new parser compile or full-suite run is claimed. Publication of the
separate investigation branch is not authorization to build or boot the guest,
run a collector, modify the server, or claim host acceptance.
