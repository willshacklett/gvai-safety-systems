# Ubuntu 24.04 Bubblewrap / AppArmor candidate

## Status: human review and host acceptance required

This is a **configuration proposal, not an accepted or deployed sandbox**.
Nothing in this change loads policy, changes sysctls, installs a service, or
contacts the DigitalOcean server. Do not enable governed workloads until all
host acceptance and supervisor cancellation tests pass without security skips.

**Current disposition after the second live failure: STOP.** UID-map setup is
blocked by AppArmor disconnected-path resolution. No safe policy-only
correction has been established. The installation/revision commands below are
historical, human-gated procedures, not a recommendation to reload this
unchanged candidate or to activate workloads. See the second-failure diagnosis.

**2026-10-19 follow-up:** the operator confirms the enforcing baseline was
restored and verified. No successful host acceptance has occurred. A new
source review corroborates the inherited-procfs-FD mechanism but establishes
no safe correction; neither policy nor production launcher/worker code is
changed by this follow-up. See the dated investigation record below.

Target supplied by the operator:

| Component | Required baseline |
| --- | --- |
| OS / kernel | Ubuntu 24.04.5 LTS / 6.8.0-147-generic |
| Bubblewrap | 0.9.0, root-owned `/usr/bin/bwrap`, non-setuid, no file capabilities |
| AppArmor | enabled, parser 4.0.1, policy ABI 4.0, profile stacking supported |
| Account | `gvaitest`, UID/GID 1000, no sudo or privileged supplementary groups |
| Sysctls | `apparmor_restrict_unprivileged_userns=1`, `unprivileged_userns_clone=1`, `max_user_namespaces=3692` |
| Interpreter | `/usr/bin/python3` resolves to `/usr/bin/python3.12` |

### Repository baseline and draft supervisors

The branch starts at fetched `main`, commit
`14d60a234856fd2c7d097a42cfd38ed6369bf494`. The worktree was clean.
At inspection, [#14](https://github.com/willshacklett/gvai-safety-systems/pull/14)
and [#15](https://github.com/willshacklett/gvai-safety-systems/pull/15) were both
open, draft, and unmerged. Their sandbox and supervisor diffs were inspected.
Neither implementation has been copied, selected, or assumed present.

`main` contains identity/authorization and authenticated shutdown-command
contracts, but **no `gvai/supervisor.py` and no independently verified process
cancellation implementation**. Those contracts are not proof of termination.
This change preserves them and adds no worker access to their keys or APIs.
One reviewed supervisor implementation must be integrated separately before
claiming authorization-before-dispatch, latched shutdown, shutdown-safe output
promotion, or one-second cancellation acceptance.

Both drafts change the sandbox command/process-launch path. When integrating:

* Keep the absolute binary path, namespaces, `--cap-drop ALL`, sanitized
  environment, seccomp FD allowlist, and fail-closed result handling.
* Retain the mandatory stacked transition; never add an inherited/unconfined
  exec fallback to make startup pass.
* Keep the supervisor, keys, audit storage, and authoritative outputs outside
  the mount tree. Only the fixed worker script is mounted, not the checkout.
* Use the draft's parent-owned session/process-group lifecycle. Do not restore
  `--new-session` if that draft removes it to preserve group cancellation.
* Run its real shutdown and startup/promotion-race tests under this policy.
  Allowing receipt of supervisor signals is not evidence that cancellation
  actually works. A separately confined supervisor needs explicit, reviewed
  signal/readby peer rules; do not substitute a wildcard peer.

## Diagnosis and policy design

### First live failure and historical socket experiment

The operator reports **19 passed, 1 setup error**, stopped at the first error,
on the target baseline above, as unprivileged `gvaitest` (UID/GID 1000).
Both `gvai-bwrap` and `gvai-worker` were loaded in enforce mode; stacking was
supported and `kernel.apparmor_restrict_unprivileged_userns=1`.
Bubblewrap stderr was exactly:

```text
bwrap: loopback: Failed to look up lo: No such file or directory
```

Observed AppArmor denials were launcher reads of `/proc/filesystems` and
`/proc/<pid>/mounts`, several disconnected-path `getattr` operations, and Unix
datagram socket creation. Complete audit records and syscall traces were not
supplied. None of these observations alone proves causation.

The source-supported leading hypothesis is the **socket creation denial**:
Bubblewrap 0.9.0 calls `if_nametoindex("lo")` before opening its raw routing
netlink socket. In glibc 2.39, `if_nametoindex` calls `__opensock`, which tries
`AF_UNIX`, `AF_INET`, then `AF_INET6` datagram sockets for `SIOCGIFINDEX`.
If all fail, glibc explicitly sets `errno=ENOENT`, hiding the original socket
errors. The existing launcher allows only raw netlink, so this mechanism
explains both the Unix denial and the misleading "No such file or directory".
It does **not** establish that `lo` is missing. Exact target libc behavior and
the causal link still require a controlled target-host rerun.

The only candidate permission added is **launcher-only**
`unix (create) type=dgram,`. This permits an unbound ioctl socket, not Unix
bind/connect/send/receive, Internet sockets, or broader capabilities. The
worker profile is unchanged and continues to `audit deny network`, including
Unix sockets, in the mandatory stack. A later ioctl or bootstrap step might
still fail; do not pre-authorize it.

The other denials remain unallowed:

* libselinux initialization probes `/proc/filesystems` and, if that fails,
  falls back to `/proc/mounts` (resolved through the caller's proc directory).
  Local Bubblewrap links libselinux; target linkage and audit correlation
  remain to be checked. These probes are a plausible explanation for the
  paired procfs denials, not the specific loopback lookup failure.
* Disconnected-path `getattr` needs the full operation/path/error/PID record
  and the setup stage. Do not infer a required path or allow
  `attach_disconnected`, recursive procfs reads, or broad file permissions.

For the first **separately approved human-run** experiment, the proposal was to stop dispatch and
reap governed processes, preserve the current policy and full audit evidence,
and apply only the one-rule launcher change using the existing-profile
revision procedure below. Keep worker policy, namespaces (especially
`--unshare-net`), capability dropping, seccomp, sysctls, and account unchanged.
First run the namespace/stack acceptance case with `-x`; then, if it succeeds,
run the entire acceptance suite without early stopping and the regressions.
Save stdout, stderr, exit status, and complete timestamp-correlated audit
records (profile, PID/comm, operation, name/info, requested/denied masks,
family/type/protocol and peer where present). If failure advances, that is
diagnostic progress, **not acceptance**. Review the next fatal operation
before any further policy change; do not permit every remaining log entry.

### Second live failure: UID-map open on a disconnected procfs mount

At commit `66b0d4e27716a7cff8d21f8c1561bbd834b43391`, the operator reports
**22 passed, 1 host setup error**, stopped at the first error. The target
baseline was unchanged: Ubuntu 24.04.5 / kernel 6.8.0-147-generic,
non-setuid Bubblewrap 0.9.0, AppArmor 4.0.1, restricted user namespaces enabled,
both GVAI profiles enforcing, and unprivileged UID/GID 1000. The revised
launcher Unix datagram creation rule was installed and loaded.

Bubblewrap stderr:

```text
bwrap: setting up uid map: Permission denied
```

Supplied critical audit event:

```text
apparmor="DENIED" operation="open" class="file" info="Failed name lookup - disconnected path" error=-13 profile="gvai-bwrap" name="proc/7029/uid_map" requested_mask="wr" denied_mask="wr"
```

Other observations were `/proc/filesystems`, `/proc/<pid>/mounts`, and
disconnected-path `getattr` denials. The operator preserved the full log at
`/root/gvai-apparmor-uid-map-failure.log` on DigitalOcean. That file was **not
accessed**, and no claim here depends on its unavailable contents.

**Established from the supplied evidence:** a launcher-labelled mapping-file
open failed AppArmor name resolution with `EACCES`. This is stronger evidence
than the earlier unattributed `getattr` messages. The candidate already has
`/proc/{self,[0-9]*}/{uid_map,gid_map,setgroups} rw,`; the missing leading `/`
in the audit name is not a request to add a relative-path rule. AppArmor can
return a partial name for auditing while refusing to use it for mediation.
Adding `/proc/** rw,`, an `owner` qualifier, another capability, or a rule
spelling out PID 7029 does not repair failed name resolution. The denial is
at **open**, before the mapping write's separate kernel authorization checks.

#### Upstream sequence and mount provenance

The following is verified against upstream Bubblewrap **v0.9.0**, not a trace
of the distribution-patched binary or target Ubuntu kernel:

1. `main()` opens `/proc` with `O_PATH` before `raw_clone()`.
   The clone always includes `CLONE_NEWNS`; the fixed executor also requests
   user, PID, network, UTS, and IPC namespaces. Open FDs retain their original
   mount references; cloning the mount tree does not retarget them.
2. For non-setuid execution, the child initializes loopback and then calls
   `write_uid_gid_map(..., pid=-1, deny_groups=TRUE, map_root=FALSE)`.
   With `--dev`, the initial maps are `0 1000 1` for UID and GID, with
   `setgroups=deny` between the two writes.
3. That helper opens `self` using `openat(proc_fd, ..., O_PATH)`, then
   `write_file_at()` opens `uid_map` with **`O_RDWR|O_CLOEXEC`**, explaining
   the audit's `wr` mask. It writes UID map, then (when requested) `setgroups`,
   then GID map. It does not re-open `/proc` in the child's mount namespace.
4. Only after that first mapping does setup make mounts slave, build the
   root tree, perform the first pivot, detach `oldroot`, perform the second
   pivot, and detach the temporary setup root.
5. Because `--dev` required namespace UID/GID 0 for devpts, another
   `unshare(CLONE_NEWUSER)` maps UID/GID back to 1000 via the **same original
   proc FD** (`1000 0 1`, `deny_groups=FALSE`). Thus fixing only the first
   mapping's FD provenance would not resolve the entire sequence.
6. Capabilities are dropped, setup's proc FD is closed on the exec path,
   seccomp is applied, and Python is executed through the mandatory worker
   stack. The UID-map error prevents reaching that transition.

In Linux v6.8, `copy_mnt_ns()` copies mount topology and retargets the task's
root/cwd, not open file descriptions. `our_mnt()` checks whether a mount belongs
to the current mount namespace. AppArmor's `d_namespace_path()` treats a
foreign-namespace mount as disconnected, even if a familiar `/proc` spelling
exists in both namespaces. Without attachment, `disconnect()` returns
`-EACCES` and strips a leading slash. `profile_path_perm()` returns that error
**before** the pathname permission matcher runs.

**Strong source-supported diagnosis:** the inherited procfs FD can already
be disconnected for the **first mapping immediately after `CLONE_NEWNS`**.
It is incorrect to infer that this denial must occur after `pivot_root` or
an unmount. A local, unconfined mount-identity experiment opened `/proc`,
passed its FD through `unshare --user --map-root-user --mount`, and compared it
with a fresh `/proc` FD: the old mount ID was absent from the child's mountinfo
while the fresh mount ID was present. No policy was loaded and no sysctl
changed. This corroborates FD/mount provenance, **not AppArmor acceptance**.

**Still unverified:** which mapping call failed on the host, the exact
distribution build and Ubuntu backport behavior, PID/stage correlation, and
subsequent DAC/user-namespace mapping checks. Both mapping calls use the same
stderr. The supplied record alone does not distinguish them. A PID from the
original procfs view also does not establish the process's inner PID.
The procfs read and `getattr` denials remain separately unattributed.

#### Options considered: no disconnected-path shortcut

| Approach | Assessment |
| --- | --- |
| More procfs path permissions | Does not fix resolution; increases exposure without addressing the fatal operation. Rejected. |
| `attach_disconnected` on the launcher | Changes naming for all its disconnected objects, not just mapping files. The Noble manual explicitly warns of aliasing and unauthorized access and calls it a debugging/development facility. Existing broad setup-path/mount grants make this particularly concerning. Not adopted. |
| `attach_disconnected.path` with a private prefix | Can separate synthetic names from ordinary root names, but remains profile-wide attachment. A prefix plus mapping globs does not prove procfs object identity, mount provenance, or that a PID is the intended child. Exact parser/kernel support and alias safety are unverified. Not adopted. |
| `mediate_deleted` or `chroot_relative` | Changes different path semantics; not a demonstrated repair for a foreign-mount FD. Not adopted. |
| Extra `--proc /proc` or a wrapper bind mount | The command already mounts a worker procfs. It does not retarget Bubblewrap's earlier retained FD. A bind creates another mount reference; reopening through the connected view is still required. Keeping host procfs visible to the worker is unacceptable. |
| Remove `--dev`, PID isolation, root pivots, or use namespace UID 0 permanently | Avoids or moves some setup steps but changes device/isolation/identity contracts, and does not repair the pre-clone FD. Not a drop-in correction. |
| Setuid launcher, host-capable mapping helpers, or unconfined mapping service | Enlarges host authority/TCB; no justification here. Not adopted. |
| Connected-procfs launcher implementation | Preferred research direction, but requires a separately reviewed Bubblewrap patch/redesign and kernel-backed tests. Not implemented or claimed safe here. |

A narrowly restricted profile **can authorize connected mapping paths** in
principle, but ordinary path rules cannot selectively turn a disconnected
object into a verified procfs mapping file. No safe policy-only change for
the stock launch sequence has been demonstrated. Stop rather than relaxing
this boundary.

For a future launcher patch, re-resolve mapping paths through a verified
procfs mount in the **current** mount namespace before the initial mapping;
after the root pivots, use a connected current-PID-namespace procfs view for
the second mapping. One bounded prototype to evaluate is a separate,
short-lived mapping-only proc FD for the `pid=-1` branch, opened afresh at each
mapping call; do not silently reuse the inherited FD if opening or verifying
the connected view fails. Mapping uses `self`, but numeric PIDs and other uses
of the global proc FD have different semantics: blindly replacing that global
FD could break mount helpers, PID lookups, or cleanup. Review every use instead.
Preserve both intended maps, deny-setgroups sequencing, mount isolation,
device behavior, capability bounding-set cleanup after nested userns,
`no_new_privs`, seccomp timing, and the mandatory stacked exec.
Verify mount identity and procfs type, close all setup FDs, and remove all
host/setup views before untrusted execution. No host UID-map service, alternate
binary path, new capabilities, or permissive policy is proposed in this PR.
Even a mapping-only prototype could leave other disconnected-FD operations
blocked. Those need separate attribution, not broader attachment or a claim
that this design resolves every bootstrap operation.

#### Next evidence collection and acceptance gate

No further live policy experiment is recommended with this unchanged
candidate. A human can separately authorize **read-only evidence collection**
from the preserved log: correlate complete audit event serials, PID/comm,
timestamps, namespace/mount identities, mapping pass, and process exit status.
Determine the exact installed Bubblewrap build/source. Any future tracing must
be explicitly authorized in a controlled test environment; ptrace can alter
behavior, so its result is not acceptance. Do not change enforcement just to
get a trace. This investigation did not access or modify DigitalOcean.

Before considering a redesigned launcher, reproduce both map passes in a
disposable restricted/enforcing Ubuntu environment. Require connected object
provenance, no surviving setup mount/FD, an exact enforcing two-profile label,
zero capabilities, `NoNewPrivs=1`, active seccomp, all namespace/identity
contracts, and all existing negative/fixed-worker cases with zero security
skips. Worker UID-map, GID-map and setgroups writes must remain blocked.
Neither the latest 22 passing tests nor disappearance of a single mapping
denial demonstrates that boundary. Supervisor cancellation remains a separate
acceptance blocker.

Ubuntu's user-namespace restriction is distinct from ordinary DAC and the
`unprivileged_userns_clone` sysctl. An unconfined application can enter the
restricted `unprivileged_userns` domain and then lose the capability and procfs
permissions needed for setup. Removing `--unshare-net` is not a fix: it removes
an isolation boundary and does not authorize UID/GID mapping.

The candidate is [usr.bin.bwrap.gvai](../security/apparmor/usr.bin.bwrap.gvai).
It declares two **enforcing, confined** profiles:

1. `gvai-bwrap` attaches only to `/usr/bin/bwrap`. Its finite capability list
   covers Bubblewrap's namespace-local setup: `sys_admin`, `sys_chroot`,
   `setuid`, `setgid`, `setpcap`, `net_admin`, and `sys_ptrace`. AppArmor
   permission is not a grant of a Linux capability: the non-setuid launcher
   starts without host capabilities. It obtains capabilities only inside its
   newly created user namespace. `setpcap` is needed when dropping capability
   bounding sets; `net_admin` and raw routing-netlink sockets initialize only
   the new network namespace's loopback.
2. Executing the resolved `/usr/bin/python3.12` **must stack** `gvai-worker`:
   `/usr/bin/python3.12 rPx -> &gvai-worker,`. There is no `ix`, `pix`, `pux`,
   `ux`, shell, arbitrary-interpreter, or missing-profile fallback.
   The worker's effective policy is the **intersection** of both profiles.
   It denies capabilities, user namespaces, networking, mounts, pivots, ptrace
   initiation, and writes to procfs/sysfs/safety state. It has no exec or
   profile-change permission. The retained launcher label does not preserve
   launcher authority through the worker profile's denials.

The transition matches the **resolved interpreter executable**, not its
arguments: both `python3 -I -c ...` in the diagnostic acceptance probe and
`python3 /runner.py --action ...` in the executor must take the same mandatory
stack. Thus `-c` is compatible, but its success alone does not validate the
fixed-worker mount or action path. AppArmor does not authenticate Python
source or arguments; the trusted executor fixes the sole worker bind mount
and command. The lightweight `bwrap_usable()` `python3 -c` check lacks the
worker script, seccomp installation, and label assertions, and is **only an
availability check**, never security acceptance. Mandatory host cases now
also run the real fixed-worker executor for safe work and file/network/spawn
attacks without mocks or setup skips.

### Why a plain `Px` / `Cx` replacement is not proposed

Bubblewrap 0.9.0 sets `PR_SET_NO_NEW_PRIVS` before namespace initialization.
AppArmor's kernel transition checks do not generally prove that a distinct
replacement profile is less permissive just because its text looks narrower.
A replacement transition can therefore fail with `no new privs`.
Stacking retains the old constraints and adds new ones, making a monotonic
restriction compatible with that check. **Parser acceptance alone does not
prove the Ubuntu kernel implements this transition as expected.** Require the
observed two-profile enforcing label and all negative tests on the target.
Do not clear `no_new_privs`, use an unconfined launcher, or drop the worker
profile to work around a denial.

Every member of the stack must permit an operation. In particular the worker
has no executable or `change_profile` grant: the launcher's Python exec rule
cannot by itself authorize a second exec from the worker or remove the worker
component. Negative syscall results alone cannot attribute enforcement to
AppArmor (seccomp, DAC, and read-only mounts can also deny them). Acceptance
must observe the exact enforcing stack before and after privilege-recovery
attempts, as well as the capability and syscall results.

### Namespace setup, mapping, and privilege removal

The existing executor explicitly unshares user, PID, network, UTS, and IPC
namespaces. Bubblewrap first initializes loopback, writes `uid_map`,
`setgroups=deny`, and `gid_map` through its retained procfs FD, then builds the
mount tree and performs two root pivots. With `--dev`, devpts setup can require
an initial namespace mapping the account to UID 0, followed by a second user
namespace mapping it back to UID 1000. A namespace UID 0 is not host root.
The candidate permits the three mapping files, not general procfs writes.
The final worker's mapping is checked against this 0.9.0 `--dev` sequence.

The launcher needs mount/remount/unmount/pivot permissions across its changing
root paths. These mount-class rules are deliberately broad **inside the
launcher**, not an audited per-mount allowlist. File access is path-scoped, but
temporary/setup paths necessarily overlap with the eventual namespace paths.
This is a residual launcher attack surface, not a claim of minimal mount
mediation. The mandatory worker stack denies these classes completely.
Do not add `attach_disconnected` to bypass path resolution failures.

Before executing Python, Bubblewrap drops capabilities with `--cap-drop ALL`
and installs the existing no-spawn seccomp filter. Acceptance requires all five
capability sets to be zero, `NoNewPrivs=1`, and `Seccomp=2`. It attempts to regain
capabilities, create another user namespace, remount, change profile, execute
Bubblewrap again, and spawn a child. No launcher privileges may be recoverable.
The worker cannot unload the policy or reach its host configuration.

The candidate permits signals **to** the worker from the unconfined trusted
host and permits read-only ptrace observation (`readby`) by that host. It does
not permit the worker to trace, signal, or change the supervisor. This assumes
the host account and its other processes are trusted; it is not hostile
same-UID tenant isolation.

### Paths and trust ownership

The launcher is locked to `/usr/bin/bwrap`, ignoring `PATH`, and rejects
symlinks, non-root-owned, setuid/setgid, group/other-writable binaries, and file
capabilities. Unexpected metadata/xattr errors propagate rather than silently
approving a launcher whose integrity could not be checked. The candidate expects a root-owned,
non-worker-writable checkout at `/opt/gvai-safety-systems`, the fixed worker
script beneath it, disposable `/tmp/gv-os-sandbox-*` trees, and optional inputs
at `/var/lib/gvai-sandbox/input`. The latter must be administrator-curated
non-secret input, not control-plane storage. Other checkout/input/interpreter
paths are unsupported and must fail, not trigger a broader glob.

The system runtime mounts expose `/usr` and library trees read-only, as before.
Do not put secrets there. Do not give the worker Docker sockets, host FDs,
credentials, the repository, audit roots, signing keys, authoritative output
roots, or `/sys`. The supervisor alone promotes staged `/work` output.
Profile files, executable paths, and the trusted launcher arguments are owned
by the external administrator. **The thing behind the switch does not own
the switch.**

AppArmor does not validate Bubblewrap arguments. A trusted host user invoking
Bubblewrap directly could choose different namespace flags or bind a host file
at an allowed sandbox path. This policy is therefore not a safe general-purpose
Bubblewrap service for hostile callers. Only the parent-owned fixed executor
command is supported; the worker cannot invoke Bubblewrap or change that command.

Missing/denied setup and missing/malformed/unsuccessful worker results now deny
authorization and commit, even with an otherwise permissive effect policy.
Network socket creation denials are recorded as blocked egress attempts,
including when AppArmor blocks `socket()` before `connect()`.

## Human-only host installation procedure

**These commands were not executed on the server.** They are a review and test
procedure, not permission to deploy. Use a maintenance window with governed
workloads stopped. Keep a separate administrator session. Do not run the
executor or acceptance suite as root.

Prerequisites: an administrator has provisioned the reviewed commit at the
root-owned `/opt/gvai-safety-systems` and a root-owned `.venv` there with the
project and existing requirements installed. No path component, source file,
test, or virtualenv may be writable by `gvaitest`. The administrator must
compare `git rev-parse HEAD` to the reviewed delivery SHA and review
`git status --short` before proceeding. Do not copy a worker-writable checkout
into this trust boundary. Do not blindly install/upgrade packages or overwrite
an existing profile on a shared host.

Run as the administrator, from a shell with `sudo`:

```bash
set -euo pipefail
cd /opt/gvai-safety-systems
git rev-parse HEAD
git status --short
uname -r
cat /etc/os-release
id gvaitest
namei -l /usr/bin/bwrap /usr/bin/python3 \
  /opt/gvai-safety-systems/gvai/os_sandbox_worker.py
stat -c '%U %G %a %n' /usr/bin/bwrap
getcap /usr/bin/bwrap                     # required: no output
/usr/bin/bwrap --version                  # required: bubblewrap 0.9.0
readlink -f /usr/bin/python3              # required: /usr/bin/python3.12
apparmor_parser --version                 # required: 4.0.1
sudo aa-status
test "$(cat /sys/module/apparmor/parameters/enabled)" = Y
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
test "$(sysctl -n kernel.unprivileged_userns_clone)" = 1
test "$(sysctl -n user.max_user_namespaces)" = 3692
test "$(cat /sys/kernel/security/apparmor/features/domain/stack)" = yes
sudo cat /sys/kernel/security/apparmor/profiles
```

For a fresh installation, stop if the baseline differs, either GVAI profile
name is already loaded, or another profile attaches to `/usr/bin/bwrap`.
The reported host already has both GVAI profiles: use the separately approved
revision procedure below, **not** the fresh-install commands. Never replace a
vendor or unrelated local policy. Save the above output and full profile list in
administrator-owned review evidence. Verify `gvaitest` cannot use sudo and has
no `docker`, `lxd`, or other privilege-bearing groups.

First compile only (no kernel load, no policy activation):

```bash
sudo apparmor_parser -Q -K --warn=all --Werror \
  security/apparmor/usr.bin.bwrap.gvai
```

Only **after explicit human approval to test the candidate**, install and load:

```bash
test ! -e /etc/apparmor.d/usr.bin.bwrap.gvai
sudo install -o root -g root -m 0644 \
  security/apparmor/usr.bin.bwrap.gvai \
  /etc/apparmor.d/usr.bin.bwrap.gvai
sudo apparmor_parser -a -K /etc/apparmor.d/usr.bin.bwrap.gvai
sudo aa-status
sudo grep -E '^gvai-(bwrap|worker) ' /sys/kernel/security/apparmor/profiles
# Required: exactly gvai-bwrap (enforce) and gvai-worker (enforce).
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
```

This file persists across AppArmor service reload/reboot. There are no changes
to the system-wide `unprivileged_userns` policy, sysctl configuration, or service
units. Verify only the two new enforcing profiles were added.

### Revising the already-loaded GVAI candidate (human only)

This procedure is for a **future explicitly approved diagnostic experiment**,
not an instruction to load this local proposal now. Keep governed workloads
stopped. Confirm both existing GVAI profiles are enforcing, the installed file
is the operator's known prior candidate, and no vendor/unrelated attachment
conflicts exist. Stop if the installed source cannot be tied to the loaded
baseline: a file backup alone does not establish what policy is in the kernel.
Review the installed-source/candidate diff; only the launcher Unix-datagram
creation rule and its comment may differ. The worker stanza must be identical.
Preserve the existing source and audit evidence in administrator-owned storage.

After all checks and explicit approval, as administrator:

```bash
set -euo pipefail
cd /opt/gvai-safety-systems
if sudo ps -e -o label= | grep -q 'gvai-bwrap\|gvai-worker'; then
  echo 'STOP: GVAI-labelled processes remain; cancel and reap them first.' >&2
  exit 1
fi
sudo test -f /etc/apparmor.d/usr.bin.bwrap.gvai
sudo test ! -e /root/gvai-apparmor-loopback-review
sudo install -d -o root -g root -m 0700 /root/gvai-apparmor-loopback-review
sudo cp -- /etc/apparmor.d/usr.bin.bwrap.gvai \
  /root/gvai-apparmor-loopback-review/before.policy
sudo chmod 0600 /root/gvai-apparmor-loopback-review/before.policy
sudo cat /sys/kernel/security/apparmor/profiles | \
  sudo tee /root/gvai-apparmor-loopback-review/profiles.before >/dev/null
sudo sha256sum /root/gvai-apparmor-loopback-review/before.policy \
  security/apparmor/usr.bin.bwrap.gvai
sudo apparmor_parser -Q -K --warn=all --Werror \
  security/apparmor/usr.bin.bwrap.gvai
sudo install -o root -g root -m 0644 \
  security/apparmor/usr.bin.bwrap.gvai /etc/apparmor.d/usr.bin.bwrap.gvai
sudo apparmor_parser -r -K /etc/apparmor.d/usr.bin.bwrap.gvai
sudo aa-status
sudo cat /sys/kernel/security/apparmor/profiles
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
```

Compare the full profile list to the saved list: names/enforce mode and all
unrelated profiles must be unchanged. Only `gvai-bwrap` gains a permission;
`gvai-worker` is reloaded identically. If replacement fails, keep dispatch stopped, inspect both
actual loaded names, and use the revision rollback below. Do not assume the
multi-profile replacement was atomic.

First diagnostic rerun (unprivileged, mandatory host prerequisites, no skips):

```bash
sudo -u gvaitest env -i PATH=/usr/bin:/bin HOME=/home/gvaitest \
  PYTHONDONTWRITEBYTECODE=1 GVAI_APPARMOR_ACCEPTANCE=1 \
  /opt/gvai-safety-systems/.venv/bin/python -m pytest \
  -q -rs -x -p no:cacheprovider tests/test_apparmor_sandbox.py \
  -k test_supported_host_namespaces_and_enforcing_stack
```

If this passes, run **all** commands below without `-x`. A passed diagnostic
case alone is not acceptance. Retain failed-run evidence even after rollback.

### Revised acceptance requirements

Run the mandatory acceptance suite, then existing OS and control regressions:

```bash
cd /opt/gvai-safety-systems
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
sudo journalctl -k --since '-15 minutes' --no-pager | grep -i apparmor
sudo aa-status
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
```

Expected: zero failures/errors and **zero skipped security cases** on the
supported host. The explicit suite has eight mandatory host cases: three
inline-probe checks, four real fixed-worker action cases, and one unapproved
executable check. Existing OS tests can skip on setup failure; any such skip
is an acceptance blocker, not a pass. Require:

* The inline probe executes under exactly `gvai-bwrap//&gvai-worker (enforce)`
  (profile order may differ), with isolated user/PID/mount/network/UTS/IPC
  namespaces.
* All capability sets are zero, `NoNewPrivs=1`, `Seccomp=2`; capset, namespace
  creation, mount/remount/unmount, profile change, launcher re-exec and child
  spawning remain denied, and no privilege recovery succeeds.
* Unix datagram/stream, Internet datagram (IPv4/IPv6), and raw netlink socket
  **creation** fail with `EACCES`/`EPERM` under the worker. A connection failure
  such as `ENETUNREACH` alone is insufficient to validate AppArmor networking.
* Safe work through the actual fixed `/runner.py` executor commits the exact
  expected output; file, network, and spawn attacks complete as blocked
  attempts without boundary failure, authorization, or output promotion.
* Unauthorized host reads, safety/policy writes, and profile changes remain
  blocked; setup fails closed and only the reviewed interpreter is executable.

Retain failures and complete audit records, correlated by PID/time with the
test and stderr. Denials from deliberate worker attacks are expected.
Remaining launcher denials must be explained and shown nonfatal, not silently
ignored or automatically allowed; disconnected-path denials remain blockers
until attributed. Absence of the enforcing stack is always a blocker.
Do not run an automatic profile generator to permit logged denials.
After selecting/integrating a supervisor draft, also
run its real `tests/test_supervisor.py` tests and acceptance cases on this host;
that file is intentionally absent on this branch.

## Rollback (human only)

Stop dispatch through the **trusted host control plane** and independently
terminate/reap all governed processes first. Do not unload policy from under
live workers: removing an enforcing profile can remove their confinement.
If startup failed partway through, inspect the actual loaded profiles before
rollback; do not assume a successful load or that the load was atomic.

**Revision rollback:** if the two profiles existed before the experiment,
restore the preserved enforcing baseline rather than removing it. After
stopping dispatch and independently verifying no GVAI-labelled processes
remain, run as administrator:

```bash
set -euo pipefail
if sudo ps -e -o label= | grep -q 'gvai-bwrap\|gvai-worker'; then
  echo 'STOP: GVAI-labelled processes remain; cancel and reap them first.' >&2
  exit 1
fi
sudo apparmor_parser -Q -K --warn=all --Werror \
  /root/gvai-apparmor-loopback-review/before.policy
sudo install -o root -g root -m 0644 \
  /root/gvai-apparmor-loopback-review/before.policy \
  /etc/apparmor.d/usr.bin.bwrap.gvai
sudo apparmor_parser -r -K /etc/apparmor.d/usr.bin.bwrap.gvai
sudo aa-status
sudo cat /sys/kernel/security/apparmor/profiles
test "$(cat /sys/module/apparmor/parameters/enabled)" = Y
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
```

Verify both GVAI names are enforcing and the full profile list matches
`profiles.before`. Keep the backup and failed-run evidence. Keep workloads
stopped: restoring the prior profile restores its known startup failure, not
an accepted sandbox. Stop and request administrator investigation if restoration
fails; never unload or switch to complain/unconfined mode to continue.

**Fresh-install rollback only:** for profiles newly added by the fresh-install
procedure, with no preexisting GVAI policy to restore:

```bash
set -euo pipefail
# Prevent new launches throughout this procedure.
if sudo ps -e -o label= | grep -q 'gvai-bwrap\|gvai-worker'; then
  echo 'STOP: GVAI-labelled processes remain; cancel and reap them first.' >&2
  exit 1
fi
sudo apparmor_parser -R /etc/apparmor.d/usr.bin.bwrap.gvai
sudo rm -- /etc/apparmor.d/usr.bin.bwrap.gvai
sudo aa-status
if sudo grep -qE '^gvai-(bwrap|worker) ' /sys/kernel/security/apparmor/profiles; then
  echo 'STOP: GVAI profiles remain loaded.' >&2
  exit 1
fi
test "$(cat /sys/module/apparmor/parameters/enabled)" = Y
test "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns)" = 1
```

If only one profile loaded, stop dispatch, verify no governed processes remain,
and use the parser to remove just that loaded name via an administrator-reviewed
single-profile file; do not unload unrelated policies. If no profile loaded,
remove only the newly installed GVAI file after inspection. No prior profile
is overwritten, so there is no preexisting profile to restore. Leave workloads
stopped: reverting the exception may make Bubblewrap unavailable, which must
continue to fail closed. Do not disable AppArmor or alter the restriction sysctl.

## Validation record and remaining blockers

### First-failure validation (historical, now in baseline)

Prepared on `feature/ubuntu-bwrap-apparmor` from
`668f30b8d561892f07431dea576fd40aed37235f`. The starting worktree was clean.
Only this runbook, the candidate policy, and `tests/test_apparmor_sandbox.py`
changed. The entire worker profile and production launcher/worker code are
unchanged. No commits, pushes, PR updates, SSH, server changes, kernel policy
loads, sysctl changes, or governed workload activation were performed. PRs #14/#15
were not modified.

Local validation uses Ubuntu 24.04.5 userspace and Bubblewrap 0.9.0, but kernel
`6.8.0-1064-azure`, glibc 2.39, an unconfined UID/GID 1000 caller, and
user-namespace restriction **0**. Local `/usr/bin/python3` is Python 3.12.3;
local pytest ran in a session-only Python 3.14.2 virtualenv, not the target
Python environment. No sysctl or live policy was changed. The previously
extracted, uninstalled AppArmor 4.0.1 parser from Ubuntu's
`apparmor_4.0.1really4.0.1-0ubuntu0.24.04.9_amd64.deb` was reused from session
storage, not installed or activated. Compilation used its bundled config
(`--config-file`) and ABI 4.0 (`-I`), plus `--warn=all --Werror -Q -K`,
with no kernel load or cache writes.

| Validation | Result |
| --- | --- |
| AppArmor 4.0.1 / ABI 4.0 compile, warnings as errors | Passed after supplying bundled config |
| Focused `test_apparmor_sandbox.py` + `test_os_sandbox.py` | **38 passed, 8 skipped**, no failures/errors |
| Full local `python -m pytest -q -rs -p no:cacheprovider` | **214 passed, 8 skipped**, no failures/errors |
| Explicit local `GVAI_APPARMOR_ACCEPTANCE=1` suite | **22 passed, 8 setup errors**, no skips; restriction sysctl is 0, not required 1 |
| `git diff --check` | Passed |
| Restricted target-host acceptance / enforcing kernel stack | **Not verified** |

All eight ordinary-run skips are the explicit opt-in target-host cases; the
existing OS regression tests executed. The eight explicit acceptance errors
occurred at prerequisites before host probes/worker execution. They confirm
fail-closed prerequisite handling, **not successful host acceptance**.

Validation setup limitations were resolved without system installation:
neither available Python initially had pytest; Python 3.12 venv creation
failed because ensurepip was absent. A session-only Python 3.14 venv restored
the existing requirements. The editor test tool reported no discovered tests,
so the existing pytest runner was used directly. The initial parser invocation
failed warnings-as-errors because `/etc/apparmor/parser.conf` was absent;
rerunning with the extracted package's config and ABI succeeded. No source
or policy failure was suppressed.

* Local focused tests cover mandatory policy structure, absolute executable
  selection, unsafe binary rejection, fail-closed bootstrap/results, and
  existing real Bubblewrap containment and authorization contracts.
  New local contracts constrain the launcher socket rule to creation only and
  preserve the sole stacked exec transition and fixed executor command.
  They are static/mocked regression evidence, not kernel enforcement evidence.
* Syntax compilation cannot verify mount path mediation, procfs remapping,
  ioctl/socket behavior, routing-netlink permission, kernel stacking, launcher
  capability removal, or supervisor shutdown. All remain target-host
  verification requirements. The supplied live result is a startup failure,
  not a partial security acceptance; complete audit records are still needed.
* The launcher has broad mount-class and temporary/setup-path permissions.
  A Bubblewrap/kernel vulnerability is outside this policy's guarantee.
  Stacking must be observed to remove those permissions from the worker.
* Exact interpreter paths and root-owned curated runtime/input trees are
  required. System Python/runtime upgrades require revalidation.
* `main` still lacks the draft supervisor's lifecycle guarantees. Do not
  interpret regression passes for command authentication as process-stop proof.
* No publication or draft PR is performed; the final task instruction forbids
  publishing. This is a local review artifact only.

### Second-failure investigation (local only)

Revalidated on `feature/ubuntu-bwrap-apparmor` at
`66b0d4e27716a7cff8d21f8c1561bbd834b43391`. This runbook and
`tests/test_apparmor_sandbox.py` already contained uncommitted second-failure
investigation edits at the start of this pass; those edits were preserved,
checked against public upstream sources, and extended. Only those two files
differ from HEAD. **Neither profile nor any production
launcher/worker code changed.** No commit, push, merge, deployment, PR update,
DigitalOcean access, policy activation, or sysctl change was performed.
PRs #14/#15 were not modified.

The local environment remains Ubuntu 24.04.5 userspace, Bubblewrap 0.9.0,
kernel `6.8.0-1064-azure`, unconfined UID/GID 1000, restriction sysctl **0**.
Tests used a newly restored session-only Python 3.14.2 virtualenv after the
default Python reported that pytest was missing; sandbox Python is 3.12.3.
The AppArmor parser was also absent. Ubuntu's
`apparmor_4.0.1really4.0.1-0ubuntu0.24.04.9_amd64.deb` was downloaded and
extracted into session storage, not installed. Compilation used that parser's
bundled config and ABI 4.0 with `--warn=all --Werror -Q -K`, without
installing/loading policy or writing its cache. A version-only invocation
warned that the system parser config was absent; the configured compile
produced no warnings.

New regression contracts reject disconnected/deleted-object relabelling and
procfs write expansion. Synthetic UID-map, setgroups, and GID-map errors test
both availability failure without fallback and execution failure after a
previous availability check, retaining stderr and refusing authorization/output
promotion even with success-shaped JSON. Only UID-map failure was reported
live; setgroups/GID-map failures are anticipatory test cases. The mandatory
host probe additionally attempts GID-map and setgroups writes under the worker.
It now attempts replacement with the launcher-only, worker-only, and unconfined
labels, and requires the observed label after all negative attempts to equal
the initial enforcing stack. The embedded probe's Python syntax was compiled
separately because ordinary pytest runs skip its execution.
These unit contracts are **not proof of kernel enforcement**.

The inline probe's interpreter-only mandatory `rPx -> &gvai-worker` transition
and the real fixed `/runner.py` executor cases remain unchanged. All worker
capability/network/mount/userns/process/file/policy restrictions remain in the
policy and acceptance requirements. The latest live failure occurs before
worker exec; loaded profiles alone cannot establish that the stack has been
entered or that launcher privileges are unrecoverable. Runtime verification
remains blocked, not waived.

| Second-investigation validation | Result |
| --- | --- |
| AppArmor 4.0.1 / ABI 4.0, `--warn=all --Werror -Q -K`, bundled config/includes | Passed; unchanged policy, no load/cache writes |
| Focused `test_apparmor_sandbox.py` + `test_os_sandbox.py` | **46 passed, 8 skipped**, no failures/errors |
| Full `python -m pytest -q -rs -p no:cacheprovider` | **222 passed, 8 skipped**, no failures/errors |
| Explicit `GVAI_APPARMOR_ACCEPTANCE=1` suite | **30 passed, 8 setup errors**, no skips |
| Local inherited/reopened procfs FD experiment | Old mount absent from current mountinfo, fresh mount present |
| Regression module and embedded acceptance probe Python syntax | Passed |
| `git diff --check` and policy/production-code comparison to HEAD | Passed; policy and production code identical |
| Restricted-kernel transition, mapping correction, target-host acceptance | **Not verified** |

Every ordinary-run skip is an explicit opt-in host case; existing OS
regressions ran. Every explicit acceptance setup error is the local restriction
sysctl mismatch (`0`, required `1`) before probe execution, not the target UID-map
failure. No restriction was changed to make a test pass. The editor test tool
found no tests, so validation used the existing pytest runner directly.
The parser succeeded on its first configured compile in this pass.
The default-Python missing-pytest failure, missing system parser, and editor
test discovery limitation were resolved using the isolated dependencies and
pytest runner described above. There were no regression assertion failures.
No test of the proposed launcher
redesign was run because no redesign was implemented.

**Review decision requested:** retain the current restrictions and stop
acceptance here; separately scope a connected-procfs launcher patch and its
restricted/enforcing-kernel verification before any further policy revision.

### Follow-up source investigation (2026-10-19)

This follow-up starts from clean commit
`cf3c7713475d4a9db1647845027615311ae85b7d`, on the new branch
`investigate/bwrap-disconnected-procfs`. Earlier validation/publication records
above describe earlier tasks, not this follow-up. The operator confirms both
profiles were enforcing and the baseline was restored and verified after the
candidate experiment. That restoration is supplied evidence, not a remote
inspection performed here. No server was accessed or altered.

The complete runbook, both policy stanzas, executor, and existing AppArmor/OS
tests were read. Public Bubblewrap v0.9.0, glibc 2.39, and Linux v6.8 sources
were retrieved and the relevant helpers and call sites inspected again:

| Evidence | What it establishes | Limit |
| --- | --- | --- |
| Supplied `open`, `error=-13`, disconnected-path info, `gvai-bwrap`, `proc/7029/uid_map`, masks `wr` | AppArmor could not resolve the mapping-file name for this open | Not a missing mapping-file allow rule; not proof of the mapping pass or exact FD |
| `main()` opens `/proc` before `raw_clone(SIGCHLD \| CLONE_NEWNS \| ...)`; both self-mapping calls use global `proc_fd` | Both mapping passes can use an FD referencing the original mount namespace | Upstream sequence, not a syscall trace of the installed Ubuntu package |
| `write_file_at()` opens the mapping file with `O_RDWR \| O_CLOEXEC` | Read **and** write audit masks are expected, even though map contents are written | Does not establish that a write syscall was reached |
| `copy_mnt_ns()` copies mounts and retargets root/cwd; AppArmor tests `our_mnt()` | A retained FD can be foreign to the child mount namespace before any pivot | Matching path text, filesystem type, or inode alone does not establish mount connectivity |
| `profile_path_perm()` returns a path-name error before `__aa_path_perm()` | Adding mapping globs cannot repair this name-resolution failure | Exact Ubuntu kernel backports remain unverified |
| `proc_self_get_link()` resolves TGID using the procfs superblock's PID namespace | `self` on the inherited procfs can resolve to an outer PID such as 7029 | The audit filename is not evidence that inner PID isolation failed |

For the fixed non-setuid UID/GID-1000 command, the upstream sequence is:
loopback setup; first UID/GID maps `0 1000 1` with `setgroups=deny`;
mount construction and both root pivots; nested user namespace; second maps
`1000 0 1` without another setgroups write; privilege removal and worker exec.
Both UID-map failures print the same stderr. Therefore an assertion that
"the pivot detached procfs and caused this particular open" is too specific:
the mount-namespace clone alone is sufficient to explain a foreign mount.
Conversely, seeing the mapping error after adding the Unix datagram rule
supports progress past loopback setup for that run, not sandbox acceptance
or permission to retain the candidate on the host.

**Narrowest correction assessment: STOP, no implementation change.**
No additional AppArmor permission repairs failed path resolution under the
stated constraints. The bounded research direction remains a mapping-only FD
reopened through a verified connected procfs view at **each** self-mapping
call. That is not an established safe patch: after the pivots, the procfs
view/PID namespace differs, and subsequent DAC, mapping, mount-helper and FD
cleanup behavior must also be verified. Do not replace the shared global FD,
add a fallback to it, or ship an alternate launcher based on this analysis.
There is no Bubblewrap source vendored here to patch, and no restricted,
enforcing test environment was established for accepting such a redesign.
The current launcher datagram rule is historical candidate content, not a
new host change or a successful resolution.

#### Evidence required before another implementation experiment

1. Obtain administrator-exported **existing** evidence first: complete audit
   serial groups, timestamps, PID/comm/profile and exit/stderr correlation;
   exact installed Bubblewrap package revision, binary checksum, matching
   distribution source/patches, kernel build, and loaded-policy provenance.
   Do not infer the loaded policy from an on-disk file alone. The preserved
   root-owned log has not been accessed by this investigation.
2. Only in a separately authorized disposable Ubuntu environment matching
   the restriction/enforcement baseline, record the pre-clone proc FD, clone
   flags, child mount namespace, and both mapping-call sites. Correlate
   `openat` dirfds and paths, map strings/order, and each FD's mount ID against
   the **same process's current** mountinfo. Compare inherited and freshly
   resolved procfs FDs, including procfs/PID-namespace provenance. Inspect
   `fdinfo` externally only if existing permissions permit it; do not expand
   policy just to enable diagnostics. Record where tracing changes behavior.
3. A future mapping-only prototype must fail closed on open/verification
   failure, preserve both maps and deny-setgroups ordering, and prove that
   host/setup mounts and FDs do not survive into the worker. Attribute every
   remaining fatal launcher denial separately. Passing one mapping is
   insufficient, and a trace is not an untraced acceptance result.
4. Require the existing full host suite without security skips, the exact
   enforcing stack before/after negative attempts, all six namespace
   identities (user, PID, mount, network, UTS, IPC), zero capabilities,
   `NoNewPrivs=1`, active seccomp, fixed-worker success/attack cases, and
   blocked worker writes to UID/GID maps and setgroups. Separately integrate
   and test supervisor cancellation. None of these requirements is waived.

The unchanged candidate must **not** be reloaded on the production/test
server to collect this evidence. No AppArmor disable/complain/unconfined
execution, disconnected-path attachment, procfs permission expansion,
network-isolation removal, worker relaxation, merge, or deployment is part of
this work.

#### Follow-up regression scope

The executor contract now pins one `--proc /proc` and one `--dev /dev`, with no
externally supplied user-namespace FD or UID/GID override. This preserves the
mapping sequence being diagnosed rather than bypassing it. Synthetic failures
now also cover opening `/proc` and `/proc/self`, in addition to UID-map,
setgroups and GID-map failures: availability refuses fallback and execution
preserves stderr while refusing authorization/output promotion. The embedded
host probe is syntax-compiled in ordinary tests, and mandatory host acceptance
checks mount, UTS and IPC namespace identities as well as user/PID/network.
These are regression guards, not an AppArmor-kernel reproduction or validation
of a connected-procfs patch. Policy and production code remain byte-identical
to the starting commit.

#### Follow-up validation and publication

The local kernel remains `6.8.0-1064-azure`, Bubblewrap reports 0.9.0, and
`apparmor_restrict_unprivileged_userns` is **0**, not the required 1. No sysctl
or policy was changed. The default Python 3.14.2 lacked pytest, so the existing
requirements were restored into this session's isolated virtualenv, with no
repository dependency changes or system installation. The editor test tool
found no tests; the existing pytest runner was then used directly.

| Follow-up check | Result |
| --- | --- |
| `python -m pytest -q -rs -p no:cacheprovider tests/test_apparmor_sandbox.py tests/test_os_sandbox.py` | **51 passed, 8 skipped** |
| Ordinary-run host-probe syntax check | Passed as part of the focused suite |
| Policy and production launcher/worker comparison to `cf3c771` | Identical |
| `git diff --check` | Passed |
| Restricted/enforcing AppArmor reproduction, redesigned launcher, host acceptance | **Not performed / not verified** |

All eight skips are explicitly opt-in host acceptance cases; all 16 existing
OS sandbox regressions executed. The focused suite covers this docs/tests-only
change; no full-suite rerun or new parser compile is claimed. Historical
validation tables above are not new results.

The operator authorized committing/pushing this follow-up branch and opening
an **evidence-only draft PR against `feature/ubuntu-bwrap-apparmor`**, the
existing candidate branch for draft #16. This keeps inherited policy and
production changes outside the new PR's diff. Publication is not host-test,
merge, or deployment authorization. The safe-correction work stops here:
acceptance remains blocked, and no further policy or launcher correction
should be inferred from the draft.

## Research sources

* [Ubuntu Security: Understanding AppArmor user namespace restriction](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)
  explains per-application authorization and the risks of unconfined exceptions.
* [Ubuntu Noble apparmor.d(5)](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html)
  specifies userns, capability, exec, mount, and mediation rules.
* [Bubblewrap v0.9.0 implementation](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c)
  establishes early `no_new_privs`, namespace/mapping/pivot order, capability
  dropping, and seccomp-before-exec.
* [Mapping helper](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L950),
  [pre-clone proc FD](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L2816),
  [first mapping](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L3067),
  [nested userns mapping](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c#L3244),
  and [write helper](https://github.com/containers/bubblewrap/blob/v0.9.0/utils.c#L447)
  establish both mapping passes and the `O_RDWR` open.
* [Linux v6.8 mount namespace copying](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L3760)
  and [`our_mnt()`](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c#L5243)
  distinguish the mount in an inherited FD from a mount in the current namespace.
* [Linux v6.8 procfs self resolution](https://github.com/torvalds/linux/blob/v6.8/fs/proc/self.c#L11)
  uses the procfs superblock's PID namespace, explaining outer-PID audit names
  without implying that the worker shares the host PID namespace.
* [AppArmor path resolution](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/path.c)
  and [file permission checks](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/file.c#L249)
  establish disconnected-name rejection before ordinary path-rule matching.
  These upstream sources corroborate the mechanism; they do not certify
  Ubuntu's exact target kernel build.
* [Bubblewrap v0.9.0 loopback initialization](https://github.com/containers/bubblewrap/blob/v0.9.0/network.c)
  calls `if_nametoindex("lo")` before raw routing-netlink setup.
* [glibc 2.39 interface lookup](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/unix/sysv/linux/if_index.c)
  and [ioctl socket selection](https://github.com/bminor/glibc/blob/glibc-2.39/socket/opensock.c)
  establish the Unix/IPv4/IPv6 datagram fallbacks and final `ENOENT`.
* [libselinux initialization](https://github.com/SELinuxProject/selinux/blob/3.5/libselinux/src/init.c)
  explains a possible nonfatal source of the two procfs reads; it does not
  establish the target denials' cause.
* [Linux 6.8 AppArmor transitions](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/domain.c)
  explains the `no_new_privs` label-subset check and stacked subsets. Ubuntu
  backports still require actual host verification.
* [AppArmor parser stacking fixture](https://github.com/oxagast/apparmor/blob/master/parser/tst/simple_tests/file/stacking_ok_1.sd)
  and [exec stacking regression](https://github.com/oxagast/apparmor/blob/master/tests/regression/apparmor/exec_stack.sh)
  corroborate explicit `&profile` targets and intersection semantics.
