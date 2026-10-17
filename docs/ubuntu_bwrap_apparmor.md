# Ubuntu 24.04 Bubblewrap / AppArmor candidate

## Status: human review and host acceptance required

This is a **configuration proposal, not an accepted or deployed sandbox**.
Nothing in this change loads policy, changes sysctls, installs a service, or
contacts the DigitalOcean server. Do not enable governed workloads until all
host acceptance and supervisor cancellation tests pass without security skips.

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

### Reported live failure and minimal next experiment

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

For the next **separately approved human-run** experiment, stop dispatch and
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
  (profile order may differ), with isolated user/PID/network namespaces.
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

### Local correction to PR #16 (not published)

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

## Research sources

* [Ubuntu Security: Understanding AppArmor user namespace restriction](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)
  explains per-application authorization and the risks of unconfined exceptions.
* [Ubuntu Noble apparmor.d(5)](https://manpages.ubuntu.com/manpages/noble/man5/apparmor.d.5.html)
  specifies userns, capability, exec, mount, and mediation rules.
* [Bubblewrap v0.9.0 implementation](https://github.com/containers/bubblewrap/blob/v0.9.0/bubblewrap.c)
  establishes early `no_new_privs`, namespace/mapping/pivot order, capability
  dropping, and seccomp-before-exec.
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
