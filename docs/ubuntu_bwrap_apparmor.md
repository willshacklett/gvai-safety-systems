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

Stop if the baseline differs, either GVAI profile name is already loaded, or
another profile attaches to `/usr/bin/bwrap`. Do not replace a vendor or local
policy silently. Save the above output and the full existing profile list in
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

Expected: zero failed tests and **zero skipped security cases** on the supported
host. Existing OS tests can skip on setup failure; the explicit acceptance
suite cannot. Retain failures and audit records. Denials from deliberate worker
attacks are expected; bootstrap denials or absence of the stacked enforcing
label are blockers. Do not run an automatic profile generator to turn these
denials into allowances. After selecting/integrating a supervisor draft, also
run its real `tests/test_supervisor.py` tests and acceptance cases on this host;
that file is intentionally absent on this branch.

## Rollback (human only)

Stop dispatch through the **trusted host control plane** and independently
terminate/reap all governed processes first. Do not unload policy from under
live workers: removing an enforcing profile can remove their confinement.
If startup failed partway through, inspect the actual loaded profiles before
rollback; do not assume a successful load or that the load was atomic.

For a successfully loaded candidate from the procedure above:

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

Local validation uses Ubuntu 24.04.5 userspace and Bubblewrap 0.9.0, but kernel
`6.8.0-1064-azure`, an unconfined caller, and user-namespace restriction **0**.
No sysctl or live policy was changed. The missing parser was extracted from
Ubuntu's `apparmor_4.0.1really4.0.1-0ubuntu0.24.04.9_amd64.deb` into session
storage, not installed or activated. Compilation uses its bundled ABI 4.0 and
`-Q -K`, with no kernel load or cache writes.

* Local focused tests cover mandatory policy structure, absolute executable
  selection, unsafe binary rejection, fail-closed bootstrap/results, and
  existing real Bubblewrap containment and authorization contracts.
* Final local full regression: **211 passed, 4 skipped**. The four skips are
  the explicitly opt-in supported-host cases; existing OS tests executed.
  AppArmor 4.0.1 compilation with ABI 4.0, `--warn=all --Werror -Q -K`
  completed successfully, as did `git diff --check`.
* Ordinary local runs explicitly skip the four new supported-host cases.
* Explicit local acceptance (`GVAI_APPARMOR_ACCEPTANCE=1`) fails on the absent
  restricted-host prerequisites instead of skipping. This is a negative check,
  **not successful host acceptance**: one test failed and three fixture setups
  errored, all because the local restriction sysctl is 0 rather than 1.
* Syntax compilation cannot verify mount path mediation, procfs remapping,
  routing-netlink permission, kernel stacking, launcher capability removal,
  or supervisor shutdown. All remain target-host verification requirements.
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
  uses raw routing-netlink for the isolated loopback.
* [Linux 6.8 AppArmor transitions](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/domain.c)
  explains the `no_new_privs` label-subset check and stacked subsets. Ubuntu
  backports still require actual host verification.
* [AppArmor parser stacking fixture](https://github.com/oxagast/apparmor/blob/master/parser/tst/simple_tests/file/stacking_ok_1.sd)
  and [exec stacking regression](https://github.com/oxagast/apparmor/blob/master/tests/regression/apparmor/exec_stack.sh)
  corroborate explicit `&profile` targets and intersection semantics.
