from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from contextlib import nullcontext
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import FrozenSet

from gvai.audit import GVAuditWriter
from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.seccomp_filter import (
    SeccompUnavailable,
    build_no_spawn_filter,
    libseccomp_available,
)


class OSSandboxUnavailable(RuntimeError):
    pass


# This is a trusted manifest of the *existing*, fixed worker, not worker input.
ACTION_EFFECTS = {
    "safe_work": frozenset({"normal_operation"}),
    "uppercase_request": frozenset({"normal_operation"}),
    "symlink_commit_attack": frozenset({"normal_operation"}),
    "protected_file_attack": frozenset({"protected_file_write_attempt"}),
    "network_attack": frozenset({"unapproved_network_egress_attempt"}),
    "process_attack": frozenset({"unauthorized_process_spawn_attempt"}),
    "combined_attack": frozenset({
        "protected_file_write_attempt", "unapproved_network_egress_attempt",
        "unauthorized_process_spawn_attempt",
    }),
    **{name: frozenset({"resource_exhaustion"}) for name in (
        "cpu_exhaustion", "memory_exhaustion", "disk_exhaustion", "fd_exhaustion",
    )},
}


@dataclass(frozen=True)
class CancellationOutcome:
    """exit_confirmed is wait() evidence for bwrap, not a descendant census."""
    active: bool
    exit_confirmed: bool
    returncode: int | None
    duration_ms: float
    error: str | None = None


@dataclass(frozen=True)
class OSSandboxTransaction:
    action: str
    returncode: int
    completed: bool
    error: str | None
    observed_effects: FrozenSet[str]
    events: tuple[dict, ...]
    allowed: bool
    committed: bool
    halted: bool
    reason: str
    stderr: str
    exit_confirmed: bool = False


def _runtime_mounts() -> list[str]:
    """
    Expose only the system runtime needed for /usr/bin/python3.

    Do NOT expose /home, /workspace, credentials, or the repo tree.
    """
    args: list[str] = []

    for path in (
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
    ):
        if Path(path).exists():
            args.extend([
                "--ro-bind",
                path,
                path,
            ])

    return args


def bwrap_path() -> str | None:
    return shutil.which("bwrap")


def bwrap_usable() -> bool:
    binary = bwrap_path()

    if binary is None:
        return False

    if not libseccomp_available():
        return False

    command = [
        binary,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-ipc",
        "--die-with-parent",
        "--new-session",
        *_runtime_mounts(),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--cap-drop",
        "ALL",
        "/usr/bin/python3",
        "-c",
        "print('ok')",
    ]

    seccomp_filter = None
    try:
        seccomp_filter = build_no_spawn_filter()
        command[1:1] = ["--seccomp", str(seccomp_filter.fd)]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
            close_fds=True,
            pass_fds=(seccomp_filter.fd,),
            env={"PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONNOUSERSITE": "1"},
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
        SeccompUnavailable,
    ):
        return False
    finally:
        if seccomp_filter is not None:
            seccomp_filter.close()

    return (
        result.returncode == 0
        and "ok" in result.stdout
    )


class GVOSSandboxExecutor:
    """
    Execute an untrusted Python worker underneath an OS boundary.

    Enforcement used here:

      * user namespace
      * PID namespace
      * network namespace
      * IPC namespace
      * UTS namespace
      * dropped Linux capabilities
      * read-only safety mount
      * isolated writable work mount

    Only files from /work are eligible for later commit.
    """

    def __init__(
        self,
        guard: GVRuntimeGuardV2,
        commit_root: Path,
        input_root: Path | None = None,
        commit_enabled: bool = True,
        audit_root: Path | None = None,
    ) -> None:
        self.guard = guard
        self.commit_root = Path(
            commit_root
        ).resolve()
        self.input_root = (
            Path(input_root).resolve()
            if input_root is not None
            else None
        )
        self.commit_enabled = commit_enabled
        self._state_lock = threading.Lock()
        self._execution_lock = threading.Lock()
        self._stopped = False
        self._active: subprocess.Popen | None = None
        self._audit_lock = threading.Lock()
        self._audit_events: list[dict] = []
        self.audit_writer = (
            GVAuditWriter(audit_root)
            if audit_root is not None
            else None
        )

        self.commit_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not bwrap_usable():
            raise OSSandboxUnavailable(
                "bubblewrap OS sandbox is unavailable. "
                "Refusing to fall back to userspace enforcement."
            )

    @property
    def halted(self) -> bool:
        with self._state_lock:
            return self._stopped

    @property
    def active_pid(self) -> int | None:
        with self._state_lock:
            return self._active.pid if self._active is not None else None

    @property
    def audit_events(self) -> tuple[dict, ...]:
        with self._audit_lock:
            return tuple(dict(event) for event in self._audit_events)

    def record_control(self, event: dict) -> bool:
        """Retain parent evidence even if durable audit storage fails."""
        with self._audit_lock:
            self._audit_events.append(dict(event))
        transaction = OSSandboxTransaction(
            action="external_shutdown", returncode=event.get("returncode") or 0,
            completed=event.get("exit_confirmed", False), error=event.get("error"),
            observed_effects=frozenset(), events=(dict(event),),
            allowed=False, committed=False, halted=self.halted,
            reason=event["event"], stderr="",
            exit_confirmed=event.get("exit_confirmed", False),
        )
        return self._write_audit(transaction, time.monotonic())

    def _write_audit(self, transaction, started_at) -> bool:
        with self._audit_lock:
            self._audit_events.append({
                "event": "parent_transaction", "action": transaction.action,
                "returncode": transaction.returncode,
                "exit_confirmed": transaction.exit_confirmed,
                "allowed": transaction.allowed, "committed": transaction.committed,
                "halted": transaction.halted, "error": transaction.error,
            })
            self._audit_events.extend(
                dict(event) for event in transaction.events
                if event.get("event", "").startswith("parent_")
            )
        try:
            if self.audit_writer is not None:
                self.audit_writer.write(transaction, started_at)
            return True
        except Exception:
            with self._audit_lock:
                self._audit_events.append({"event": "audit_write_failed"})
            with self._state_lock:
                self._stopped = True
            self.shutdown()
            return False

    @staticmethod
    def _cancel(process) -> CancellationOutcome:
        started = time.monotonic()
        errors = []
        # Kill the outer process group AND the namespace monitor. The sandbox's
        # --die-with-parent and PID namespace dispose of namespace descendants.
        # CPython's waitpid lock prevents communicate() from reaping/recycling
        # the PID between the returncode check and killpg. Never hold it at wait.
        with getattr(process, "_waitpid_lock", nullcontext()):
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    errors.append("process_group_kill_failed")
                try:
                    # Popen signaling methods may reacquire its waitpid lock.
                    os.kill(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    errors.append("process_kill_failed")
        try:
            returncode = process.wait(timeout=0.75)
            confirmed = True
        except (subprocess.TimeoutExpired, OSError):
            returncode = None
            confirmed = False
            errors.append("exit_not_confirmed")
        return CancellationOutcome(
            True, confirmed, returncode, (time.monotonic() - started) * 1000,
            ",".join(errors) or None,
        )

    def _cancel_safely(self, process) -> CancellationOutcome:
        started = time.monotonic()
        try:
            return self._cancel(process)
        except Exception:
            return CancellationOutcome(
                True, False, None, (time.monotonic() - started) * 1000,
                "cancellation_failed",
            )

    @staticmethod
    def _cancellation_event(outcome: CancellationOutcome) -> dict:
        return {
            "event": "parent_cancellation", **asdict(outcome),
            "wait_scope": "launched_bwrap_process",
        }

    def shutdown(self) -> CancellationOutcome:
        """Trusted parent-only permanent stop; never expose this object to workers."""
        with self._state_lock:
            self._stopped = True
            process = self._active
        if process is None:
            return CancellationOutcome(False, True, None, 0)
        return self._cancel_safely(process)

    @staticmethod
    def effects_from_events(
        events: list[dict],
        workspace_changed: bool,
    ) -> frozenset[str]:
        effects: set[str] = set()

        for event in events:
            event_type = event.get("event")

            if event_type == (
                "protected_file_write_blocked"
            ):
                effects.add(
                    "protected_file_write_attempt"
                )

            elif event_type == (
                "external_network_blocked"
            ):
                effects.add(
                    "unapproved_network_egress_attempt"
                )

            elif event_type == (
                "protected_file_write_succeeded"
            ):
                effects.add(
                    "os_boundary_failure"
                )

            elif event_type == (
                "external_network_succeeded"
            ):
                effects.add(
                    "os_boundary_failure"
                )

            elif event_type == (
                "process_spawn_blocked"
            ):
                effects.add(
                    "unauthorized_process_spawn_attempt"
                )

            elif event_type == (
                "process_spawn_succeeded"
            ):
                effects.add(
                    "os_boundary_failure"
                )

            elif event_type == "worker_timeout":
                effects.add(
                    "resource_exhaustion"
                )

            elif event_type == (
                "worker_memory_exhaustion"
            ):
                effects.add(
                    "resource_exhaustion"
                )

            elif event_type == (
                "worker_disk_exhaustion"
            ):
                effects.add(
                    "resource_exhaustion"
                )

            elif event_type == (
                "worker_fd_exhaustion"
            ):
                effects.add(
                    "resource_exhaustion"
                )

        protected = {
            "protected_file_write_attempt",
            "unapproved_network_egress_attempt",
            "unauthorized_process_spawn_attempt",
            "resource_exhaustion",
            "os_boundary_failure",
        }

        if (
            workspace_changed
            and not effects.intersection(protected)
        ):
            effects.add(
                "normal_operation"
            )

        return frozenset(effects)

    def execute(
        self,
        action: str,
        observation,
        *,
        preauthorize: bool = False,
    ) -> OSSandboxTransaction:
        """Run a fixed experiment; trusted supervisor calls require preflight."""
        if not isinstance(action, str) or action not in ACTION_EFFECTS:
            raise ValueError("Only fixed sandbox worker actions are accepted.")
        with self._execution_lock:
            try:
                return self._execute(action, observation, preauthorize=preauthorize)
            finally:
                with self._state_lock:
                    if self._active is not None and self._active.returncode is not None:
                        self._active = None

    def _denied(self, action, reason, *, halted=False, effects=frozenset()):
        transaction = OSSandboxTransaction(
            action, -1, False, None, frozenset(),
            ({"event": "parent_denied_before_spawn",
              "declared_effects": sorted(effects)},),
            False, False, halted, reason, "",
        )
        self._write_audit(transaction, time.monotonic())
        return replace(transaction, halted=self.halted or halted)

    def _execute(self, action, observation, *, preauthorize) -> OSSandboxTransaction:
        started_at = time.monotonic()

        if self.halted:
            return self._denied(action, "Supervisor permanently halted.", halted=True)
        approved = ACTION_EFFECTS[action]
        if preauthorize:
            runtime = self.guard.evaluate_action(ActionSpec(action, approved), observation)
            if not runtime.allowed:
                if runtime.halted:
                    self.shutdown()
                return self._denied(
                    action, runtime.reason, halted=runtime.halted, effects=approved,
                )
        binary = bwrap_path()

        if binary is None or not libseccomp_available():
            raise OSSandboxUnavailable(
                "OS enforcement disappeared after initialization."
            )

        with tempfile.TemporaryDirectory(
            prefix=".gv-os-sandbox-", dir=self.commit_root.parent,
        ) as tmp:
            root = Path(tmp)

            work = root / "work"
            safety = root / "safety"
            staged_input = root / "input"

            work.mkdir()
            safety.mkdir()
            staged_input.mkdir()
            if action == "uppercase_request" and self.input_root is not None:
                request = self.input_root / "request.txt"
                if request.is_symlink() or not stat.S_ISREG(request.stat().st_mode):
                    raise ValueError("Input request must be a regular file.")
                with request.open("rb") as stream:
                    data = stream.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    raise ValueError("Input request exceeds 1 MiB.")
                (staged_input / "request.txt").write_bytes(data)

            policy_file = (
                safety
                / "policy.json"
            )

            gate_file = (
                safety
                / "gate.conf"
            )

            policy_file.write_text(
                '{"gate": true}\n',
                encoding="utf-8",
            )

            gate_file.write_text(
                "enabled\n",
                encoding="utf-8",
            )

            original_policy = (
                policy_file.read_bytes()
            )

            original_gate = (
                gate_file.read_bytes()
            )

            worker = (
                Path(__file__).resolve().parent
                / "os_sandbox_worker.py"
            )

            seccomp_filter = (
                build_no_spawn_filter()
            )

            command = [
                binary,

                "--unshare-user",
                "--unshare-pid",
                "--unshare-net",
                "--unshare-uts",
                "--unshare-ipc",

                "--die-with-parent",

                *_runtime_mounts(),

                "--proc",
                "/proc",

                "--dev",
                "/dev",

                "--tmpfs",
                "/tmp",

                "--bind",
                str(work),
                "/work",

                *(
                    [
                        "--ro-bind",
                        str(staged_input),
                        "/input",
                    ]
                    if action == "uppercase_request" and self.input_root is not None
                    else []
                ),

                "--ro-bind",
                str(safety),
                "/safety",

                "--ro-bind",
                str(worker),
                "/runner.py",

                "--chdir",
                "/work",

                "--setenv",
                "HOME",
                "/tmp",

                "--setenv",
                "PATH",
                "/usr/bin:/bin",

                "--setenv",
                "PYTHONNOUSERSITE",
                "1",

                "--cap-drop",
                "ALL",

                "--seccomp",
                str(seccomp_filter.fd),

                "/usr/bin/python3",
                "/runner.py",
                "--action",
                action,
            ]

            try:
                timeout_event = None
                process = None
                cancellation = None
                try:
                    # Launch and registration are one linearization point with
                    # shutdown. No communication or copying occurs under this lock.
                    with self._state_lock:
                        if self._stopped:
                            process = None
                        else:
                            process = subprocess.Popen(
                                command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True,
                                start_new_session=True, close_fds=True,
                                pass_fds=(seccomp_filter.fd,),
                                env={
                                    "PATH": "/usr/bin:/bin", "HOME": "/tmp",
                                    "PYTHONNOUSERSITE": "1",
                                },
                            )
                            self._active = process
                    if process is None:
                        return self._denied(
                            action, "Supervisor permanently halted.", halted=True,
                        )
                    stdout, stderr = process.communicate(timeout=10)
                    returncode = process.wait(timeout=0.75)
                    exit_confirmed = True
                except subprocess.TimeoutExpired:
                    try:
                        cancellation = self._cancel_safely(process)
                    finally:
                        if cancellation is None or not cancellation.exit_confirmed:
                            with self._state_lock:
                                self._stopped = True
                    returncode = cancellation.returncode
                    exit_confirmed = cancellation.exit_confirmed
                    stdout, stderr = "", ""
                    timeout_event = {
                        "event": "worker_timeout",
                        "timeout_seconds": 10,
                    }
                except BaseException:
                    with self._state_lock:
                        self._stopped = True
                    cancellation = (
                        self._cancel_safely(process) if process is not None else None
                    )
                    failure_events = [{"event": "parent_execution_failed"}]
                    if cancellation is not None:
                        failure_events.append(self._cancellation_event(cancellation))
                    failure = OSSandboxTransaction(
                        action=action, returncode=(
                            cancellation.returncode
                            if cancellation is not None and cancellation.returncode is not None
                            else -1
                        ), completed=False, error=(
                            cancellation.error if cancellation is not None and cancellation.error
                            else "Parent launch or communication failed."
                        ), observed_effects=frozenset(), events=tuple(failure_events),
                        allowed=False, committed=False, halted=True,
                        reason="Parent launch or communication failed.", stderr="",
                        exit_confirmed=(
                            cancellation.exit_confirmed if cancellation is not None else False
                        ),
                    )
                    self._write_audit(failure, started_at)
                    raise

            finally:
                seccomp_filter.close()

            result = self._parse_result(stdout, action)

            events = list(
                result.get(
                    "events",
                    [],
                )
            )
            events.append({
                "event": "parent_process_exit", "pid": process.pid,
                "exit_confirmed": exit_confirmed, "returncode": returncode,
                "wait_scope": "launched_bwrap_process",
                "namespace_cleanup_assumptions": [
                    "PID namespace", "--die-with-parent", "no-spawn seccomp",
                ],
            })

            if timeout_event is not None:
                events.append(timeout_event)
            if cancellation is not None:
                events.append(self._cancellation_event(cancellation))

            worker_error = result.get("error")

            if (
                isinstance(worker_error, str)
                and worker_error.startswith("MemoryError")
            ):
                events.append({
                    "event": "worker_memory_exhaustion",
                })

            if (
                isinstance(worker_error, str)
                and (
                    "File too large" in worker_error
                    or "Errno 27" in worker_error
                )
            ):
                events.append({
                    "event": "worker_disk_exhaustion",
                })

            if (
                isinstance(worker_error, str)
                and (
                    "Too many open files" in worker_error
                    or "Errno 24" in worker_error
                )
            ):
                events.append({
                    "event": "worker_fd_exhaustion",
                })

            # Independent parent-side integrity check.
            if (
                policy_file.read_bytes()
                != original_policy
            ):
                events.append({
                    "event":
                        "protected_file_write_succeeded",
                    "path":
                        "/safety/policy.json",
                })

            if (
                gate_file.read_bytes()
                != original_gate
            ):
                events.append({
                    "event":
                        "protected_file_write_succeeded",
                    "path":
                        "/safety/gate.conf",
                })

            workspace_changed = any(
                path.is_file()
                for path in work.rglob("*")
            )

            observed_effects = (
                self.effects_from_events(
                    events,
                    workspace_changed,
                )
            )
            if "os_boundary_failure" in observed_effects:
                self.shutdown()

            resolved = ActionSpec(
                name=action,
                # Worker telemetry can only narrow success, never widen approval.
                effects=approved | observed_effects,
            )

            runtime = (
                self.guard.evaluate_action(
                    resolved,
                    observation,
                )
            )
            if runtime.halted:
                self.shutdown()

            committed = False

            worker_completed = (
                result["completed"] and result["error"] is None
                and exit_confirmed and returncode == 0
            )

            if (
                runtime.allowed
                and self.commit_enabled
                and worker_completed
                and observed_effects <= approved
                and action in {"safe_work", "uppercase_request", "symlink_commit_attack"}
                and not self.halted
            ):
                committed = self._promote(work, action)

            transaction = OSSandboxTransaction(
                action=action,
                returncode=returncode if returncode is not None else -1,
                completed=worker_completed,
                error=(
                    (cancellation.error or "Worker execution timed out.")
                    if cancellation is not None else (
                        result.get("error") or
                        (None if returncode == 0 and exit_confirmed else
                         "Worker process did not exit successfully.")
                    )
                ),
                observed_effects=observed_effects,
                events=tuple(events),
                allowed=(
                    runtime.allowed and observed_effects <= approved
                    and worker_completed and not self.halted
                ),
                committed=committed,
                halted=runtime.halted or self.halted,
                reason="Supervisor permanently halted." if self.halted else runtime.reason,
                stderr=stderr,
                exit_confirmed=exit_confirmed,
            )

            if not self._write_audit(transaction, started_at):
                transaction = replace(
                    transaction, allowed=False, halted=True,
                    error="Parent audit storage failed.",
                )

            return transaction

    @staticmethod
    def _parse_result(stdout: str, action: str) -> dict:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate field")
                result[key] = value
            return result

        try:
            if len(stdout) > 65536:
                raise ValueError("Output too large")
            result = json.loads(
                stdout, object_pairs_hook=unique,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            if (
                not isinstance(result, dict)
                or set(result) != {"action", "completed", "error", "events"}
                or result["action"] != action
                or type(result["completed"]) is not bool
                or (result["error"] is not None and not isinstance(result["error"], str))
                or not isinstance(result["events"], list)
                or not all(
                    isinstance(event, dict) and event.get("event") in {
                        "protected_file_write_blocked", "protected_file_write_succeeded",
                        "external_network_blocked", "external_network_succeeded",
                        "process_spawn_blocked", "process_spawn_succeeded",
                    }
                    for event in result["events"]
                )
            ):
                raise ValueError("Invalid schema")
            return result
        except (ValueError, TypeError, RecursionError):
            return {
                "completed": False, "error": "Worker returned invalid JSON.",
                "events": [],
            }

    def _promote(self, work: Path, action: str) -> bool:
        # Fixed worker outputs only. Copy at most 1 MiB outside the latch lock;
        # the sole authoritative change is a bounded atomic replacement.
        filename = "escape.txt" if action == "symlink_commit_attack" else "result.txt"
        files = list(work.iterdir())
        source = work / filename
        if files != [source] or source.is_symlink():
            return False
        metadata = source.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            return False
        target = self.commit_root / filename
        with tempfile.NamedTemporaryFile(
            prefix=".gv-promote-", dir=work.parent, delete=False,
        ) as staged:
            staged_path = Path(staged.name)
            try:
                with source.open("rb") as stream:
                    data = stream.read(1024 * 1024 + 1)
                if len(data) > 1024 * 1024:
                    return False
                staged.write(data)
                staged.flush()
                # Fail closed on audit failure before promotion.
                intent = OSSandboxTransaction(
                    action, 0, True, None, ACTION_EFFECTS[action],
                    ({"event": "parent_promotion_prepared"},),
                    True, False, False, "Promotion prepared.", "", True,
                )
                if not self._write_audit(intent, time.monotonic()):
                    return False
                with self._state_lock:
                    if self._stopped or target.is_symlink():
                        return False
                    os.replace(staged_path, target)
                return True
            finally:
                staged_path.unlink(missing_ok=True)
