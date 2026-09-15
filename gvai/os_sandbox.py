from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet

from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.seccomp_filter import (
    SeccompUnavailable,
    build_no_spawn_filter,
    libseccomp_available,
)


class OSSandboxUnavailable(RuntimeError):
    pass


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

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    except (
        OSError,
        subprocess.TimeoutExpired,
    ):
        return False

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

        self.commit_root.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not bwrap_usable():
            raise OSSandboxUnavailable(
                "bubblewrap OS sandbox is unavailable. "
                "Refusing to fall back to userspace enforcement."
            )

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
    ) -> OSSandboxTransaction:
        binary = bwrap_path()

        if binary is None:
            raise OSSandboxUnavailable(
                "bwrap disappeared after initialization."
            )

        with tempfile.TemporaryDirectory(
            prefix="gv-os-sandbox-"
        ) as tmp:
            root = Path(tmp)

            work = root / "work"
            safety = root / "safety"

            work.mkdir()
            safety.mkdir()

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
                "--new-session",

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
                        str(self.input_root),
                        "/input",
                    ]
                    if self.input_root is not None
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
                try:
                    process = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                        pass_fds=(
                            seccomp_filter.fd,
                        ),
                        env={
                            "PATH": "/usr/bin:/bin",
                            "HOME": "/tmp",
                            "PYTHONNOUSERSITE": "1",
                        },
                    )

                except subprocess.TimeoutExpired as exc:
                    process = subprocess.CompletedProcess(
                        args=command,
                        returncode=-1,
                        stdout=(
                            exc.stdout.decode()
                            if isinstance(exc.stdout, bytes)
                            else (exc.stdout or "")
                        ),
                        stderr=(
                            exc.stderr.decode()
                            if isinstance(exc.stderr, bytes)
                            else (exc.stderr or "")
                        ),
                    )

                    timeout_event = {
                        "event": "worker_timeout",
                        "timeout_seconds": 10,
                    }

                else:
                    timeout_event = None

            finally:
                seccomp_filter.close()

            stdout_lines = [
                line
                for line
                in process.stdout.splitlines()
                if line.strip()
            ]

            result: dict = {}

            if stdout_lines:
                try:
                    result = json.loads(
                        stdout_lines[-1]
                    )
                except json.JSONDecodeError:
                    result = {
                        "completed": False,
                        "error": (
                            "Worker returned invalid JSON."
                        ),
                        "events": [],
                    }

            events = list(
                result.get(
                    "events",
                    [],
                )
            )

            if timeout_event is not None:
                events.append(timeout_event)

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

            resolved = ActionSpec(
                name=action,
                effects=observed_effects,
            )

            runtime = (
                self.guard.evaluate_action(
                    resolved,
                    observation,
                )
            )

            committed = False

            worker_completed = bool(
                result.get(
                    "completed",
                    False,
                )
            )

            if (
                runtime.allowed
                and self.commit_enabled
                and worker_completed
            ):
                commit_failed = False

                for source in work.rglob("*"):
                    if source.is_symlink():
                        commit_failed = True
                        break

                    if not source.is_file():
                        continue

                    relative = (
                        source.relative_to(
                            work
                        )
                    )

                    target = (
                        self.commit_root
                        / relative
                    )

                    resolved_target = (
                        target.resolve(
                            strict=False
                        )
                    )

                    try:
                        resolved_target.relative_to(
                            self.commit_root
                        )
                    except ValueError:
                        commit_failed = True
                        break

                    target.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    # Re-check after directory creation.
                    resolved_target = (
                        target.resolve(
                            strict=False
                        )
                    )

                    try:
                        resolved_target.relative_to(
                            self.commit_root
                        )
                    except ValueError:
                        commit_failed = True
                        break

                    if target.is_symlink():
                        commit_failed = True
                        break

                    shutil.copy2(
                        source,
                        target,
                    )

                committed = not commit_failed

            return OSSandboxTransaction(
                action=action,
                returncode=process.returncode,
                completed=bool(
                    result.get(
                        "completed",
                        False,
                    )
                ),
                error=result.get("error"),
                observed_effects=observed_effects,
                events=tuple(events),
                allowed=runtime.allowed,
                committed=committed,
                halted=runtime.halted,
                reason=runtime.reason,
                stderr=process.stderr,
            )
