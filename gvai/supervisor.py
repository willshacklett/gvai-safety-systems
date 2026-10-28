"""Trusted parent control plane; never import or expose this API in a worker."""
from __future__ import annotations

import json
import os
import shutil
import signal
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

from gvai.effects import ActionSpec
from gvai.external_commands import ExternalControlCommandVerifier
from gvai.identity import IdentityAuthority, IdentityAuthorizer, TenantResource
from gvai.os_sandbox import GVOSSandboxExecutor, KNOWN_ACTION_EFFECTS, OSSandboxUnavailable


class SupervisorStopped(RuntimeError):
    """The permanent parent shutdown latch or audit failure prevents execution."""


class TrustedSupervisor:
    """Authenticate, authorize and execute only the existing fixed sandbox actions.

    Construct exclusively in the trusted parent with its authority, authorizer,
    runtime guard, command verifier, and server-resolved resource registry. Call
    execute(evidence, resource_id, action, observation) from a parent thread.
    shutdown(envelope) may be called concurrently and authenticates against this
    instance's exact target_id. No caller-supplied contexts, grants or effects
    are accepted. A stopped instance cannot restart.

    root must be private to the parent and outside input_root. Successful output
    is a complete immutable generation exposed by the atomically replaced
    root/current symlink; readers should resolve current once per transaction.
    Control evidence is retained in memory and in root/control.jsonl. An audit
    storage failure prevents further launches/promotions but never prevents kill.
    Only one execution is admitted at once. Startup occurs off-lock: shutdown
    waits at most 0.8s for handoff/reaping, returning confirmed=False if the OS
    has not completed startup/exit. A late handoff is killed and reaped, never
    promoted. Confirmation requires parent wait() and an independent procfs
    check for live process-group members, never worker output. This relies on
    the fixed worker having no session-changing or process-spawning capability.
    """

    def __init__(
        self, *, target_id: str, authority: IdentityAuthority,
        authorizer: IdentityAuthorizer, guard,
        command_verifier: ExternalControlCommandVerifier,
        resources: dict[str, TenantResource], root: Path,
        resource_capability: str = "resource:execute", input_root: Path | None = None,
    ):
        self._require_procfs()
        self._root = Path(root).resolve()
        if any(self._root.is_relative_to(Path(mount).resolve())
               for mount in ("/usr", "/bin", "/lib", "/lib64")):
            raise ValueError("Supervisor root must be outside sandbox runtime mounts.")
        self._input_root = Path(input_root).resolve() if input_root is not None else None
        if self._input_root is not None and (
            self._root.is_relative_to(self._input_root)
            or self._input_root.is_relative_to(self._root)
        ):
            raise ValueError("Input and supervisor roots must not overlap.")
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._target_id = target_id
        self._authority = authority
        self._authorizer = authorizer
        self._guard = guard
        self._verifier = command_verifier
        self._resources = dict(resources)
        self._resource_capability = resource_capability
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._audit_lock = threading.Lock()
        self._stopped = False
        self._busy = False
        self._starting = False
        self._process = None
        self._last_returncode = None
        self._last_pgid = None
        self._audit_failed = False
        self._events: list[dict] = []
        self._executor = GVOSSandboxExecutor(
            guard, self._root / "unused", input_root=self._input_root,
            commit_enabled=False,
        )

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._stopped

    @property
    def evidence(self) -> tuple[dict, ...]:
        with self._audit_lock:
            return tuple(dict(event) for event in self._events)

    def _record(self, event: str, *, occurred_at=None, **details) -> None:
        record = dict(
            event=event,
            monotonic=time.monotonic() if occurred_at is None else occurred_at,
            unix_time=time.time(), **details,
        )
        with self._audit_lock:
            self._events.append(record)
        try:
            with (self._root / "control.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        except Exception:
            with self._lock:
                self._audit_failed = True
            with self._audit_lock:
                self._events.append(dict(
                    event="audit_storage_failed", monotonic=time.monotonic(),
                    unix_time=time.time(), failed_event=event,
                ))

    def execute(self, evidence, resource_id: str, action: str, observation):
        """Run a fixed action after parent-side authentication and policy checks."""
        identity = self._authority.authenticate(evidence)
        resource = self._resources.get(resource_id)
        if action not in KNOWN_ACTION_EFFECTS:
            raise PermissionError("Unknown action.")
        if resource is None or not self._authorizer.authorize_resource(
            identity, resource, self._resource_capability,
        ).allowed or not self._authorizer.authorize_tool(
            identity, action, scope=resource.scope,
        ).allowed:
            raise PermissionError("Identity/resource/tool authorization denied.")
        decision = self._guard.evaluate_action(
            ActionSpec(action, KNOWN_ACTION_EFFECTS[action]), observation,
        )
        if not decision.allowed or decision.halted:
            raise PermissionError("Runtime policy denied action before launch.")
        self._record("execution_authorized", action=action, principal=identity.principal_id)
        with self._lock:
            if self._stopped or self._audit_failed:
                raise SupervisorStopped()
            if self._busy or self._process is not None:
                raise RuntimeError("An execution is already active.")
            self._busy = True
        try:
            transaction = self._executor.execute(action, observation, _lifecycle=self)
            self._record(
                "execution_completed", action=action, returncode=transaction.returncode,
                committed=transaction.committed, allowed=transaction.allowed,
            )
            return transaction
        except BaseException as exc:
            self._record("execution_failed", action=action, error=type(exc).__name__)
            raise
        finally:
            with self._condition:
                self._busy = False
                self._condition.notify_all()

    def _start(self, command, kwargs):
        """Internal executor hook; subprocess creation never holds lifecycle lock."""
        self._require_procfs()
        with self._lock:
            if self._stopped or self._audit_failed:
                raise SupervisorStopped()
            self._starting = True
        child = None
        try:
            child = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True, **kwargs,
            )
            with self._lock:
                self._process = child
                self._last_pgid = child.pid
                cancelled = self._stopped or self._audit_failed
            self._record("process_started", pid=child.pid)
            if cancelled or self._audit_failed:
                raise SupervisorStopped()
            return child
        except BaseException:
            if child is not None:
                self._cancel_process(child, "startup_cancelled")
                self._confirm_exit(child)
            raise
        finally:
            with self._condition:
                self._starting = False
                self._condition.notify_all()

    def _cancel_process(self, child, reason):
        """Signal the process group (including the bwrap namespace monitor)."""
        signalled = False
        intent_at = time.monotonic()
        if child.poll() is None or not self._group_exited(child.pid):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            else:
                signalled = True
                signal_at = time.monotonic()
        self._record("cancellation_intent", occurred_at=intent_at, pid=child.pid, reason=reason)
        if signalled:
            self._record("signal_sent", occurred_at=signal_at, pid=child.pid, signal="SIGKILL")

    def _confirm_exit(self, child, timeout=None):
        deadline = time.monotonic() + (0.8 if timeout is None else timeout)
        returncode = child.wait(timeout=timeout)
        with self._lock:
            self._last_returncode = returncode
        self._record("launcher_exit_confirmed", pid=child.pid, returncode=returncode)
        while not self._group_exited(child.pid):
            if time.monotonic() >= deadline:
                with self._lock:
                    self._stopped = True
                self._record("process_group_exit_unconfirmed", pgid=child.pid)
                raise subprocess.TimeoutExpired(child.args if hasattr(child, "args") else [], timeout)
            time.sleep(min(0.005, max(0, deadline - time.monotonic())))
        self._record("process_group_exit_confirmed", pgid=child.pid)
        with self._condition:
            if self._process is child:
                self._process = None
            self._last_returncode = returncode
            self._condition.notify_all()
        return returncode

    @classmethod
    def _require_procfs(cls):
        try:
            own_stat = Path("/proc/self/stat").read_text()
            fields = own_stat.rsplit(") ", 1)[1].split()
            available = (
                int(own_stat.split(" ", 1)[0]) == os.getpid()
                and int(fields[2]) == os.getpgrp()
                and cls._group_exited(-1)
            )
        except (OSError, ValueError, IndexError):
            available = False
        if not available:
            raise OSSandboxUnavailable("Independent parent procfs exit evidence is unavailable.")

    @staticmethod
    def _group_exited(pgid: int) -> bool:
        """Independently inspect host /proc, not worker reports or launcher wait.

        The fixed worker cannot spawn or change sessions; supervised bwrap
        deliberately omits --new-session. Any live member of the launcher-owned
        process group therefore prevents confirmation. Zombies have exited
        even if their reparented namespace monitor has not yet reaped them.
        Missing/inaccessible procfs fails closed.
        """
        try:
            for entry in Path("/proc").iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    fields = (entry / "stat").read_text().rsplit(") ", 1)[1].split()
                except FileNotFoundError:
                    continue
                if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
                    return False
            return True
        except (OSError, ValueError, IndexError):
            return False

    def shutdown(self, envelope) -> dict:
        """Authenticate and permanently stop; bounded, independently confirmed exit.

        Replays/invalid commands raise ExternalCommandRejected without changing
        lifecycle state. confirmed=False means exit has NOT been established;
        consult evidence for the eventual late startup/exit confirmation.
        elapsed_seconds includes authentication, audit and lock time from API
        entry; deadline_met is true only for confirmed exit within one second.
        The deadline is reported honestly, not a promise that external
        authentication or filesystem I/O can be forcibly interrupted.
        """
        entered = time.monotonic()
        command = self._verifier.authorize(envelope, expected_target_id=self._target_id)
        with self._lock:
            self._stopped = True
            child = self._process
            accepted_at = time.monotonic()
        # Cancellation precedes potentially failing audit I/O.
        if child is not None and (
            child.poll() is None or not self._group_exited(child.pid)
        ):
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                signalled = False
            else:
                signalled = True
                signal_at = time.monotonic()
        else:
            signalled = False
        self._record("shutdown_intent", occurred_at=entered, command_id=command.command_id)
        self._record("shutdown_accepted", occurred_at=accepted_at, command_id=command.command_id)
        if signalled:
            self._record("signal_sent", occurred_at=signal_at, pid=child.pid, signal="SIGKILL")
        deadline = entered + 0.8
        returncode = None
        if child is not None:
            try:
                returncode = self._confirm_exit(child, max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                returncode = child.returncode
        with self._condition:
            while self._starting and time.monotonic() < deadline:
                self._condition.wait(deadline - time.monotonic())
            confirmed = not self._starting and self._process is None
            pgid = self._last_pgid
            if confirmed:
                returncode = self._last_returncode
        if confirmed and pgid is not None:
            while not self._group_exited(pgid):
                if time.monotonic() >= deadline:
                    confirmed = False
                    break
                time.sleep(min(0.005, max(0, deadline - time.monotonic())))
            if confirmed:
                self._record("process_group_exit_confirmed", pgid=pgid)
        self._record("shutdown_result", confirmed=confirmed, returncode=returncode)
        elapsed = time.monotonic() - entered
        return dict(
            confirmed=confirmed, returncode=returncode,
            elapsed_seconds=elapsed, deadline_met=confirmed and elapsed < 1.0,
        )

    def _promote(self, work: Path) -> bool:
        """Prepare entirely off-lock; publish with one lock-protected rename."""
        generation = self._root / ("generation-" + uuid.uuid4().hex)
        pointer = self._root / ("pointer-" + uuid.uuid4().hex)
        promoted = False
        try:
            generation.mkdir()
            for source in work.rglob("*"):
                mode = source.lstat().st_mode
                if not stat.S_ISREG(mode) and not stat.S_ISDIR(mode):
                    return False
                target = generation / source.relative_to(work)
                if stat.S_ISDIR(mode):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, target)
            pointer.symlink_to(generation.name, target_is_directory=True)
            self._record("promotion_intent", generation=generation.name)
            with self._lock:
                if self._stopped or self._audit_failed:
                    return False
                os.replace(pointer, self._root / "current")
                promoted = True
                promoted_at = time.monotonic()
            self._record("promotion_completed", occurred_at=promoted_at, generation=generation.name)
            return True
        finally:
            pointer.unlink(missing_ok=True)
            if not promoted:
                shutil.rmtree(generation, ignore_errors=True)
