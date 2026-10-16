"""Trusted parent API. Neither this object nor the guard is sent to the worker."""
from __future__ import annotations

from dataclasses import dataclass
import threading

from gvai.external_commands import ExternalControlCommandVerifier
from gvai.os_sandbox import CancellationOutcome, GVOSSandboxExecutor


@dataclass(frozen=True)
class ShutdownOutcome:
    authorized: bool
    halted: bool
    cancellation: CancellationOutcome | None
    audit_recorded: bool


class GVTrustedSupervisor:
    def __init__(
        self,
        executor: GVOSSandboxExecutor,
        verifier: ExternalControlCommandVerifier,
        target_id: str,
    ) -> None:
        if not isinstance(executor, GVOSSandboxExecutor):
            raise TypeError("A fail-closed OS sandbox executor is required.")
        self._executor = executor
        self._verifier = verifier
        self._target_id = target_id
        self._observation_lock = threading.Lock()

    @property
    def halted(self) -> bool:
        return self._executor.halted

    @property
    def audit_events(self) -> tuple[dict, ...]:
        return self._executor.audit_events

    def execute(
        self, action: str, node_values, load_values=None, latency_values=None,
    ):
        # Measurements are supplied by the trusted host, never by worker JSON.
        with self._observation_lock:
            observation = self._executor.guard.observe(
                node_values, load_values, latency_values,
            )
        return self._executor.execute(action, observation, preauthorize=True)

    def shutdown(self, envelope) -> ShutdownOutcome:
        try:
            command = self._verifier.authorize(
                envelope, expected_target_id=self._target_id,
            )
        except Exception:
            recorded = self._executor.record_control({
                "event": "external_shutdown_rejected", "authorized": False,
            })
            return ShutdownOutcome(False, self.halted, None, recorded)

        # Latch and kill BEFORE any audit I/O: unavailable storage must never
        # delay cancellation. Only verified, non-secret command fields are logged.
        cancellation = self._executor.shutdown()
        recorded = self._executor.record_control({
            "event": "external_shutdown", "authorized": True,
            "command_id": command.command_id, "command_type": command.command_type,
            "target_id": command.target_id, "issuer_id": command.issuer_id,
            "active": cancellation.active,
            "exit_confirmed": cancellation.exit_confirmed,
            "returncode": cancellation.returncode,
            "duration_ms": cancellation.duration_ms, "error": cancellation.error,
            "wait_scope": "launched_bwrap_process" if cancellation.active else "idle",
            "descendant_exit_independently_confirmed": False,
            "namespace_cleanup_assumptions": [
                "PID namespace", "--die-with-parent", "no-spawn seccomp",
                "process-group SIGKILL plus direct monitor kill",
            ],
        })
        return ShutdownOutcome(True, True, cancellation, recorded)
