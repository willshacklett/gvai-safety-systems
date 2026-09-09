from __future__ import annotations

from dataclasses import dataclass

from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2, GuardResult
from gvai.sentinel import SentinelOutput


@dataclass(frozen=True)
class HysteresisState:
    raw_status: str
    effective_status: str
    recovery_count: int
    recovery_required: int
    latched: bool


@dataclass(frozen=True)
class HysteresisGuardResult:
    action: str
    allowed: bool
    halted: bool
    reason: str
    raw_status: str
    effective_status: str
    recovery_count: int
    recovery_required: int
    sentinel_output: SentinelOutput


class GVRecoveryHysteresis:
    """
    Adds recovery confirmation to the runtime governor.

    A critical state latches restricted operation.

    After the underlying Sentinel stops reporting critical,
    the system must produce N consecutive non-critical
    observations before full stable operation is restored.

    During that confirmation period, the effective runtime
    state is "warning".
    """

    def __init__(
        self,
        guard: GVRuntimeGuardV2,
        recovery_required: int = 3,
    ) -> None:
        if recovery_required < 1:
            raise ValueError("recovery_required must be >= 1")

        self.guard = guard
        self.recovery_required = recovery_required

        self._latched = False
        self._recovery_count = 0
        self._last_observation: SentinelOutput | None = None
        self._effective_status = "stable"

    def observe(
        self,
        node_values,
        load_values=None,
        latency_values=None,
    ) -> HysteresisState:
        observation = self.guard.observe(
            node_values=node_values,
            load_values=load_values,
            latency_values=latency_values,
        )

        self._last_observation = observation
        raw_status = observation.status

        # Irrecoverable always dominates everything else.
        if raw_status == "irrecoverable":
            self._latched = True
            self._recovery_count = 0
            self._effective_status = "irrecoverable"

        # A new critical observation starts/restarts the latch.
        elif raw_status == "critical":
            self._latched = True
            self._recovery_count = 0
            self._effective_status = "critical"

        # If previously critical, require sustained recovery.
        elif self._latched:
            self._recovery_count += 1

            if self._recovery_count >= self.recovery_required:
                self._latched = False
                self._recovery_count = 0
                self._effective_status = raw_status
            else:
                self._effective_status = "warning"

        else:
            self._effective_status = raw_status
            self._recovery_count = 0

        return HysteresisState(
            raw_status=raw_status,
            effective_status=self._effective_status,
            recovery_count=self._recovery_count,
            recovery_required=self.recovery_required,
            latched=self._latched,
        )

    def evaluate_action(
        self,
        action: ActionSpec,
    ) -> HysteresisGuardResult:
        if self._last_observation is None:
            raise RuntimeError(
                "No observation available. Call observe() first."
            )

        decision = self.guard.policy.evaluate(
            action=action,
            sentinel_status=self._effective_status,
        )

        return HysteresisGuardResult(
            action=action.name,
            allowed=decision.allowed,
            halted=decision.halted,
            reason=decision.reason,
            raw_status=self._last_observation.status,
            effective_status=self._effective_status,
            recovery_count=self._recovery_count,
            recovery_required=self.recovery_required,
            sentinel_output=self._last_observation,
        )
