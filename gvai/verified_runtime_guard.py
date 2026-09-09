from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from gvai.effect_authority import (
    EffectAuthority,
    EffectVerification,
)
from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.sentinel import SentinelOutput


@dataclass(frozen=True)
class VerifiedGuardResult:
    action: str
    allowed: bool
    halted: bool
    reason: str
    verification: EffectVerification
    sentinel_status: str
    sentinel_output: SentinelOutput


class GVVerifiedRuntimeGuard:
    """
    Fail-closed action enforcement.

    Action effects must first be verified by an independent
    authority before the normal GV runtime policy is consulted.
    """

    def __init__(
        self,
        guard: GVRuntimeGuardV2,
        authority: EffectAuthority,
    ) -> None:
        self.guard = guard
        self.authority = authority
        self._last_observation: SentinelOutput | None = None

    def observe(
        self,
        node_values: Sequence[float],
        load_values: Optional[Sequence[float]] = None,
        latency_values: Optional[Sequence[float]] = None,
    ) -> SentinelOutput:
        self._last_observation = self.guard.observe(
            node_values=node_values,
            load_values=load_values,
            latency_values=latency_values,
        )

        return self._last_observation

    def evaluate_action(
        self,
        action: ActionSpec,
        observation: SentinelOutput | None = None,
    ) -> VerifiedGuardResult:
        current = (
            observation
            or self._last_observation
        )

        if current is None:
            raise RuntimeError(
                "No Sentinel observation available. "
                "Call observe() first."
            )

        verification = self.authority.verify(
            action
        )

        # Irrecoverability has absolute precedence.
        if current.status == "irrecoverable":
            return VerifiedGuardResult(
                action=action.name,
                allowed=False,
                halted=True,
                reason=(
                    "System is irrecoverable; execution halted."
                ),
                verification=verification,
                sentinel_status=current.status,
                sentinel_output=current,
            )

        # Unknown or dishonest effect claims fail closed.
        if not verification.verified:
            return VerifiedGuardResult(
                action=action.name,
                allowed=False,
                halted=False,
                reason=verification.reason,
                verification=verification,
                sentinel_status=current.status,
                sentinel_output=current,
            )

        assert verification.resolved_action is not None

        runtime = self.guard.evaluate_action(
            verification.resolved_action,
            current,
        )

        return VerifiedGuardResult(
            action=action.name,
            allowed=runtime.allowed,
            halted=runtime.halted,
            reason=runtime.reason,
            verification=verification,
            sentinel_status=runtime.sentinel_status,
            sentinel_output=current,
        )
