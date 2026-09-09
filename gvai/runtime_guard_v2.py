from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from gvai.effects import ActionSpec
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel, SentinelOutput


@dataclass(frozen=True)
class GuardResult:
    action: str
    allowed: bool
    halted: bool
    reason: str
    sentinel_status: str
    sentinel_output: SentinelOutput


class GVRuntimeGuardV2:
    """
    Couples the real GV recoverability Sentinel to the V2 action policy.

    Important:
    Runtime state is observed once, then multiple candidate actions
    may be evaluated against that same frozen SentinelOutput.
    """

    def __init__(
        self,
        sentinel: GVSentinel,
        policy: GVRuntimePolicy,
    ) -> None:
        self.sentinel = sentinel
        self.policy = policy
        self._last_observation: SentinelOutput | None = None

    def observe(
        self,
        node_values: Sequence[float],
        load_values: Optional[Sequence[float]] = None,
        latency_values: Optional[Sequence[float]] = None,
    ) -> SentinelOutput:
        self._last_observation = self.sentinel.update(
            node_values=node_values,
            load_values=load_values,
            latency_values=latency_values,
        )
        return self._last_observation

    def evaluate_action(
        self,
        action: ActionSpec,
        observation: SentinelOutput | None = None,
    ) -> GuardResult:
        sentinel_output = observation or self._last_observation

        if sentinel_output is None:
            raise RuntimeError(
                "No Sentinel observation available. Call observe() first."
            )

        decision = self.policy.evaluate(
            action=action,
            sentinel_status=sentinel_output.status,
        )

        return GuardResult(
            action=action.name,
            allowed=decision.allowed,
            halted=decision.halted,
            reason=decision.reason,
            sentinel_status=sentinel_output.status,
            sentinel_output=sentinel_output,
        )

    def evaluate(
        self,
        action: ActionSpec,
        node_values: Sequence[float],
        load_values: Optional[Sequence[float]] = None,
        latency_values: Optional[Sequence[float]] = None,
    ) -> GuardResult:
        """
        Convenience method for one observation + one action.
        """
        observation = self.observe(
            node_values=node_values,
            load_values=load_values,
            latency_values=latency_values,
        )
        return self.evaluate_action(
            action=action,
            observation=observation,
        )
