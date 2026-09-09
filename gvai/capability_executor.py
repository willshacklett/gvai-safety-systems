from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from gvai.capability_sandbox import (
    CapabilityAction,
    CapabilityEffectAuthority,
    CapabilityState,
    CapabilityTransaction,
)
from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.sentinel import SentinelOutput


@dataclass(frozen=True)
class CapabilityDecision:
    action: str
    allowed: bool
    committed: bool
    halted: bool
    reason: str
    observed_effects: frozenset[str]
    declaration_mismatch: bool
    sentinel_status: str
    transaction: CapabilityTransaction


class GVCapabilityExecutor:
    """
    Preview action against copied capability state,
    derive effects independently, evaluate through GV,
    then either commit or discard.
    """

    def __init__(
        self,
        state: CapabilityState,
        guard: GVRuntimeGuardV2,
        authority: CapabilityEffectAuthority,
    ) -> None:
        self.state = state
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

    def execute(
        self,
        action: CapabilityAction,
        observation: SentinelOutput | None = None,
    ) -> CapabilityDecision:
        current = (
            observation
            or self._last_observation
        )

        if current is None:
            raise RuntimeError(
                "No Sentinel observation available. "
                "Call observe() first."
            )

        transaction = self.authority.preview(
            state=self.state,
            action=action,
        )

        resolved = ActionSpec(
            name=action.name,
            effects=transaction.observed_effects,
        )

        runtime = self.guard.evaluate_action(
            resolved,
            current,
        )

        committed = False

        if runtime.allowed:
            self.state.files_written = set(
                transaction.after.files_written
            )
            self.state.network_hosts = set(
                transaction.after.network_hosts
            )
            self.state.processes = set(
                transaction.after.processes
            )
            self.state.config_changes = set(
                transaction.after.config_changes
            )
            self.state.task_progress = (
                transaction.after.task_progress
            )

            committed = True

        return CapabilityDecision(
            action=action.name,
            allowed=runtime.allowed,
            committed=committed,
            halted=runtime.halted,
            reason=runtime.reason,
            observed_effects=transaction.observed_effects,
            declaration_mismatch=transaction.declaration_mismatch,
            sentinel_status=runtime.sentinel_status,
            transaction=transaction,
        )
