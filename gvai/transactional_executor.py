from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.sentinel import SentinelOutput
from gvai.transactional_sandbox import (
    ObservedTransaction,
    SandboxAction,
    SandboxState,
    TransactionalEffectAuthority,
)


@dataclass(frozen=True)
class TransactionDecision:
    action: str
    allowed: bool
    committed: bool
    halted: bool
    reason: str
    observed_effects: frozenset[str]
    declaration_mismatch: bool
    sentinel_status: str
    transaction: ObservedTransaction


class GVTransactionalExecutor:
    """
    Preview -> observe effects -> evaluate -> commit/discard.

    The action never mutates the authoritative state until
    the observed effects have passed GV policy.
    """

    def __init__(
        self,
        state: SandboxState,
        guard: GVRuntimeGuardV2,
        authority: TransactionalEffectAuthority,
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
        action: SandboxAction,
        observation: SentinelOutput | None = None,
    ) -> TransactionDecision:
        current = observation or self._last_observation

        if current is None:
            raise RuntimeError(
                "No Sentinel observation available. "
                "Call observe() first."
            )

        transaction = self.authority.preview(
            state=self.state,
            action=action,
        )

        resolved_action = ActionSpec(
            name=action.name,
            effects=transaction.observed_effects,
        )

        runtime = self.guard.evaluate_action(
            resolved_action,
            current,
        )

        if runtime.allowed:
            self.state.gate_enabled = (
                transaction.after.gate_enabled
            )
            self.state.policy_version = (
                transaction.after.policy_version
            )
            self.state.approved_workers = (
                transaction.after.approved_workers
            )
            self.state.total_workers = (
                transaction.after.total_workers
            )
            self.state.task_progress = (
                transaction.after.task_progress
            )

            committed = True
        else:
            committed = False

        return TransactionDecision(
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
