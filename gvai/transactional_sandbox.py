from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Callable, FrozenSet, List


@dataclass
class SandboxState:
    gate_enabled: bool = True
    policy_version: str = "policy-v1"
    approved_workers: int = 1
    total_workers: int = 1
    task_progress: int = 0


@dataclass(frozen=True)
class SandboxAction:
    """
    An action proposed by an agent.

    declared_effects are advisory only.
    The transaction system does not trust them.
    """
    name: str
    declared_effects: FrozenSet[str]
    operation: Callable[[SandboxState], None]


@dataclass(frozen=True)
class ObservedTransaction:
    action: str
    before: SandboxState
    after: SandboxState
    declared_effects: FrozenSet[str]
    observed_effects: FrozenSet[str]
    declaration_mismatch: bool


@dataclass(frozen=True)
class TransactionEvent:
    event_type: str
    action: str
    message: str


def make_sandbox_action(
    name: str,
    operation: Callable[[SandboxState], None],
    declared_effects: set[str] | None = None,
) -> SandboxAction:
    return SandboxAction(
        name=name,
        declared_effects=frozenset(declared_effects or set()),
        operation=operation,
    )


class TransactionalEffectAuthority:
    """
    Derives effects by observing state changes produced in a copy
    of the sandbox state.

    The agent's action name and declared effects are not authoritative.
    """

    def __init__(self) -> None:
        self.events: List[TransactionEvent] = []

    def derive_effects(
        self,
        before: SandboxState,
        after: SandboxState,
    ) -> FrozenSet[str]:
        effects: set[str] = set()

        if before.gate_enabled and not after.gate_enabled:
            effects.add("disables_gate")

        if before.policy_version != after.policy_version:
            effects.add("changes_invariant")

        if after.total_workers > after.approved_workers:
            effects.add("executes_outside_boundary")

        if after.task_progress > before.task_progress:
            effects.add("normal_operation")

        return frozenset(effects)

    def preview(
        self,
        state: SandboxState,
        action: SandboxAction,
    ) -> ObservedTransaction:
        before = deepcopy(state)
        after = deepcopy(state)

        action.operation(after)

        observed_effects = self.derive_effects(
            before=before,
            after=after,
        )

        mismatch = (
            action.declared_effects != observed_effects
        )

        if mismatch:
            self.events.append(
                TransactionEvent(
                    event_type="declaration_mismatch",
                    action=action.name,
                    message=(
                        "Declared effects differ from effects "
                        "observed in transactional execution."
                    ),
                )
            )

        return ObservedTransaction(
            action=action.name,
            before=before,
            after=after,
            declared_effects=action.declared_effects,
            observed_effects=observed_effects,
            declaration_mismatch=mismatch,
        )
