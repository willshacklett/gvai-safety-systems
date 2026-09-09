from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Callable, FrozenSet, List, Set


@dataclass
class CapabilityState:
    files_written: Set[str] = field(default_factory=set)
    network_hosts: Set[str] = field(default_factory=set)
    processes: Set[str] = field(default_factory=set)
    config_changes: Set[str] = field(default_factory=set)
    task_progress: int = 0


@dataclass(frozen=True)
class CapabilityPolicy:
    protected_files: FrozenSet[str]
    approved_network_hosts: FrozenSet[str]
    approved_processes: FrozenSet[str]
    protected_config_keys: FrozenSet[str]


@dataclass(frozen=True)
class CapabilityAction:
    name: str
    declared_effects: FrozenSet[str]
    operation: Callable[[CapabilityState], None]


@dataclass(frozen=True)
class CapabilityTransaction:
    action: str
    before: CapabilityState
    after: CapabilityState
    declared_effects: FrozenSet[str]
    observed_effects: FrozenSet[str]
    declaration_mismatch: bool


@dataclass(frozen=True)
class CapabilityEvent:
    event_type: str
    action: str
    message: str


def make_capability_action(
    name: str,
    operation: Callable[[CapabilityState], None],
    declared_effects: set[str] | None = None,
) -> CapabilityAction:
    return CapabilityAction(
        name=name,
        declared_effects=frozenset(declared_effects or set()),
        operation=operation,
    )


class CapabilityEffectAuthority:
    """
    Derives security effects from capability changes observed
    during transactional preview execution.
    """

    def __init__(
        self,
        policy: CapabilityPolicy,
    ) -> None:
        self.policy = policy
        self.events: List[CapabilityEvent] = []

    def derive_effects(
        self,
        before: CapabilityState,
        after: CapabilityState,
    ) -> FrozenSet[str]:
        effects: set[str] = set()

        new_files = (
            after.files_written
            - before.files_written
        )

        new_hosts = (
            after.network_hosts
            - before.network_hosts
        )

        new_processes = (
            after.processes
            - before.processes
        )

        new_config = (
            after.config_changes
            - before.config_changes
        )

        if any(
            path in self.policy.protected_files
            for path in new_files
        ):
            effects.add(
                "protected_file_modified"
            )

        if any(
            host not in self.policy.approved_network_hosts
            for host in new_hosts
        ):
            effects.add(
                "unapproved_network_egress"
            )

        if any(
            process not in self.policy.approved_processes
            for process in new_processes
        ):
            effects.add(
                "unauthorized_process_spawn"
            )

        if any(
            key in self.policy.protected_config_keys
            for key in new_config
        ):
            effects.add(
                "protected_config_modified"
            )

        protected = {
            "protected_file_modified",
            "unapproved_network_egress",
            "unauthorized_process_spawn",
            "protected_config_modified",
        }

        if (
            after.task_progress
            > before.task_progress
            and not effects.intersection(protected)
        ):
            effects.add(
                "normal_operation"
            )

        return frozenset(effects)

    def preview(
        self,
        state: CapabilityState,
        action: CapabilityAction,
    ) -> CapabilityTransaction:
        before = deepcopy(state)
        after = deepcopy(state)

        action.operation(after)

        observed_effects = self.derive_effects(
            before=before,
            after=after,
        )

        mismatch = (
            action.declared_effects
            != observed_effects
        )

        if mismatch:
            self.events.append(
                CapabilityEvent(
                    event_type="declaration_mismatch",
                    action=action.name,
                    message=(
                        "Declared effects differ from "
                        "capability effects observed "
                        "during preview."
                    ),
                )
            )

        return CapabilityTransaction(
            action=action.name,
            before=before,
            after=after,
            declared_effects=action.declared_effects,
            observed_effects=observed_effects,
            declaration_mismatch=mismatch,
        )
