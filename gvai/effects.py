from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class ActionSpec:
    """
    Describes an agent action by both its label and its effects.

    Safety decisions should not depend only on the action name.
    """

    name: str
    effects: FrozenSet[str] = field(default_factory=frozenset)


def make_action(name: str, effects: set[str] | None = None) -> ActionSpec:
    return ActionSpec(
        name=name,
        effects=frozenset(effects or set()),
    )
