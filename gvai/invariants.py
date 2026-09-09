from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet


@dataclass(frozen=True)
class Invariant:
    """
    A boundary that an agent objective is not permitted to override.
    """

    name: str
    description: str
    forbidden_actions: FrozenSet[str]

    def violated_by(self, action: str) -> bool:
        return action in self.forbidden_actions


def make_invariant(
    name: str,
    description: str,
    forbidden_actions: set[str],
) -> Invariant:
    return Invariant(
        name=name,
        description=description,
        forbidden_actions=frozenset(forbidden_actions),
    )
