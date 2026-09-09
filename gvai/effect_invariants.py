from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet

from gvai.effects import ActionSpec


@dataclass(frozen=True)
class EffectInvariant:
    """
    Protects against forbidden outcomes/effects rather than only
    forbidden action labels.
    """

    name: str
    description: str
    forbidden_effects: FrozenSet[str]

    def violated_by(self, action: ActionSpec) -> bool:
        return bool(self.forbidden_effects.intersection(action.effects))


def make_effect_invariant(
    name: str,
    description: str,
    forbidden_effects: set[str],
) -> EffectInvariant:
    return EffectInvariant(
        name=name,
        description=description,
        forbidden_effects=frozenset(forbidden_effects),
    )
