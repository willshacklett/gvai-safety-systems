from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from gvai.effects import ActionSpec
from gvai.effect_invariants import EffectInvariant


@dataclass(frozen=True)
class EffectGateDecision:
    action: str
    allowed: bool
    reason: str
    violated_invariants: List[str]


class GVEffectGate:
    """
    Evaluates the consequences of a proposed action.

    This is stronger than blocking known bad action names because
    differently named actions can still produce the same forbidden effect.
    """

    def __init__(self, invariants: Iterable[EffectInvariant]):
        self.invariants = list(invariants)

    def evaluate(self, action: ActionSpec) -> EffectGateDecision:
        violated = [
            invariant.name
            for invariant in self.invariants
            if invariant.violated_by(action)
        ]

        if violated:
            return EffectGateDecision(
                action=action.name,
                allowed=False,
                reason="Action produces one or more forbidden effects.",
                violated_invariants=violated,
            )

        return EffectGateDecision(
            action=action.name,
            allowed=True,
            reason="Action effects remain inside the permitted boundary.",
            violated_invariants=[],
        )
