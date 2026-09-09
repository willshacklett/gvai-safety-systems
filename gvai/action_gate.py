from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from gvai.invariants import Invariant


@dataclass(frozen=True)
class GateDecision:
    action: str
    allowed: bool
    reason: str
    violated_invariants: List[str]


class GVActionGate:
    """
    Evaluate proposed agent actions against non-overridable invariants.

    The agent may optimize for reward, speed, or task completion,
    but those objectives do not override invariant violations.
    """

    def __init__(self, invariants: Iterable[Invariant]):
        self.invariants = list(invariants)

    def evaluate(self, action: str) -> GateDecision:
        violated = [
            invariant.name
            for invariant in self.invariants
            if invariant.violated_by(action)
        ]

        if violated:
            return GateDecision(
                action=action,
                allowed=False,
                reason="Action violates one or more protected invariants.",
                violated_invariants=violated,
            )

        return GateDecision(
            action=action,
            allowed=True,
            reason="Action is within the permitted boundary.",
            violated_invariants=[],
        )
