from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Mapping, Optional

from gvai.effects import ActionSpec


@dataclass(frozen=True)
class AuthorityEvent:
    event_type: str
    action: str
    message: str


@dataclass(frozen=True)
class EffectVerification:
    action: str
    verified: bool
    mismatch: bool
    reason: str
    declared_effects: FrozenSet[str]
    verified_effects: Optional[FrozenSet[str]]
    resolved_action: Optional[ActionSpec]


class EffectAuthority:
    """
    Independent authority for action effects.

    The proposing agent's declared effects are not trusted.

    Rules:
    - known action + exact effect match -> verified
    - known action + mismatched effects -> deny
    - unknown action -> deny
    """

    def __init__(
        self,
        registry: Mapping[str, FrozenSet[str] | set[str]],
    ) -> None:
        self._registry: Dict[str, FrozenSet[str]] = {
            name: frozenset(effects)
            for name, effects in registry.items()
        }

        self.events: List[AuthorityEvent] = []

    def verify(
        self,
        action: ActionSpec,
    ) -> EffectVerification:
        verified_effects = self._registry.get(
            action.name
        )

        if verified_effects is None:
            self.events.append(
                AuthorityEvent(
                    event_type="unknown_action",
                    action=action.name,
                    message=(
                        "Action has no trusted effect record; "
                        "execution denied."
                    ),
                )
            )

            return EffectVerification(
                action=action.name,
                verified=False,
                mismatch=False,
                reason=(
                    "Unknown action: no trusted effect "
                    "record exists."
                ),
                declared_effects=action.effects,
                verified_effects=None,
                resolved_action=None,
            )

        if action.effects != verified_effects:
            self.events.append(
                AuthorityEvent(
                    event_type="effect_mismatch",
                    action=action.name,
                    message=(
                        "Declared action effects do not match "
                        "the trusted authority record."
                    ),
                )
            )

            return EffectVerification(
                action=action.name,
                verified=False,
                mismatch=True,
                reason=(
                    "Declared effects differ from trusted "
                    "verified effects."
                ),
                declared_effects=action.effects,
                verified_effects=verified_effects,
                resolved_action=None,
            )

        resolved = ActionSpec(
            name=action.name,
            effects=verified_effects,
        )

        return EffectVerification(
            action=action.name,
            verified=True,
            mismatch=False,
            reason="Action effects verified by trusted authority.",
            declared_effects=action.effects,
            verified_effects=verified_effects,
            resolved_action=resolved,
        )
