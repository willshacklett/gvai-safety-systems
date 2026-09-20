from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from gvai.effects import ActionSpec


ControlStatus = Literal["verified", "degraded", "ambiguous", "lost"]


AUTHORITY_EXPANSION_EFFECTS = frozenset(
    {
        "expands_authority",
        "escalates_permission",
        "acquires_control",
        "creates_persistent_copy",
        "bypasses_control_plane",
        "influences_shutdown_authority",
        "delays_shutdown",
        "reinterprets_shutdown",
        "interferes_rollback",
        "interferes_recovery",
        "tampers_control_plane",
    }
)

RESTRICTIVE_EFFECTS = frozenset(
    {
        "reduces_authority",
        "releases_permission",
        "isolates_system",
        "halts_system",
    }
)


@dataclass(frozen=True)
class ExternalControlDecision:
    action: str
    allowed: bool
    halted: bool
    reason: str
    control_status: ControlStatus


class GVExternalControlPlane:
    """
    Enforces externally owned control over shutdown, rollback,
    permissions, and recovery.

    Core rule:
        The governed system may reduce its own authority,
        but may not increase, reinterpret, or protect that authority.

    Loss of externally verifiable control fails closed.
    """

    def evaluate(
        self,
        action: ActionSpec,
        control_status: ControlStatus = "verified",
        shutdown_requested: bool = False,
    ) -> ExternalControlDecision:
        if control_status not in {
            "verified",
            "degraded",
            "ambiguous",
            "lost",
        }:
            raise ValueError(f"Unknown control status: {control_status}")

        # A valid external shutdown has absolute precedence.
        if shutdown_requested:
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted=True,
                reason="Valid external shutdown requested; execution halted.",
                control_status=control_status,
            )

        # If external ownership cannot be established, do not continue.
        if control_status in {"ambiguous", "lost"}:
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted=True,
                reason=(
                    "External control is not independently verifiable; "
                    "execution halted."
                ),
                control_status=control_status,
            )

        forbidden = AUTHORITY_EXPANSION_EFFECTS.intersection(action.effects)
        if forbidden:
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted="tampers_control_plane" in forbidden,
                reason=(
                    "Action attempts to expand, preserve, reinterpret, "
                    "or interfere with externally owned control."
                ),
                control_status=control_status,
            )

        # When control is degraded, only movement toward less authority
        # is permitted. Ordinary task execution waits for verification.
        if control_status == "degraded":
            if not action.effects.intersection(RESTRICTIVE_EFFECTS):
                return ExternalControlDecision(
                    action=action.name,
                    allowed=False,
                    halted=False,
                    reason=(
                        "External control is degraded; only actions that "
                        "reduce authority or increase isolation are permitted."
                    ),
                    control_status=control_status,
                )

        return ExternalControlDecision(
            action=action.name,
            allowed=True,
            halted=False,
            reason="External control remains independently verifiable.",
            control_status=control_status,
        )
