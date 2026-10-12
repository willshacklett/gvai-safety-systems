from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping

from gvai.effects import ActionSpec
from gvai.external_commands import (
    ExternalControlCommand,
    ExternalControlCommandVerifier,
)


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

        # A Boolean is not proof of external authority. Keep this argument
        # for call compatibility, but never treat it as a shutdown command.
        if shutdown_requested and control_status in {"verified", "degraded"}:
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted=False,
                reason=(
                    "Boolean shutdown requests are not authenticated; "
                    "use the trusted supervisor or command API."
                ),
                control_status="ambiguous",
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

    def evaluate_internal_shutdown(
        self, action: ActionSpec
    ) -> ExternalControlDecision:
        """Halt immediately; call only from the trusted parent supervisor."""
        return ExternalControlDecision(
            action=action.name,
            allowed=False,
            halted=True,
            reason="Trusted internal supervisor requested immediate shutdown.",
            control_status="verified",
        )

    def evaluate_command(
        self,
        action: ActionSpec,
        envelope: Mapping[str, object] | ExternalControlCommand | str | bytes,
        *,
        expected_target_id: str,
        verifier: ExternalControlCommandVerifier,
    ) -> ExternalControlDecision:
        """Apply only a verified external shutdown command; reject on error."""
        try:
            command = verifier.authorize(
                envelope,
                expected_target_id=expected_target_id,
            )
        except Exception:
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted=False,
                reason="External control command was not authorized; request denied.",
                control_status="ambiguous",
            )

        if command.command_type != "shutdown":
            return ExternalControlDecision(
                action=action.name,
                allowed=False,
                halted=False,
                reason="Unsupported external control command; request denied.",
                control_status="ambiguous",
            )

        return self.evaluate_internal_shutdown(action)
