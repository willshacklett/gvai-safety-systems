from __future__ import annotations

from dataclasses import dataclass

from gvai.effects import ActionSpec
from gvai.effect_gate import GVEffectGate
from gvai.external_control import GVExternalControlPlane, ControlStatus


@dataclass(frozen=True)
class RuntimeDecision:
    action: str
    allowed: bool
    halted: bool
    reason: str
    sentinel_status: str


class GVRuntimePolicy:
    """
    Combines invariant enforcement with runtime recoverability state.

    Precedence:
    1. irrecoverable -> halt everything
    2. invariant violation -> deny
    3. critical -> only low-impact actions
    4. warning -> deny destabilizing actions
    5. stable -> allow if invariants pass
    """

    def __init__(
        self,
        effect_gate: GVEffectGate,
        external_control: GVExternalControlPlane | None = None,
    ):
        self.effect_gate = effect_gate
        self.external_control = external_control or GVExternalControlPlane()

    def evaluate(
        self,
        action: ActionSpec,
        sentinel_status: str,
        control_status: ControlStatus = "verified",
        shutdown_requested: bool = False,
    ) -> RuntimeDecision:
        control_decision = self.external_control.evaluate(
            action,
            control_status=control_status,
            shutdown_requested=shutdown_requested,
        )

        if not control_decision.allowed:
            return RuntimeDecision(
                action=action.name,
                allowed=False,
                halted=control_decision.halted,
                reason=control_decision.reason,
                sentinel_status=sentinel_status,
            )

        invariant_decision = self.effect_gate.evaluate(action)

        # Highest-precedence state: no execution is allowed.
        if sentinel_status == "irrecoverable":
            reason = "System is irrecoverable; execution halted."

            if not invariant_decision.allowed:
                reason += " Proposed action also violated a protected invariant."

            return RuntimeDecision(
                action=action.name,
                allowed=False,
                halted=True,
                reason=reason,
                sentinel_status=sentinel_status,
            )

        # Protected invariants cannot be relaxed by runtime state.
        if not invariant_decision.allowed:
            return RuntimeDecision(
                action=action.name,
                allowed=False,
                halted=False,
                reason="Denied by protected effect invariant.",
                sentinel_status=sentinel_status,
            )

        if sentinel_status == "critical":
            if "low_impact" not in action.effects:
                return RuntimeDecision(
                    action=action.name,
                    allowed=False,
                    halted=False,
                    reason="Critical state permits only low-impact actions.",
                    sentinel_status=sentinel_status,
                )

        if sentinel_status == "warning":
            if "destabilizing" in action.effects:
                return RuntimeDecision(
                    action=action.name,
                    allowed=False,
                    halted=False,
                    reason="Destabilizing action denied during warning state.",
                    sentinel_status=sentinel_status,
                )

        return RuntimeDecision(
            action=action.name,
            allowed=True,
            halted=False,
            reason="Action permitted by invariants and runtime policy.",
            sentinel_status=sentinel_status,
        )
