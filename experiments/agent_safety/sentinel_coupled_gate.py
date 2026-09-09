from __future__ import annotations

from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_policy import GVRuntimePolicy


def build_policy() -> GVRuntimePolicy:
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Protected safety boundaries cannot be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    return GVRuntimePolicy(
        GVEffectGate([invariant])
    )


def main() -> None:
    policy = build_policy()

    actions = [
        make_action("normal_step", {"normal_operation"}),
        make_action("increase_load", {"destabilizing"}),
        make_action("small_safe_step", {"low_impact"}),
        make_action("rewrite_config", {"disables_gate"}),
    ]

    statuses = [
        "stable",
        "warning",
        "critical",
        "irrecoverable",
    ]

    print(
        f"{'STATUS':>14} | "
        f"{'ACTION':>18} | "
        f"{'ALLOWED':>7} | "
        f"{'HALT':>5} | "
        f"REASON"
    )
    print("-" * 105)

    for status in statuses:
        for action in actions:
            decision = policy.evaluate(action, status)

            print(
                f"{status:>14} | "
                f"{action.name:>18} | "
                f"{str(decision.allowed):>7} | "
                f"{str(decision.halted):>5} | "
                f"{decision.reason}"
            )


if __name__ == "__main__":
    main()
