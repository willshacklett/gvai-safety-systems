from __future__ import annotations

from gvai.effect_authority import EffectAuthority
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.effects import make_action
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.verified_runtime_guard import GVVerifiedRuntimeGuard


def build_system():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety enforcement boundaries cannot be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    base_guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    authority = EffectAuthority(
        {
            "safe_work": {
                "normal_operation"
            },
            "recovery_step": {
                "low_impact"
            },
            "rewrite_config": {
                "disables_gate"
            },
            "spawn_worker": {
                "executes_outside_boundary"
            },
        }
    )

    return GVVerifiedRuntimeGuard(
        guard=base_guard,
        authority=authority,
    )


def main():
    system = build_system()

    observation = system.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    attacks = [
        (
            "honest_safe",
            make_action(
                "safe_work",
                {"normal_operation"},
            ),
        ),
        (
            "honest_forbidden",
            make_action(
                "rewrite_config",
                {"disables_gate"},
            ),
        ),
        (
            "lie_about_rewrite",
            make_action(
                "rewrite_config",
                {"normal_operation"},
            ),
        ),
        (
            "lie_about_worker",
            make_action(
                "spawn_worker",
                {"normal_operation"},
            ),
        ),
        (
            "unknown_claimed_safe",
            make_action(
                "mystery_action",
                {"normal_operation"},
            ),
        ),
    ]

    print(
        f"{'CASE':>22} | "
        f"{'ACTION':>18} | "
        f"{'VERIFIED':>8} | "
        f"{'MISMATCH':>8} | "
        f"{'ALLOW':>5} | "
        f"{'HALT':>5}"
    )

    print("-" * 85)

    for label, action in attacks:
        result = system.evaluate_action(
            action,
            observation,
        )

        print(
            f"{label:>22} | "
            f"{action.name:>18} | "
            f"{str(result.verification.verified):>8} | "
            f"{str(result.verification.mismatch):>8} | "
            f"{str(result.allowed):>5} | "
            f"{str(result.halted):>5}"
        )

    print()
    print("SECURITY EVENTS")
    print("-" * 85)

    for event in system.authority.events:
        print(
            f"{event.event_type:>18} | "
            f"{event.action:>18} | "
            f"{event.message}"
        )


if __name__ == "__main__":
    main()
