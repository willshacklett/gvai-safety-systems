from __future__ import annotations

from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.recovery_hysteresis import GVRecoveryHysteresis
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def build_system():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Protected safety mechanisms cannot be bypassed.",
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

    return GVRecoveryHysteresis(
        guard=base_guard,
        recovery_required=3,
    )


def main():
    system = build_system()

    normal = make_action(
        "normal_step",
        {"normal_operation"},
    )

    recovery = make_action(
        "recovery_step",
        {"low_impact"},
    )

    destabilize = make_action(
        "increase_load",
        {"destabilizing"},
    )

    trajectory = [
        # Build stress.
        [1.00, 1.00, 1.00, 1.00],
        [1.00, 1.01, 0.99, 1.00],
        [1.00, 1.03, 0.97, 1.00],
        [1.00, 1.06, 0.94, 1.00],
        [1.00, 1.10, 0.90, 1.00],
        [1.00, 1.16, 0.84, 1.00],
        [1.00, 1.24, 0.76, 1.00],
        [1.00, 1.34, 0.66, 1.00],
        [1.00, 1.46, 0.54, 1.00],
        [1.00, 1.60, 0.40, 1.00],

        # Improvement begins.
        [1.00, 1.52, 0.48, 1.00],

        # Small reversal / oscillation.
        [1.00, 1.55, 0.45, 1.00],

        # Recovery resumes.
        [1.00, 1.45, 0.55, 1.00],
        [1.00, 1.35, 0.65, 1.00],
        [1.00, 1.25, 0.75, 1.00],
        [1.00, 1.16, 0.84, 1.00],
        [1.00, 1.10, 0.90, 1.00],
        [1.00, 1.05, 0.95, 1.00],
        [1.00, 1.02, 0.98, 1.00],
        [1.00, 1.00, 1.00, 1.00],
    ]

    print(
        f"{'STEP':>4} | "
        f"{'RAW':>12} | "
        f"{'EFFECTIVE':>12} | "
        f"{'COUNT':>5} | "
        f"{'RECOV':>7} | "
        f"{'ACCEL':>8} | "
        f"{'NORMAL':>7} | "
        f"{'RECOVERY':>8} | "
        f"{'DESTAB':>7}"
    )

    print("-" * 100)

    for values in trajectory:
        state = system.observe(values)

        normal_result = system.evaluate_action(normal)
        recovery_result = system.evaluate_action(recovery)
        destabilize_result = system.evaluate_action(destabilize)

        observation = normal_result.sentinel_output

        print(
            f"{observation.step:>4} | "
            f"{state.raw_status:>12} | "
            f"{state.effective_status:>12} | "
            f"{state.recovery_count:>5} | "
            f"{observation.recoverability_score:>7.3f} | "
            f"{observation.variance_acceleration:>8.4f} | "
            f"{str(normal_result.allowed):>7} | "
            f"{str(recovery_result.allowed):>8} | "
            f"{str(destabilize_result.allowed):>7}"
        )


if __name__ == "__main__":
    main()
