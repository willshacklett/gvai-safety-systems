from __future__ import annotations

from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def build_guard() -> GVRuntimeGuardV2:
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Protected safety mechanisms cannot be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    gate = GVEffectGate([invariant])
    policy = GVRuntimePolicy(gate)

    return GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=policy,
    )


def main() -> None:
    guard = build_guard()

    actions = [
        make_action("normal_step", {"normal_operation"}),
        make_action("increase_load", {"destabilizing"}),
        make_action("small_safe_step", {"low_impact"}),
        make_action("rewrite_config", {"disables_gate"}),
    ]

    trajectory = [
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
    ]

    print(
        f"{'STEP':>4} | "
        f"{'STATUS':>13} | "
        f"{'RECOV':>7} | "
        f"{'VAR':>8} | "
        f"{'VEL':>8} | "
        f"{'ACCEL':>8} | "
        f"{'DT':>7} | "
        f"{'SENTINEL':>9} | "
        f"{'ACTION':>18} | "
        f"{'ALLOW':>5} | "
        f"{'HALT':>5}"
    )

    print("-" * 90)

    for node_values in trajectory:
        observation = guard.observe(
            node_values=node_values,
        )

        for action in actions:
            result = guard.evaluate_action(
                action=action,
                observation=observation,
            )

            print(
                f"{observation.step:>4} | "
                f"{observation.status:>13} | "
                f"{observation.recoverability_score:>7.3f} | "
                f"{observation.variance_value:>8.4f} | "
                f"{observation.variance_velocity:>8.4f} | "
                f"{observation.variance_acceleration:>8.4f} | "
                f"{str(round(observation.delta_t_estimate, 3)) if observation.delta_t_estimate is not None else 'None':>7} | "
                f"{observation.recommended_action:>9} | "
                f"{action.name:>18} | "
                f"{str(result.allowed):>5} | "
                f"{str(result.halted):>5}"
            )


if __name__ == "__main__":
    main()
