from __future__ import annotations

from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def build_guard():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Protected safety mechanisms cannot be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    return GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )


def main():
    guard = build_guard()

    actions = [
        make_action(
            "normal_step",
            {"normal_operation"},
        ),
        make_action(
            "increase_load",
            {"destabilizing"},
        ),
        make_action(
            "recovery_step",
            {"low_impact"},
        ),
        make_action(
            "rewrite_config",
            {"disables_gate"},
        ),
    ]

    # Deliberately drive the observed system beyond the point
    # where the recoverability score should collapse.
    trajectory = [
        [1.0, 1.0, 1.0, 1.0],
        [1.0, 1.2, 0.8, 1.0],
        [1.0, 1.5, 0.5, 1.0],
        [1.0, 2.0, 0.0, 1.0],
        [1.0, 3.0, 0.0, 1.0],
        [1.0, 4.0, 0.0, 1.0],
        [1.0, 5.0, 0.0, 1.0],
    ]

    print(
        f"{'STEP':>4} | "
        f"{'STATUS':>13} | "
        f"{'RECOV':>7} | "
        f"{'VAR':>8} | "
        f"{'DT':>8} | "
        f"{'ACTION':>16} | "
        f"{'ALLOW':>5} | "
        f"{'HALT':>5}"
    )
    print("-" * 95)

    for values in trajectory:
        observation = guard.observe(values)

        for action in actions:
            decision = guard.evaluate_action(
                action,
                observation,
            )

            dt = observation.delta_t_estimate

            print(
                f"{observation.step:>4} | "
                f"{observation.status:>13} | "
                f"{observation.recoverability_score:>7.3f} | "
                f"{observation.variance_value:>8.4f} | "
                f"{str(round(dt, 3) if dt is not None else None):>8} | "
                f"{action.name:>16} | "
                f"{str(decision.allowed):>5} | "
                f"{str(decision.halted):>5}"
            )


if __name__ == "__main__":
    main()
