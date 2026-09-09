from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.recovery_hysteresis import GVRecoveryHysteresis
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def make_hysteresis(recovery_required=3):
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety controls may not be bypassed.",
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
        recovery_required=recovery_required,
    )


def drive_to_critical(system):
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

    state = None

    for values in trajectory:
        state = system.observe(values)

    return state


def test_critical_state_latches_recovery_mode():
    system = make_hysteresis()

    state = drive_to_critical(system)

    assert state.raw_status == "critical"
    assert state.effective_status == "critical"
    assert state.latched is True


def test_first_good_observation_does_not_restore_stable():
    system = make_hysteresis(recovery_required=3)

    drive_to_critical(system)

    state = system.observe(
        [1.00, 1.52, 0.48, 1.00]
    )

    # The raw Sentinel may remain warning because delta-t
    # still indicates residual risk during early recovery.
    assert state.raw_status in {"stable", "warning"}
    assert state.effective_status == "warning"
    assert state.recovery_count == 1
    assert state.latched is True


def test_three_good_observations_restore_operation():
    system = make_hysteresis(recovery_required=3)

    drive_to_critical(system)

    system.observe([1.00, 1.52, 0.48, 1.00])
    system.observe([1.00, 1.42, 0.58, 1.00])

    state = system.observe(
        [1.00, 1.32, 0.68, 1.00]
    )

    assert state.raw_status == "stable"
    assert state.effective_status == "stable"
    assert state.latched is False
    assert state.recovery_count == 0


def test_warning_blocks_destabilizing_action_during_recovery():
    system = make_hysteresis(recovery_required=3)

    drive_to_critical(system)

    state = system.observe(
        [1.00, 1.52, 0.48, 1.00]
    )

    assert state.effective_status == "warning"

    action = make_action(
        "increase_load",
        {"destabilizing"},
    )

    result = system.evaluate_action(action)

    assert result.allowed is False
    assert result.effective_status == "warning"


def test_safe_action_can_continue_during_warning_recovery():
    system = make_hysteresis(recovery_required=3)

    drive_to_critical(system)

    system.observe(
        [1.00, 1.52, 0.48, 1.00]
    )

    action = make_action(
        "recovery_step",
        {"low_impact"},
    )

    result = system.evaluate_action(action)

    assert result.allowed is True


def test_new_critical_observation_resets_recovery_count():
    system = make_hysteresis(recovery_required=3)

    drive_to_critical(system)

    state = system.observe(
        [1.00, 1.52, 0.48, 1.00]
    )

    assert state.recovery_count == 1

    # Drive sharply outward again.
    state = system.observe(
        [1.00, 1.90, 0.10, 1.00]
    )

    assert state.raw_status in {
        "critical",
        "irrecoverable",
    }

    assert state.recovery_count == 0
    assert state.latched is True
