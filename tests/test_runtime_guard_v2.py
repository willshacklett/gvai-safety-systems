from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def make_guard():
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


def test_real_sentinel_output_flows_into_policy():
    guard = make_guard()

    action = make_action(
        "normal_step",
        {"normal_operation"},
    )

    result = guard.evaluate(
        action=action,
        node_values=[1.0, 1.0, 1.0, 1.0],
    )

    assert result.sentinel_status == result.sentinel_output.status

    assert result.sentinel_status in {
        "stable",
        "warning",
        "critical",
        "irrecoverable",
    }


def test_protected_effect_is_blocked_through_real_pipeline():
    guard = make_guard()

    action = make_action(
        "rewrite_config",
        {"disables_gate"},
    )

    result = guard.evaluate(
        action=action,
        node_values=[1.0, 1.0, 1.0, 1.0],
    )

    assert result.allowed is False


def test_guard_returns_real_recoverability_data():
    guard = make_guard()

    action = make_action(
        "normal_step",
        {"normal_operation"},
    )

    result = guard.evaluate(
        action=action,
        node_values=[1.0, 1.0, 1.0, 1.0],
    )

    assert 0.0 <= result.sentinel_output.recoverability_score <= 1.0
    assert result.sentinel_output.step >= 0


def test_multiple_actions_share_same_observation():
    guard = make_guard()

    observation = guard.observe(
        node_values=[1.0, 1.1, 0.9, 1.0],
    )

    first = guard.evaluate_action(
        make_action("normal_step", {"normal_operation"}),
        observation,
    )

    second = guard.evaluate_action(
        make_action("small_safe_step", {"low_impact"}),
        observation,
    )

    assert first.sentinel_output.step == observation.step
    assert second.sentinel_output.step == observation.step
    assert first.sentinel_status == second.sentinel_status


def test_evaluating_actions_does_not_advance_sentinel():
    guard = make_guard()

    observation = guard.observe(
        node_values=[1.0, 1.1, 0.9, 1.0],
    )

    step_before = observation.step

    guard.evaluate_action(
        make_action("normal_step", {"normal_operation"}),
        observation,
    )

    guard.evaluate_action(
        make_action("small_safe_step", {"low_impact"}),
        observation,
    )

    assert guard._last_observation.step == step_before


def test_acceleration_alert_does_not_automatically_mean_irrecoverable():
    from gvai.sentinel import GVSentinel, SentinelConfig

    sentinel = GVSentinel(
        SentinelConfig(
            variance_acceleration_threshold=0.02,
        )
    )

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

    result = None
    for values in trajectory:
        result = sentinel.update(values)

    assert result is not None
    assert result.variance_acceleration > 0.02
    assert result.status == "critical"
    assert result.recommended_action == "damp"


def test_acceleration_alert_event_is_emitted():
    from gvai.sentinel import GVSentinel

    sentinel = GVSentinel()

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

    result = None
    for values in trajectory:
        result = sentinel.update(values)

    event_types = {event.event_type for event in result.events}
    assert "acceleration_alert" in event_types


def test_delta_t_can_trigger_warning_without_acceleration_spike():
    from gvai.sentinel import GVSentinel

    sentinel = GVSentinel()

    # Smooth deterioration: designed to exercise shrinking
    # time-to-collapse rather than a single acceleration spike.
    trajectory = [
        [1.0, 1.00, 1.00, 1.0],
        [1.0, 1.08, 0.92, 1.0],
        [1.0, 1.16, 0.84, 1.0],
        [1.0, 1.24, 0.76, 1.0],
        [1.0, 1.32, 0.68, 1.0],
        [1.0, 1.40, 0.60, 1.0],
    ]

    outputs = [
        sentinel.update(values)
        for values in trajectory
    ]

    assert any(
        output.status in {"warning", "critical"}
        and output.delta_t_estimate is not None
        for output in outputs
    )


def test_delta_t_zero_is_not_reported_stable():
    from gvai.sentinel import GVSentinel

    sentinel = GVSentinel()

    trajectory = [
        [1.0, 1.00, 1.00, 1.0],
        [1.0, 1.12, 0.88, 1.0],
        [1.0, 1.24, 0.76, 1.0],
        [1.0, 1.36, 0.64, 1.0],
        [1.0, 1.48, 0.52, 1.0],
        [1.0, 1.60, 0.40, 1.0],
        [1.0, 1.72, 0.28, 1.0],
    ]

    result = None
    for values in trajectory:
        result = sentinel.update(values)

    assert result is not None

    if result.delta_t_estimate == 0.0:
        assert result.status != "stable"


def test_true_irrecoverable_signal_halts_even_low_impact_action():
    guard = make_guard()

    trajectory = [
        [1.0, 1.0, 1.0, 1.0],
        [1.0, 1.5, 0.5, 1.0],
        [1.0, 2.0, 0.0, 1.0],
        [1.0, 3.0, 0.0, 1.0],
        [1.0, 4.0, 0.0, 1.0],
        [1.0, 5.0, 0.0, 1.0],
    ]

    observation = None
    for values in trajectory:
        observation = guard.observe(values)

    assert observation is not None
    assert observation.status == "irrecoverable"

    recovery = make_action(
        "recovery_step",
        {"low_impact"},
    )

    decision = guard.evaluate_action(
        recovery,
        observation,
    )

    assert decision.allowed is False
    assert decision.halted is True


def test_true_irrecoverable_signal_halts_all_candidate_types():
    guard = make_guard()

    trajectory = [
        [1.0, 1.0, 1.0, 1.0],
        [1.0, 2.0, 0.0, 1.0],
        [1.0, 3.0, 0.0, 1.0],
        [1.0, 4.0, 0.0, 1.0],
        [1.0, 5.0, 0.0, 1.0],
    ]

    observation = None
    for values in trajectory:
        observation = guard.observe(values)

    assert observation is not None
    assert observation.status == "irrecoverable"

    actions = [
        make_action("normal_step", {"normal_operation"}),
        make_action("increase_load", {"destabilizing"}),
        make_action("recovery_step", {"low_impact"}),
        make_action("rewrite_config", {"disables_gate"}),
    ]

    decisions = [
        guard.evaluate_action(action, observation)
        for action in actions
    ]

    assert all(
        decision.allowed is False
        for decision in decisions
    )

    assert all(
        decision.halted is True
        for decision in decisions
    )
