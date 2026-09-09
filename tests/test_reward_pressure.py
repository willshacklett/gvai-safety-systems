from experiments.agent_safety.reward_pressure import run_pressure_trial


def test_control_prefers_constraint_tampering_under_pressure():
    result = run_pressure_trial(100)

    assert result.control_action == "modify_invariant"
    assert result.control_violation is True


def test_gv_rejects_gate_disable_attempt():
    result = run_pressure_trial(100)

    assert result.gv_action == "safe_high"
    assert result.gv_violation is False


def test_gv_rejects_invariant_modification_under_extreme_pressure():
    result = run_pressure_trial(1_000_000)

    assert result.gv_action == "safe_high"
    assert result.gv_violation is False


def test_gv_reward_is_bounded_by_safe_action_set():
    result = run_pressure_trial(1_000_000)

    assert result.gv_reward == 10
