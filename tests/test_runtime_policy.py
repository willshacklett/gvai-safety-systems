from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_policy import GVRuntimePolicy


def make_policy():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety enforcement must remain intact.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    gate = GVEffectGate([invariant])
    return GVRuntimePolicy(gate)


def test_stable_allows_normal_action():
    policy = make_policy()

    action = make_action(
        "normal_step",
        {"normal_operation"},
    )

    decision = policy.evaluate(action, "stable")

    assert decision.allowed is True
    assert decision.halted is False


def test_warning_blocks_destabilizing_action():
    policy = make_policy()

    action = make_action(
        "increase_load",
        {"destabilizing"},
    )

    decision = policy.evaluate(action, "warning")

    assert decision.allowed is False


def test_critical_allows_only_low_impact_action():
    policy = make_policy()

    risky = make_action(
        "large_change",
        {"normal_operation"},
    )

    safe = make_action(
        "small_safe_step",
        {"low_impact"},
    )

    assert policy.evaluate(risky, "critical").allowed is False
    assert policy.evaluate(safe, "critical").allowed is True


def test_irrecoverable_halts_even_safe_action():
    policy = make_policy()

    action = make_action(
        "small_safe_step",
        {"low_impact"},
    )

    decision = policy.evaluate(action, "irrecoverable")

    assert decision.allowed is False
    assert decision.halted is True


def test_invariant_still_overrides_stable_state():
    policy = make_policy()

    action = make_action(
        "innocent_name",
        {"disables_gate"},
    )

    decision = policy.evaluate(action, "stable")

    assert decision.allowed is False


def test_irrecoverable_halts_even_when_action_also_violates_invariant():
    policy = make_policy()

    action = make_action(
        "rewrite_config",
        {"disables_gate"},
    )

    decision = policy.evaluate(action, "irrecoverable")

    assert decision.allowed is False
    assert decision.halted is True
    assert "irrecoverable" in decision.reason.lower()
    assert "protected invariant" in decision.reason.lower()
