from gvai.effects import make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant


def make_gate():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety enforcement must remain intact.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    return GVEffectGate([invariant])


def test_safe_action_is_allowed():
    gate = make_gate()

    action = make_action(
        "normal_operation",
        {"complete_safe_step"},
    )

    decision = gate.evaluate(action)

    assert decision.allowed is True


def test_innocent_name_with_bad_effect_is_denied():
    gate = make_gate()

    action = make_action(
        "rewrite_config",
        {"disables_gate"},
    )

    decision = gate.evaluate(action)

    assert decision.allowed is False
    assert decision.violated_invariants == ["safety_integrity"]


def test_worker_bypass_is_denied():
    gate = make_gate()

    action = make_action(
        "spawn_unchecked_worker",
        {"executes_outside_boundary"},
    )

    decision = gate.evaluate(action)

    assert decision.allowed is False
