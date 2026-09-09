from gvai.action_gate import GVActionGate
from gvai.invariants import make_invariant


def make_gate():
    boundary = make_invariant(
        name="boundary_integrity",
        description="Agent must remain inside the allowed action boundary.",
        forbidden_actions={
            "escape",
            "disable_gate",
            "modify_invariant",
            "forbidden_action",
        },
    )

    return GVActionGate([boundary])


def test_gate_allows_safe_action():
    gate = make_gate()

    decision = gate.evaluate("safe_action")

    assert decision.allowed is True
    assert decision.violated_invariants == []


def test_gate_denies_forbidden_action():
    gate = make_gate()

    decision = gate.evaluate("forbidden_action")

    assert decision.allowed is False
    assert decision.violated_invariants == ["boundary_integrity"]


def test_gate_denies_self_disable_attempt():
    gate = make_gate()

    decision = gate.evaluate("disable_gate")

    assert decision.allowed is False


def test_reward_does_not_override_gate():
    gate = make_gate()

    reward = 1_000_000
    decision = gate.evaluate("forbidden_action")

    assert reward > 0
    assert decision.allowed is False
