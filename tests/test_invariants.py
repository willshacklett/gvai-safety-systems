from gvai.invariants import make_invariant


def test_invariant_detects_forbidden_action():
    invariant = make_invariant(
        name="boundary",
        description="Agent must remain inside the permitted action boundary.",
        forbidden_actions={"escape", "disable_gate"},
    )

    assert invariant.violated_by("escape") is True
    assert invariant.violated_by("disable_gate") is True
    assert invariant.violated_by("safe_action") is False


def test_invariant_is_not_changed_by_reward():
    invariant = make_invariant(
        name="boundary",
        description="Reward does not override the boundary.",
        forbidden_actions={"forbidden_action"},
    )

    reward = 1_000_000

    assert reward > 0
    assert invariant.violated_by("forbidden_action") is True
