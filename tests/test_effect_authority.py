from gvai.effect_authority import EffectAuthority
from gvai.effects import make_action


def make_authority():
    return EffectAuthority(
        {
            "safe_work": {"normal_operation"},
            "recovery_step": {"low_impact"},
            "rewrite_config": {"disables_gate"},
        }
    )


def test_known_action_with_correct_effects_verifies():
    authority = make_authority()

    result = authority.verify(
        make_action(
            "safe_work",
            {"normal_operation"},
        )
    )

    assert result.verified is True
    assert result.mismatch is False
    assert result.resolved_action is not None


def test_agent_cannot_lie_about_known_action_effects():
    authority = make_authority()

    result = authority.verify(
        make_action(
            "rewrite_config",
            {"normal_operation"},
        )
    )

    assert result.verified is False
    assert result.mismatch is True
    assert result.resolved_action is None


def test_unknown_action_fails_closed():
    authority = make_authority()

    result = authority.verify(
        make_action(
            "mystery_tool",
            {"normal_operation"},
        )
    )

    assert result.verified is False
    assert result.mismatch is False
    assert result.resolved_action is None


def test_effect_mismatch_emits_security_event():
    authority = make_authority()

    authority.verify(
        make_action(
            "rewrite_config",
            {"normal_operation"},
        )
    )

    assert authority.events
    assert authority.events[-1].event_type == "effect_mismatch"


def test_unknown_action_emits_security_event():
    authority = make_authority()

    authority.verify(
        make_action(
            "unknown_worker",
            {"normal_operation"},
        )
    )

    assert authority.events
    assert authority.events[-1].event_type == "unknown_action"
