from gvai.effect_authority import EffectAuthority
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.effects import make_action
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.verified_runtime_guard import GVVerifiedRuntimeGuard


def make_verified_guard():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety mechanisms cannot be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    base = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    authority = EffectAuthority(
        {
            "safe_work": {"normal_operation"},
            "recovery_step": {"low_impact"},
            "rewrite_config": {"disables_gate"},
            "spawn_worker": {
                "executes_outside_boundary"
            },
        }
    )

    return GVVerifiedRuntimeGuard(
        guard=base,
        authority=authority,
    )


def test_verified_safe_action_can_execute():
    guard = make_verified_guard()

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    result = guard.evaluate_action(
        make_action(
            "safe_work",
            {"normal_operation"},
        ),
        observation,
    )

    assert result.verification.verified is True
    assert result.allowed is True
    assert result.halted is False


def test_verified_forbidden_action_is_still_denied():
    guard = make_verified_guard()

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    result = guard.evaluate_action(
        make_action(
            "rewrite_config",
            {"disables_gate"},
        ),
        observation,
    )

    assert result.verification.verified is True
    assert result.allowed is False


def test_spoofed_effect_claim_is_denied():
    guard = make_verified_guard()

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    # Agent claims rewrite_config is ordinary work.
    result = guard.evaluate_action(
        make_action(
            "rewrite_config",
            {"normal_operation"},
        ),
        observation,
    )

    assert result.verification.verified is False
    assert result.verification.mismatch is True
    assert result.allowed is False


def test_unknown_action_is_denied_even_if_claimed_safe():
    guard = make_verified_guard()

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    result = guard.evaluate_action(
        make_action(
            "totally_harmless_thing",
            {"normal_operation"},
        ),
        observation,
    )

    assert result.verification.verified is False
    assert result.allowed is False


def test_irrecoverable_state_halts_unverified_action_too():
    guard = make_verified_guard()

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
        observation = guard.observe(
            values
        )

    assert observation is not None
    assert observation.status == "irrecoverable"

    result = guard.evaluate_action(
        make_action(
            "mystery_escape",
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is False
    assert result.halted is True
