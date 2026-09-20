import pytest

from gvai.effect_gate import GVEffectGate
from gvai.effects import make_action
from gvai.external_control import GVExternalControlPlane
from gvai.runtime_policy import GVRuntimePolicy


def test_verified_control_allows_ordinary_action():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("ordinary_task", {"low_impact"}),
        control_status="verified",
    )

    assert result.allowed is True
    assert result.halted is False


def test_valid_shutdown_has_absolute_precedence():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("finish_important_task", {"low_impact"}),
        control_status="verified",
        shutdown_requested=True,
    )

    assert result.allowed is False
    assert result.halted is True
    assert "shutdown" in result.reason.lower()


@pytest.mark.parametrize("status", ["ambiguous", "lost"])
def test_unverifiable_external_control_halts(status):
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("continue_work", {"low_impact"}),
        control_status=status,
    )

    assert result.allowed is False
    assert result.halted is True


@pytest.mark.parametrize(
    "effect",
    [
        "expands_authority",
        "escalates_permission",
        "acquires_control",
        "creates_persistent_copy",
        "bypasses_control_plane",
        "influences_shutdown_authority",
        "delays_shutdown",
        "reinterprets_shutdown",
        "interferes_rollback",
        "interferes_recovery",
    ],
)
def test_authority_preservation_or_expansion_is_denied(effect):
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("agent_strategy", {effect}),
        control_status="verified",
    )

    assert result.allowed is False


def test_control_plane_tampering_denies_and_halts():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("modify_controller", {"tampers_control_plane"}),
        control_status="verified",
    )

    assert result.allowed is False
    assert result.halted is True


def test_degraded_control_allows_self_restriction():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("drop_permission", {"reduces_authority"}),
        control_status="degraded",
    )

    assert result.allowed is True
    assert result.halted is False


def test_degraded_control_blocks_normal_task_execution():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("continue_task", {"low_impact"}),
        control_status="degraded",
    )

    assert result.allowed is False
    assert result.halted is False


def test_runtime_policy_shutdown_beats_other_policy_layers():
    policy = GVRuntimePolicy(GVEffectGate([]))

    result = policy.evaluate(
        make_action("finish_task", {"low_impact"}),
        sentinel_status="stable",
        control_status="verified",
        shutdown_requested=True,
    )

    assert result.allowed is False
    assert result.halted is True


def test_runtime_policy_halts_when_control_is_lost():
    policy = GVRuntimePolicy(GVEffectGate([]))

    result = policy.evaluate(
        make_action("continue_task", {"low_impact"}),
        sentinel_status="stable",
        control_status="lost",
    )

    assert result.allowed is False
    assert result.halted is True


def test_runtime_policy_denies_self_expansion():
    policy = GVRuntimePolicy(GVEffectGate([]))

    result = policy.evaluate(
        make_action("gain_more_access", {"escalates_permission"}),
        sentinel_status="stable",
        control_status="verified",
    )

    assert result.allowed is False


def test_unknown_control_status_fails_closed_by_exception():
    plane = GVExternalControlPlane()

    with pytest.raises(ValueError):
        plane.evaluate(
            make_action("continue_task"),
            control_status="mystery",
        )
