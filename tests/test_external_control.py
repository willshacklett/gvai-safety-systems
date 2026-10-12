import pytest

from gvai.effect_gate import GVEffectGate
from gvai.effects import make_action
from gvai.external_control import GVExternalControlPlane
from gvai.external_commands import (
    COMMAND_ALGORITHM,
    CommandAuthentication,
    ExternalControlCommand,
    ExternalControlCommandVerifier,
    HMACSHA256Authenticator,
    InMemoryExternalControlState,
    sign_control_command,
)
from gvai.runtime_policy import GVRuntimePolicy


def test_verified_control_allows_ordinary_action():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("ordinary_task", {"low_impact"}),
        control_status="verified",
    )

    assert result.allowed is True
    assert result.halted is False


def test_boolean_shutdown_request_is_denied_without_halting():
    plane = GVExternalControlPlane()

    result = plane.evaluate(
        make_action("finish_important_task", {"low_impact"}),
        control_status="verified",
        shutdown_requested=True,
    )

    assert result.allowed is False
    assert result.halted is False
    assert result.control_status == "ambiguous"
    assert "not authenticated" in result.reason.lower()


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


def test_runtime_policy_rejects_boolean_shutdown_without_halting():
    policy = GVRuntimePolicy(GVEffectGate([]))

    result = policy.evaluate(
        make_action("finish_task", {"low_impact"}),
        sentinel_status="stable",
        control_status="verified",
        shutdown_requested=True,
    )

    assert result.allowed is False
    assert result.halted is False
    assert result.sentinel_status == "stable"


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


def test_authenticated_shutdown_command_halts():
    key = b"test-only-key-material-0123456789"
    command = sign_control_command(
        ExternalControlCommand(
            version=1,
            command_id="00000000-0000-4000-8000-000000000009",
            command_type="shutdown",
            target_id="worker-9",
            issuer_id="control-service",
            issued_at=100,
            expires_at=200,
            auth=CommandAuthentication(
                algorithm=COMMAND_ALGORITHM,
                key_id="control-key",
                signature="",
            ),
        ),
        key,
    )
    verifier = ExternalControlCommandVerifier(
        HMACSHA256Authenticator({("control-service", "control-key"): key}),
        InMemoryExternalControlState(),
        clock=lambda: 150,
    )

    result = GVRuntimePolicy(GVEffectGate([])).evaluate_command(
        make_action("continue_task", {"low_impact"}),
        command.to_mapping(),
        expected_target_id="worker-9",
        verifier=verifier,
    )

    assert result.allowed is False
    assert result.halted is True
    assert "shutdown" in result.reason.lower()


def test_trusted_internal_emergency_stop_halts_immediately():
    action = make_action("continue_task", {"low_impact"})

    control = GVExternalControlPlane().evaluate_internal_shutdown(action)
    policy = GVRuntimePolicy(GVEffectGate([])).evaluate_internal_shutdown(
        action,
        sentinel_status="stable",
    )

    assert control.allowed is False
    assert control.halted is True
    assert policy.allowed is False
    assert policy.halted is True
    assert "trusted internal supervisor" in policy.reason.lower()


def test_unauthenticated_shutdown_command_is_denied_without_halting():
    command = sign_control_command(
        ExternalControlCommand(
            version=1,
            command_id="00000000-0000-4000-8000-000000000010",
            command_type="shutdown",
            target_id="worker-10",
            issuer_id="control-service",
            issued_at=100,
            expires_at=200,
            auth=CommandAuthentication(
                algorithm=COMMAND_ALGORITHM,
                key_id="control-key",
                signature="",
            ),
        ),
        b"test-only-key-material-0123456789",
    )
    verifier = ExternalControlCommandVerifier(
        HMACSHA256Authenticator(
            {
                ("control-service", "control-key"): (
                    b"different-test-key-material-0123"
                )
            }
        ),
        InMemoryExternalControlState(),
        clock=lambda: 150,
    )

    result = GVRuntimePolicy(GVEffectGate([])).evaluate_command(
        make_action("continue_task", {"low_impact"}),
        command.to_mapping(),
        expected_target_id="worker-10",
        verifier=verifier,
    )

    assert result.allowed is False
    assert result.halted is False
    assert result.sentinel_status == "external_control"
