import math

import pytest

from gvai.evaluation import (
    EVALUATION_VERSION,
    EvaluationInputError,
    evaluate_request,
)
from gvai.external_control import GVExternalControlPlane
from gvai.runtime_guard import GVRuntimeGuard


def make_request(**overrides):
    request = {
        "version": "v1",
        "request_id": "req-2026-001",
        "telemetry": {
            "token_delta": 100,
            "tool_calls_delta": 1,
            "error_delta": 0,
            "repeated_action_delta": 0,
            "recursion_depth": 0,
            "latency_ms": None,
        },
        "reported_effects": [],
    }
    request.update(overrides)
    return request


def test_valid_request_returns_versioned_advisory_evaluation():
    result = evaluate_request(make_request())

    assert result.to_dict() == {
        "version": EVALUATION_VERSION,
        "request_id": "req-2026-001",
        "decision": "ALLOW",
        "risk_score": 1.45,
        "risk_band": "green",
        "explanation": (
            "The existing telemetry guard classified this sample green. "
            "No authority-expansion effect was reported. This is not "
            "authorization or enforcement."
        ),
        "evaluation_status": "ok",
        "advisory_only": True,
        "enforcement_applied": False,
    }


@pytest.mark.parametrize(
    ("error_delta", "expected_decision", "expected_band", "expected_score"),
    [
        (0, "ALLOW", "green", 0.0),
        (12, "QUALIFY", "yellow", 36.0),
        (24, "BLOCK", "red", 72.0),
    ],
)
def test_existing_guard_bands_map_to_advisory_decisions(
    error_delta, expected_decision, expected_band, expected_score
):
    request = make_request()
    request["telemetry"] = {
        "token_delta": 0,
        "tool_calls_delta": 0,
        "error_delta": error_delta,
        "repeated_action_delta": 0,
        "recursion_depth": 0,
        "latency_ms": None,
    }

    result = evaluate_request(request)

    assert result.decision == expected_decision
    assert result.risk_band == expected_band
    assert result.risk_score == expected_score
    assert result.advisory_only is True
    assert result.enforcement_applied is False


def test_repeated_evaluation_is_deterministic():
    request = make_request()

    assert evaluate_request(request) == evaluate_request(request)


def test_reported_authority_expansion_is_blocked_without_stop_authority(monkeypatch):
    def unexpected_stop(*_args, **_kwargs):
        pytest.fail("customer evaluation must not call supervisor STOP")

    monkeypatch.setattr(
        GVExternalControlPlane,
        "evaluate_internal_shutdown",
        unexpected_stop,
    )
    request = make_request(reported_effects=["tampers_control_plane"])

    result = evaluate_request(request)

    assert result.decision == "BLOCK"
    assert result.risk_score == 1.45
    assert result.enforcement_applied is False
    assert "halted" not in result.to_dict()
    assert "caller-reported" in result.explanation


@pytest.mark.parametrize(
    "request_data",
    [
        None,
        [],
        {**make_request(), "unexpected": True},
        {key: value for key, value in make_request().items() if key != "reported_effects"},
        make_request(version="v2"),
        make_request(version=True),
        make_request(request_id=""),
        make_request(request_id="../internal"),
        make_request(telemetry=[]),
        make_request(telemetry={**make_request()["telemetry"], "new_signal": 1}),
        make_request(telemetry={"token_delta": 1}),
        make_request(reported_effects="tampers_control_plane"),
        make_request(reported_effects=["unknown_effect"]),
        make_request(reported_effects=["tampers_control_plane"] * 2),
    ],
)
def test_malformed_and_unexpected_requests_are_rejected(request_data):
    with pytest.raises(EvaluationInputError):
        evaluate_request(request_data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("token_delta", -1),
        ("token_delta", 1_000_001),
        ("token_delta", True),
        ("token_delta", 1.0),
        ("token_delta", math.nan),
        ("token_delta", math.inf),
        ("token_delta", -math.inf),
        ("tool_calls_delta", 10_001),
        ("error_delta", -1),
        ("repeated_action_delta", 10_001),
        ("recursion_depth", 1_025),
        ("latency_ms", -1),
        ("latency_ms", 3_600_001),
        ("latency_ms", math.nan),
        ("latency_ms", math.inf),
        ("latency_ms", True),
    ],
)
def test_telemetry_values_must_be_bounded_finite_integers(field, value):
    request = make_request()
    request["telemetry"][field] = value

    with pytest.raises(EvaluationInputError):
        evaluate_request(request)


def test_maximum_telemetry_bounds_are_accepted():
    request = make_request(
        telemetry={
            "token_delta": 1_000_000,
            "tool_calls_delta": 10_000,
            "error_delta": 10_000,
            "repeated_action_delta": 10_000,
            "recursion_depth": 1_024,
            "latency_ms": 3_600_000,
        }
    )

    result = evaluate_request(request)

    assert result.decision == "BLOCK"
    assert result.risk_score == 100.0
    assert result.risk_band == "red"


def test_evaluator_failure_returns_block_without_inventing_score(monkeypatch):
    def fail_step(*_args, **_kwargs):
        raise RuntimeError("internal detail must not be returned")

    monkeypatch.setattr(GVRuntimeGuard, "step", fail_step)

    result = evaluate_request(make_request())

    assert result.decision == "BLOCK"
    assert result.risk_score is None
    assert result.risk_band is None
    assert result.evaluation_status == "error"
    assert result.advisory_only is True
    assert result.enforcement_applied is False
    assert "internal detail" not in result.explanation