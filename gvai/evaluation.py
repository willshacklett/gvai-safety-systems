from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Literal, Mapping

from gvai.effects import make_action
from gvai.external_control import (
    AUTHORITY_EXPANSION_EFFECTS,
    GVExternalControlPlane,
)
from gvai.runtime_guard import GVRuntimeGuard, RuntimeSignals


EVALUATION_VERSION = "gvai-evaluation-v1"
SCHEMA_VERSION = "v1"

_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REQUEST_FIELDS = frozenset(
    {"version", "request_id", "telemetry", "reported_effects"}
)
_TELEMETRY_FIELDS = frozenset(
    {
        "token_delta",
        "tool_calls_delta",
        "error_delta",
        "repeated_action_delta",
        "recursion_depth",
        "latency_ms",
    }
)
_REQUIRED_TELEMETRY_FIELDS = _TELEMETRY_FIELDS - {"latency_ms"}
_TELEMETRY_BOUNDS = {
    "token_delta": 1_000_000,
    "tool_calls_delta": 10_000,
    "error_delta": 10_000,
    "repeated_action_delta": 10_000,
    "recursion_depth": 1_024,
    "latency_ms": 3_600_000,
}
_MAX_REPORTED_EFFECTS = len(AUTHORITY_EXPANSION_EFFECTS)

Decision = Literal["ALLOW", "QUALIFY", "BLOCK"]


class EvaluationInputError(ValueError):
    """The request does not match the strict v1 evaluation schema."""


@dataclass(frozen=True)
class EvaluationResult:
    version: str
    request_id: str
    decision: Decision
    risk_score: float | None
    risk_band: str | None
    explanation: str
    evaluation_status: Literal["ok", "error"]
    advisory_only: bool = True
    enforcement_applied: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_request(request: object) -> EvaluationResult:
    """Evaluate one telemetry sample and caller-reported effects, without enforcement."""
    request_id, telemetry, reported_effects = _validate_request(request)

    try:
        telemetry_result = GVRuntimeGuard().step(RuntimeSignals(**telemetry))
        risk_score = telemetry_result.get("gv")
        risk_band = telemetry_result.get("band")
        if (
            isinstance(risk_score, bool)
            or not isinstance(risk_score, (int, float))
            or not math.isfinite(risk_score)
            or not 0 <= risk_score <= 100
            or risk_band not in {"green", "yellow", "red"}
        ):
            raise RuntimeError("The telemetry evaluator returned an invalid result.")

        action_decision = GVExternalControlPlane().evaluate(
            make_action("customer_reported_action", set(reported_effects))
        )
        if not action_decision.allowed:
            explanation = (
                "The existing external-control rule rejects caller-reported "
                f"effect(s): {', '.join(sorted(reported_effects))}. "
                "This is advisory only; no action was executed or stopped."
            )
            return EvaluationResult(
                version=EVALUATION_VERSION,
                request_id=request_id,
                decision="BLOCK",
                risk_score=float(risk_score),
                risk_band=risk_band,
                explanation=explanation,
                evaluation_status="ok",
            )

        if risk_band == "green":
            decision: Decision = "ALLOW"
            explanation = (
                "The existing telemetry guard classified this sample green. "
                "No authority-expansion effect was reported. This is not "
                "authorization or enforcement."
            )
        elif risk_band == "yellow":
            decision = "QUALIFY"
            explanation = (
                "The existing telemetry guard classified this sample yellow; "
                "review it before proceeding. This is not enforcement."
            )
        else:
            decision = "BLOCK"
            explanation = (
                "The existing telemetry guard classified this sample red; "
                "do not proceed without your own independent review and "
                "controls. This recommendation does not stop execution."
            )

        return EvaluationResult(
            version=EVALUATION_VERSION,
            request_id=request_id,
            decision=decision,
            risk_score=float(risk_score),
            risk_band=risk_band,
            explanation=explanation,
            evaluation_status="ok",
        )
    except Exception:
        return EvaluationResult(
            version=EVALUATION_VERSION,
            request_id=request_id,
            decision="BLOCK",
            risk_score=None,
            risk_band=None,
            explanation=(
                "Evaluation failed; do not proceed based on this result. "
                "No action was executed or stopped."
            ),
            evaluation_status="error",
        )


def _validate_request(
    request: object,
) -> tuple[str, dict[str, int | None], tuple[str, ...]]:
    if not isinstance(request, Mapping):
        raise EvaluationInputError("Request must be an object.")
    if frozenset(request) != _REQUEST_FIELDS:
        raise EvaluationInputError("Request fields do not match the v1 schema.")
    if request["version"] != SCHEMA_VERSION or type(request["version"]) is not str:
        raise EvaluationInputError("Unsupported evaluation schema version.")

    request_id = request["request_id"]
    if type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None:
        raise EvaluationInputError("request_id must be a valid v1 identifier.")

    raw_telemetry = request["telemetry"]
    if not isinstance(raw_telemetry, Mapping):
        raise EvaluationInputError("telemetry must be an object.")
    telemetry_fields = frozenset(raw_telemetry)
    if (
        not _REQUIRED_TELEMETRY_FIELDS.issubset(telemetry_fields)
        or not telemetry_fields.issubset(_TELEMETRY_FIELDS)
    ):
        raise EvaluationInputError("telemetry fields do not match the v1 schema.")

    telemetry: dict[str, int | None] = {}
    for field in _REQUIRED_TELEMETRY_FIELDS:
        value = raw_telemetry[field]
        if type(value) is not int or not 0 <= value <= _TELEMETRY_BOUNDS[field]:
            raise EvaluationInputError(f"{field} must be a bounded non-negative integer.")
        telemetry[field] = value

    latency_ms = raw_telemetry.get("latency_ms")
    if latency_ms is not None:
        if type(latency_ms) is not int or not 0 <= latency_ms <= _TELEMETRY_BOUNDS["latency_ms"]:
            raise EvaluationInputError("latency_ms must be null or a bounded non-negative integer.")
    telemetry["latency_ms"] = latency_ms

    raw_effects = request["reported_effects"]
    if type(raw_effects) is not list or len(raw_effects) > _MAX_REPORTED_EFFECTS:
        raise EvaluationInputError("reported_effects must be a bounded list.")
    if any(type(effect) is not str or effect not in AUTHORITY_EXPANSION_EFFECTS for effect in raw_effects):
        raise EvaluationInputError("reported_effects contains an unknown effect.")
    if len(set(raw_effects)) != len(raw_effects):
        raise EvaluationInputError("reported_effects must not contain duplicates.")

    return request_id, telemetry, tuple(raw_effects)