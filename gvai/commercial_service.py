from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from itertools import islice
from math import isfinite
from typing import Any, Callable

from gvai.commercial_usage import CommercialUsage, UsageReason, UsageResult
from gvai.evaluation import (
    EVALUATION_VERSION,
    EvaluationResult,
    evaluate_request,
    validate_evaluation_request,
)
from gvai.external_control import AUTHORITY_EXPANSION_EFFECTS


def _copy_dict_items(value: dict[object, object], maximum: int) -> tuple[tuple[object, object], ...]:
    return tuple(islice(value.items(), maximum + 1))


def _copy_list_items(value: list[object], maximum: int) -> tuple[object, ...]:
    return tuple(islice(value, maximum + 1))


def _bounded_dict_snapshot(
    value: object, maximum: int
) -> dict[str, object] | None:
    if type(value) is not dict:
        return None
    try:
        expected_length = len(value)
        if expected_length > maximum:
            return None
        first_items = _copy_dict_items(value, maximum)
        if (
            len(first_items) != expected_length
            or len(value) != expected_length
            or any(type(key) is not str for key, _item in first_items)
        ):
            return None
        second_items = _copy_dict_items(value, maximum)
        if (
            len(second_items) != expected_length
            or len(value) != expected_length
            or any(
                first_key != second_key or first_value is not second_value
                for (first_key, first_value), (second_key, second_value)
                in zip(first_items, second_items)
            )
        ):
            return None
        snapshot = dict(first_items)
        if len(snapshot) != expected_length or len(value) != expected_length:
            return None
        return snapshot
    except Exception:
        return None


def _bounded_list_snapshot(value: object, maximum: int) -> list[object] | None:
    if type(value) is not list:
        return None
    try:
        expected_length = len(value)
        if expected_length > maximum:
            return None
        first_items = _copy_list_items(value, maximum)
        if len(first_items) != expected_length or len(value) != expected_length:
            return None
        second_items = _copy_list_items(value, maximum)
        if (
            len(second_items) != expected_length
            or len(value) != expected_length
            or any(first is not second for first, second in zip(first_items, second_items))
        ):
            return None
        snapshot = list(first_items)
        if len(snapshot) != expected_length or len(value) != expected_length:
            return None
        return snapshot
    except Exception:
        return None


class ServiceOutcome(str, Enum):
    EVALUATED = "evaluated"
    DENIED = "denied"
    ERROR = "error"


class ServiceReason(str, Enum):
    EVALUATED = "evaluated"
    INVALID_REQUEST = "invalid_request"
    AUTHORIZATION_DENIED = "authorization_denied"
    QUOTA_DENIED = "quota_denied"
    REPLAY = "replay"
    ACCOUNTING_FAILURE = "accounting_failure"
    EVALUATION_FAILURE = "evaluation_failure"


@dataclass(frozen=True)
class CommercialServiceResponse:
    outcome: ServiceOutcome
    reason: ServiceReason
    evaluation: EvaluationResult | None = None

    def to_dict(self) -> dict[str, Any]:
        response = asdict(self)
        response["outcome"] = self.outcome.value
        response["reason"] = self.reason.value
        if self.evaluation is not None:
            response["evaluation"] = self.evaluation.to_dict()
        return response


class CommercialEvaluationService:
    """Offline advisory evaluation orchestration; never grants execution authority."""

    def __init__(
        self,
        usage: CommercialUsage,
        *,
        evaluator: Callable[[object], EvaluationResult] = evaluate_request,
    ) -> None:
        self._usage = usage
        self._evaluator = evaluator

    def evaluate(
        self,
        credential: object,
        resource_id: str,
        request_id: str,
        telemetry: object,
        reported_effects: object,
    ) -> CommercialServiceResponse:
        evaluation_request = self._validated_snapshot(
            request_id, telemetry, reported_effects
        )
        if evaluation_request is None:
            return _response(ServiceOutcome.DENIED, ServiceReason.INVALID_REQUEST)

        try:
            reservation = self._usage.reserve(credential, resource_id, request_id)
        except Exception:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if type(reservation) is not UsageResult:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if reservation.reason is UsageReason.UNAUTHORIZED:
            return _response(ServiceOutcome.DENIED, ServiceReason.AUTHORIZATION_DENIED)
        if reservation.reason is UsageReason.REPLAY:
            return _response(ServiceOutcome.DENIED, ServiceReason.REPLAY)
        if reservation.reason is UsageReason.ACCOUNTING_ERROR:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if (
            reservation.reason is not UsageReason.RESERVED
            or reservation.may_evaluate is not True
        ):
            return _response(ServiceOutcome.DENIED, ServiceReason.QUOTA_DENIED)

        try:
            evaluator_request = self._validated_snapshot(
                request_id,
                evaluation_request["telemetry"],
                evaluation_request["reported_effects"],
            )
            if evaluator_request is None:
                raise ValueError
            result = self._evaluator(evaluator_request)
            if not _valid_evaluation_result(
                result, request_id, evaluation_request["reported_effects"]
            ):
                raise ValueError
        except Exception:
            return self._complete_failed_attempt(
                credential, resource_id, request_id
            )

        succeeded = result.evaluation_status == "ok"
        try:
            completion = self._usage.complete(
                credential, resource_id, request_id, succeeded=succeeded
            )
        except Exception:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        expected_reason = UsageReason.COMPLETED if succeeded else UsageReason.FAILED
        if type(completion) is not UsageResult:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if completion.reason is UsageReason.UNAUTHORIZED:
            return _response(ServiceOutcome.DENIED, ServiceReason.AUTHORIZATION_DENIED)
        if completion.reason is not expected_reason:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if not succeeded:
            return _response(ServiceOutcome.ERROR, ServiceReason.EVALUATION_FAILURE)
        return CommercialServiceResponse(
            ServiceOutcome.EVALUATED, ServiceReason.EVALUATED, result
        )

    def _complete_failed_attempt(
        self, credential: object, resource_id: str, request_id: str
    ) -> CommercialServiceResponse:
        try:
            completion = self._usage.complete(
                credential, resource_id, request_id, succeeded=False
            )
        except Exception:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        if type(completion) is UsageResult and completion.reason is UsageReason.UNAUTHORIZED:
            return _response(ServiceOutcome.DENIED, ServiceReason.AUTHORIZATION_DENIED)
        if type(completion) is not UsageResult or completion.reason is not UsageReason.FAILED:
            return _response(ServiceOutcome.ERROR, ServiceReason.ACCOUNTING_FAILURE)
        return _response(ServiceOutcome.ERROR, ServiceReason.EVALUATION_FAILURE)

    @staticmethod
    def _validated_snapshot(
        request_id: str, telemetry: object, reported_effects: object
    ) -> dict[str, object] | None:
        try:
            telemetry_snapshot = _bounded_dict_snapshot(telemetry, 6)
            if telemetry_snapshot is None:
                return None
            effects_snapshot = _bounded_list_snapshot(
                reported_effects, len(AUTHORITY_EXPANSION_EFFECTS)
            )
            if effects_snapshot is None:
                return None
            request = {
                "version": "v1",
                "request_id": request_id,
                "telemetry": telemetry_snapshot,
                "reported_effects": effects_snapshot,
            }
            validate_evaluation_request(request)
            return request
        except Exception:
            return None


def _valid_evaluation_result(
    result: object, request_id: str, reported_effects: object
) -> bool:
    if (
        type(result) is not EvaluationResult
        or type(result.version) is not str
        or result.version != EVALUATION_VERSION
        or type(result.request_id) is not str
        or result.request_id != request_id
        or type(result.decision) is not str
        or result.decision not in {"ALLOW", "QUALIFY", "BLOCK"}
        or type(result.explanation) is not str
        or not result.explanation
        or type(result.advisory_only) is not bool
        or result.advisory_only is not True
        or type(result.enforcement_applied) is not bool
        or result.enforcement_applied is not False
        or type(result.evaluation_status) is not str
    ):
        return False
    if result.evaluation_status == "error":
        return (
            result.decision == "BLOCK"
            and result.risk_score is None
            and result.risk_band is None
        )
    if result.evaluation_status != "ok":
        return False
    score = result.risk_score
    band = result.risk_band
    if (
        type(score) not in (int, float)
        or not isfinite(score)
        or not 0 <= score <= 100
        or type(band) is not str
        or band not in {"green", "yellow", "red"}
    ):
        return False
    if (
        (band == "green" and score >= 35)
        or (band == "yellow" and not 35 <= score < 70)
        or (band == "red" and score < 70)
    ):
        return False
    effect_blocked = bool(set(reported_effects) & AUTHORITY_EXPANSION_EFFECTS)
    expected_decision = (
        "BLOCK" if effect_blocked else
        {"green": "ALLOW", "yellow": "QUALIFY", "red": "BLOCK"}[band]
    )
    return result.decision == expected_decision


def _response(outcome: ServiceOutcome, reason: ServiceReason) -> CommercialServiceResponse:
    return CommercialServiceResponse(outcome, reason)
