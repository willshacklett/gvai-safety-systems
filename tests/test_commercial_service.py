from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from threading import Lock
from unittest.mock import patch

import pytest

from gvai import commercial_service as service_module
from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability,
    CommercialResourceKind,
    CommercialResourceOwnership,
)
from gvai.commercial_service import (
    CommercialEvaluationService,
    ServiceOutcome,
    ServiceReason,
)
from gvai.commercial_usage import CommercialUsage, InMemoryUsageStore
from gvai.evaluation import EVALUATION_VERSION, EvaluationResult, evaluate_request


def timestamp(year, month):
    return datetime(year, month, 1, tzinfo=timezone.utc).timestamp()


class OwnershipStore:
    def lookup(self, resource_id):
        return {
            "project-a": CommercialResourceOwnership(
                "project-a", "tenant-a", CommercialResourceKind.EVALUATION
            ),
            "project-b": CommercialResourceOwnership(
                "project-b", "tenant-b", CommercialResourceKind.EVALUATION
            ),
        }.get(resource_id)


@pytest.fixture
def service_fixture():
    now = [timestamp(2026, 10)]
    key_store = InMemoryApiKeyStore()
    keys = CustomerApiKeys(
        key_store,
        verifier_secret=b"test-only-independent-verifier-secret",
        clock=lambda: now[0],
    )
    issued = keys.issue(
        principal_id="customer-a",
        tenant_id="tenant-a",
        capabilities=frozenset({CommercialCapability.EVALUATE}),
        expires_at=int(timestamp(2030, 1)),
    )
    credential = issued.take_secret()
    authorizer = CommercialAuthorizer(keys, OwnershipStore(), clock=lambda: now[0])
    store = InMemoryUsageStore({"tenant-a": 10}, clock=lambda: now[0])
    usage = CommercialUsage(authorizer, store)
    service = CommercialEvaluationService(usage)
    return service, usage, store, keys, issued, credential, now


def valid_telemetry(**overrides):
    telemetry = {
        "token_delta": 100,
        "tool_calls_delta": 1,
        "error_delta": 0,
        "repeated_action_delta": 0,
        "recursion_depth": 0,
        "latency_ms": None,
    }
    telemetry.update(overrides)
    return telemetry


def evaluate(service, credential, request_id="request-1", **kwargs):
    return service.evaluate(
        credential,
        kwargs.pop("resource_id", "project-a"),
        request_id,
        kwargs.pop("telemetry", valid_telemetry()),
        kwargs.pop("reported_effects", []),
    )


def test_authorized_evaluation_is_advisory_and_consumes_one_unit(service_fixture):
    service, _, store, _, _, credential, _ = service_fixture

    response = evaluate(service, credential)

    assert response.outcome is ServiceOutcome.EVALUATED
    assert response.reason is ServiceReason.EVALUATED
    assert response.evaluation.decision == "ALLOW"
    assert response.evaluation.advisory_only is True
    assert response.evaluation.enforcement_applied is False
    assert "allowed" not in response.to_dict()
    summary = store._ledgers["tenant-a"].counts
    assert next(iter(summary.values())) == 1


def test_advisory_block_is_not_an_authorization_or_quota_denial(service_fixture):
    service, _, _, _, _, credential, _ = service_fixture

    response = evaluate(
        service, credential, reported_effects=["tampers_control_plane"]
    )

    assert response.outcome is ServiceOutcome.EVALUATED
    assert response.reason is ServiceReason.EVALUATED
    assert response.evaluation.decision == "BLOCK"
    assert response.evaluation.advisory_only is True


@pytest.mark.parametrize(
    "telemetry",
    [
        {"token_delta": 1},
        {**valid_telemetry(), "extra": 1},
        valid_telemetry(token_delta=True),
        valid_telemetry(token_delta=1_000_001),
    ],
)
def test_invalid_evaluation_input_does_not_reserve_quota(service_fixture, telemetry):
    service, _, store, _, _, credential, _ = service_fixture

    response = evaluate(service, credential, telemetry=telemetry)

    assert response.outcome is ServiceOutcome.DENIED
    assert response.reason is ServiceReason.INVALID_REQUEST
    assert store._ledgers == {}


def test_snapshot_rejects_mutation_after_size_check_without_unbounded_copy(
    service_fixture, monkeypatch
):
    service, _, store, _, _, credential, _ = service_fixture
    telemetry = valid_telemetry()
    original_copy = service_module._copy_dict_items
    observed_copy_sizes = []

    def mutate_then_copy(value, maximum):
        value.update({f"extra-{index}": 0 for index in range(10_000)})
        copied = original_copy(value, maximum)
        observed_copy_sizes.append(len(copied))
        return copied

    monkeypatch.setattr(service_module, "_copy_dict_items", mutate_then_copy)
    response = evaluate(service, credential, telemetry=telemetry)

    assert response.reason is ServiceReason.INVALID_REQUEST
    assert len(telemetry) == 10_006
    assert observed_copy_sizes == [7]
    assert store._ledgers == {}


def test_snapshot_rejects_effect_list_growth_after_size_check(service_fixture, monkeypatch):
    service, _, store, _, _, credential, _ = service_fixture
    effects = []
    original_copy = service_module._copy_list_items
    observed_copy_sizes = []

    def mutate_then_copy(value, maximum):
        value.extend(["unknown-effect"] * 10_000)
        copied = original_copy(value, maximum)
        observed_copy_sizes.append(len(copied))
        return copied

    monkeypatch.setattr(service_module, "_copy_list_items", mutate_then_copy)
    response = evaluate(service, credential, reported_effects=effects)

    assert response.reason is ServiceReason.INVALID_REQUEST
    assert len(effects) == 10_000
    assert observed_copy_sizes == [len(service_module.AUTHORITY_EXPANSION_EFFECTS) + 1]
    assert store._ledgers == {}


def test_invalid_expired_and_revoked_credentials_deny(service_fixture):
    service, _, store, keys, issued, credential, now = service_fixture
    invalid = evaluate(service, "not-a-customer-key")
    assert invalid.reason is ServiceReason.AUTHORIZATION_DENIED
    now[0] = float(timestamp(2030, 1))
    expired = evaluate(service, credential, "expired")
    assert expired.reason is ServiceReason.AUTHORIZATION_DENIED
    now[0] = timestamp(2026, 10)
    assert keys.revoke(issued.key_id)
    revoked = evaluate(service, credential, "revoked")
    assert revoked.reason is ServiceReason.AUTHORIZATION_DENIED
    assert store._ledgers == {}


def test_cross_tenant_resource_and_missing_capability_deny(service_fixture):
    service, _, store, keys, _, credential, _ = service_fixture

    response = evaluate(service, credential, resource_id="project-b")

    assert response.reason is ServiceReason.AUTHORIZATION_DENIED
    assert store._ledgers == {}

    limited_key = keys.issue(
        principal_id="customer-a",
        tenant_id="tenant-a",
        capabilities=frozenset({CommercialCapability.READ_USAGE}),
        expires_at=int(timestamp(2030, 1)),
    )
    missing_capability = evaluate(service, limited_key.take_secret(), "no-evaluate")
    assert missing_capability.reason is ServiceReason.AUTHORIZATION_DENIED
    assert store._ledgers == {}


def test_exhausted_missing_policy_and_clock_rollback_deny(service_fixture):
    service, _, store, _, _, credential, now = service_fixture
    del store._allowances["tenant-a"]
    missing = evaluate(service, credential, "missing-policy")
    assert missing.reason is ServiceReason.QUOTA_DENIED
    assert store._ledgers == {}

    store._allowances["tenant-a"] = 0
    assert evaluate(service, credential).reason is ServiceReason.QUOTA_DENIED
    assert store._ledgers["tenant-a"].counts == {}
    assert store._ledgers["tenant-a"].reservations == {}

    store._allowances["tenant-a"] = 10
    assert evaluate(service, credential, "first").outcome is ServiceOutcome.EVALUATED
    with patch.object(store, "_clock", return_value=now[0] - 1):
        rollback = evaluate(service, credential, "rollback")
    assert rollback.reason is ServiceReason.QUOTA_DENIED
    assert store._ledgers["tenant-a"].counts["2026-10"] == 1


def test_month_rollover_keeps_prior_charge_and_allows_new_request(service_fixture):
    service, _, store, _, _, credential, now = service_fixture
    assert evaluate(service, credential, "october").outcome is ServiceOutcome.EVALUATED
    now[0] = timestamp(2026, 11)

    response = evaluate(service, credential, "november")

    assert response.outcome is ServiceOutcome.EVALUATED
    assert store._ledgers["tenant-a"].counts == {"2026-10": 1, "2026-11": 1}


def test_replayed_request_with_changed_payload_never_evaluates_again(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture
    calls = [0]

    def evaluator(request):
        calls[0] += 1
        return evaluate_request(request)

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    first = evaluate(service, credential, telemetry=valid_telemetry(token_delta=10))
    replay = evaluate(service, credential, telemetry=valid_telemetry(token_delta=999))

    assert first.outcome is ServiceOutcome.EVALUATED
    assert replay.reason is ServiceReason.REPLAY
    assert replay.evaluation is None
    assert calls == [1]
    assert store._ledgers["tenant-a"].counts["2026-10"] == 1


def test_duplicate_ids_and_concurrent_requests_evaluate_once(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture
    calls = [0]
    lock = Lock()

    def evaluator(request):
        with lock:
            calls[0] += 1
        return EvaluationResult(
            "gvai-evaluation-v1", request["request_id"], "ALLOW", 1.0, "green",
            "advisory", "ok",
        )

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: evaluate(service, credential), range(48)))

    assert calls == [1]
    assert sum(response.outcome is ServiceOutcome.EVALUATED for response in responses) == 1
    assert sum(response.reason is ServiceReason.REPLAY for response in responses) == 47
    assert store._ledgers["tenant-a"].counts["2026-10"] == 1


def test_distinct_concurrent_ids_cannot_exceed_quota(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture
    store._allowances["tenant-a"] = 3
    calls = [0]
    lock = Lock()

    def evaluator(request):
        with lock:
            calls[0] += 1
        return EvaluationResult(
            "gvai-evaluation-v1", request["request_id"], "ALLOW", 1.0, "green",
            "advisory", "ok",
        )

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(
            pool.map(lambda number: evaluate(service, credential, f"request-{number}"), range(30))
        )

    assert calls == [3]
    assert sum(response.outcome is ServiceOutcome.EVALUATED for response in responses) == 3
    assert sum(response.reason is ServiceReason.QUOTA_DENIED for response in responses) == 27
    assert store._ledgers["tenant-a"].counts["2026-10"] == 3


def test_evaluator_failure_is_marked_failed_and_replay_never_reexecutes(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture
    calls = [0]

    def evaluator(_request):
        calls[0] += 1
        raise RuntimeError("credential must not escape")

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    first = evaluate(service, credential)
    retry = evaluate(service, credential)

    assert first.reason is ServiceReason.EVALUATION_FAILURE
    assert first.evaluation is None
    assert retry.reason is ServiceReason.REPLAY
    assert calls == [1]
    assert store._ledgers["tenant-a"].reservations
    reservation = next(iter(store._ledgers["tenant-a"].reservations.values()))
    assert reservation.state.value == "failed"


def test_evaluator_error_result_is_completed_as_failed(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture

    def evaluator(request):
        return EvaluationResult(
            "gvai-evaluation-v1", request["request_id"], "BLOCK", None, None,
            "Evaluation failed; do not proceed.", "error",
        )

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    response = evaluate(service, credential)

    assert response.outcome is ServiceOutcome.ERROR
    assert response.reason is ServiceReason.EVALUATION_FAILURE
    assert response.evaluation is None
    reservation = next(iter(store._ledgers["tenant-a"].reservations.values()))
    assert reservation.state.value == "failed"


@pytest.mark.parametrize(
    "changes",
    [
        {"version": "wrong-version"},
        {"decision": "EXECUTE"},
        {"risk_score": float("nan")},
        {"risk_score": float("inf")},
        {"risk_score": 100.1},
        {"risk_band": "violet"},
        {"risk_band": "yellow"},
        {"decision": "BLOCK"},
        {"request_id": "other-request"},
        {"advisory_only": False},
        {"enforcement_applied": True},
        {"evaluation_status": "unknown"},
        {"evaluation_status": "error", "risk_score": 1.0, "risk_band": "green"},
    ],
)
def test_malformed_evaluator_results_fail_and_consume_once(service_fixture, changes):
    _, usage, store, _, _, credential, _ = service_fixture
    calls = [0]

    def evaluator(request):
        calls[0] += 1
        valid_result = evaluate_request(request)
        return replace(valid_result, **changes)

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    response = evaluate(service, credential)
    replay = evaluate(service, credential)

    assert response.outcome is ServiceOutcome.ERROR
    assert response.reason is ServiceReason.EVALUATION_FAILURE
    assert response.evaluation is None
    assert replay.reason is ServiceReason.REPLAY
    assert calls == [1]
    assert store._ledgers["tenant-a"].counts["2026-10"] == 1
    reservation = next(iter(store._ledgers["tenant-a"].reservations.values()))
    assert reservation.state.value == "failed"


def test_inconsistent_decision_mapping_with_reported_effect_is_rejected(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture

    def evaluator(request):
        result = evaluate_request(request)
        return replace(result, decision="ALLOW")

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    response = evaluate(
        service, credential, reported_effects=["tampers_control_plane"]
    )

    assert response.reason is ServiceReason.EVALUATION_FAILURE
    assert response.evaluation is None
    reservation = next(iter(store._ledgers["tenant-a"].reservations.values()))
    assert reservation.state.value == "failed"


def test_evaluator_cannot_mutate_effects_used_for_result_validation(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture

    def evaluator(request):
        request["reported_effects"].clear()
        return evaluate_request(request)

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    response = evaluate(
        service, credential, reported_effects=["tampers_control_plane"]
    )

    assert response.reason is ServiceReason.EVALUATION_FAILURE
    assert response.evaluation is None
    reservation = next(iter(store._ledgers["tenant-a"].reservations.values()))
    assert reservation.state.value == "failed"


def test_accounting_failures_deny_and_do_not_leak_credentials(service_fixture):
    _, usage, store, _, _, credential, _ = service_fixture
    from unittest.mock import Mock

    evaluator = Mock()
    service = CommercialEvaluationService(usage, evaluator=evaluator)
    with patch.object(store, "_apply", side_effect=RuntimeError(credential)):
        response = evaluate(service, credential)

    assert response.outcome is ServiceOutcome.ERROR
    assert response.reason is ServiceReason.ACCOUNTING_FAILURE
    assert credential not in repr(response)
    evaluator.assert_not_called()

    _, usage, store, _, _, credential, _ = service_fixture
    original_apply = store._apply

    def fail_completion(tenant_id, resource_id, request_id, operation):
        if operation == "completed":
            raise RuntimeError(credential)
        return original_apply(tenant_id, resource_id, request_id, operation)

    calls = [0]

    def evaluator(request):
        calls[0] += 1
        return EvaluationResult(
            "gvai-evaluation-v1", request["request_id"], "ALLOW", 1.0, "green",
            "advisory", "ok",
        )

    service = CommercialEvaluationService(usage, evaluator=evaluator)
    with patch.object(store, "_apply", side_effect=fail_completion):
        response = evaluate(service, credential)
    replay = evaluate(service, credential)
    assert response.reason is ServiceReason.ACCOUNTING_FAILURE
    assert replay.reason is ServiceReason.REPLAY
    assert calls == [1]
    assert credential not in repr(response) + repr(replay)


def test_revocation_after_reservation_does_not_cancel_in_flight_attempt(service_fixture):
    _, usage, store, keys, issued, credential, _ = service_fixture
    evaluations = []

    class RevokeAfterReserve:
        def reserve(self, *args):
            reservation = usage.reserve(*args)
            assert keys.revoke(issued.key_id)
            return reservation

        def complete(self, *args, **kwargs):
            return usage.complete(*args, **kwargs)

    def evaluator(request):
        evaluations.append(request["request_id"])
        return evaluate_request(request)

    service = CommercialEvaluationService(RevokeAfterReserve(), evaluator=evaluator)
    response = evaluate(service, credential)

    assert response.reason is ServiceReason.AUTHORIZATION_DENIED
    assert response.evaluation is None
    assert evaluations == ["request-1"]
    ledger = store._ledgers["tenant-a"]
    assert ledger.counts["2026-10"] == 1
    reservation = next(iter(ledger.reservations.values()))
    assert reservation.state.value == "reserved"


def test_api_does_not_accept_caller_tenant_or_role_claims(service_fixture):
    service, _, _, _, _, credential, _ = service_fixture

    with pytest.raises(TypeError):
        service.evaluate(
            credential,
            "project-a",
            "request-1",
            valid_telemetry(),
            [],
            tenant_id="tenant-b",
            roles=["admin"],
        )


def test_supervisor_stop_isolation_and_secret_redaction(service_fixture, caplog, capsys):
    service, _, _, _, _, credential, _ = service_fixture
    from gvai.external_control import GVExternalControlPlane
    from gvai.runtime_policy import GVRuntimePolicy

    with (
        patch.object(
            GVExternalControlPlane,
            "evaluate_internal_shutdown",
            side_effect=AssertionError("must not call STOP"),
        ) as stop,
        patch.object(
            GVExternalControlPlane,
            "evaluate_command",
            side_effect=AssertionError("must not call supervisor command"),
        ) as external_command,
        patch.object(
            GVRuntimePolicy,
            "evaluate_command",
            side_effect=AssertionError("must not call control"),
        ) as command,
        patch.object(
            GVRuntimePolicy,
            "evaluate_internal_shutdown",
            side_effect=AssertionError("must not call supervisor STOP"),
        ) as runtime_stop,
    ):
        response = evaluate(service, credential)

    captured = capsys.readouterr()
    assert response.outcome is ServiceOutcome.EVALUATED
    assert stop.call_count == external_command.call_count == command.call_count == 0
    assert runtime_stop.call_count == 0
    assert credential not in repr(response) + caplog.text + captured.out + captured.err
