from dataclasses import FrozenInstanceError, replace
from itertools import permutations
from pathlib import Path
import socket
import subprocess

import pytest

from gvai.approval_lifecycle_model import (
    Context, ModelResult, ModelState, SyntheticRequest, transition,
)


NOW = 1000
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("Lifecycle scenarios cannot use network or processes.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(socket, "getaddrinfo", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)


@pytest.fixture
def state():
    return ModelState(Context(
        domain="synthetic-execution", supervisor="synthetic-supervisor",
        environment="offline", tenant="synthetic-tenant", boot=1,
        workload_digest="1" * 64, action_digest="2" * 64, effects=("effect:a",),
        policy_digest="3" * 64, policy_epoch=1, grants_epoch=1,
        observation_digest="4" * 64,
    ), NOW)


@pytest.fixture
def scenario(state):
    return SyntheticRequest(
        issuer="synthetic-issuer", principal="synthetic-human", scope=("scope:a",),
        decision="synthetic-decision", approval_id="synthetic-approval",
        challenge="synthetic-challenge", context=state.context,
        issued_at=NOW, not_before=NOW, expires_at=NOW + 60,
    )


def step(state, event, *, now=NOW, **kwargs):
    result = transition(state, event, now=now, **kwargs)
    assert type(result) is ModelResult
    assert result.allowed is False
    assert result.authenticated is False
    assert not result
    assert result.state.consumed >= state.consumed
    assert result.state.challenges >= state.challenges
    assert not state.stopped or result.state.stopped
    assert not state.uncertain or result.state.uncertain
    return result.state


def assert_no_consumption(state):
    assert not state.consumed
    assert not state.challenges
    assert not state.attempts


def test_modeled_completion_is_immutable_and_never_authority(state, scenario):
    request = scenario
    running = step(state, "attempt", request=request)
    assert len(running.consumed) == len(running.challenges) == 1
    assert running.attempts[0].phase == "modeled_running"
    completed = step(running, "complete", request=request)
    assert completed.attempts[0].phase == "modeled_complete"
    assert step(completed, "complete", request=request) == completed
    assert_no_consumption(state)
    with pytest.raises(FrozenInstanceError):
        completed.stopped = False


def test_replay_before_and_after_completion(state, scenario):
    request = scenario
    running = step(state, "attempt", request=request)
    for base in (running, step(running, "complete", request=request)):
        assert step(base, "attempt", request=request) == base
        assert len(base.consumed) == 1


@pytest.mark.parametrize("different_issuer", [False, True])
def test_challenge_reuse_with_different_approval(state, scenario, different_issuer):
    request = scenario
    running = step(state, "attempt", request=request)
    other = replace(request, approval_id="synthetic-other",
                    issuer="other-issuer" if different_issuer else request.issuer)
    assert step(running, "attempt", request=other) == running


def test_consumption_id_cannot_be_reused_with_new_challenge(state, scenario):
    request = scenario
    running = step(state, "attempt", request=request)
    assert step(running, "attempt", request=replace(request, challenge="other")) == running


def test_serialized_duplicate_attempt_orderings(state, scenario):
    request = scenario
    requests = (request, replace(request, approval_id="other"))
    for order in permutations(requests):
        current = state
        for item in order:
            current = step(current, "attempt", request=item)
        assert len(current.consumed) == len(current.attempts) == 1
        assert current.attempts[0].request == order[0]


@pytest.mark.parametrize("event", ["shutdown", "revoke"])
@pytest.mark.parametrize("control_first", [False, True])
def test_stop_and_revocation_race_orderings(state, scenario, event, control_first):
    request = scenario
    if control_first:
        current = step(state, event, request=request)
        current = step(current, "attempt", request=request)
        assert_no_consumption(current)
    else:
        current = step(state, "attempt", request=request)
        current = step(current, event, request=request)
        assert current.attempts[0].phase == "cancel_required"
        assert step(current, "complete", request=request) == current
        assert len(current.consumed) == 1


@pytest.mark.parametrize("event", ["shutdown", "revoke", "context_change"])
def test_completion_and_control_both_orderings(state, scenario, event):
    request = scenario
    changed = replace(state.context, policy_epoch=2, policy_digest="a" * 64)
    for order in permutations(("complete", event)):
        current = step(state, "attempt", request=request)
        for item in order:
            current = step(current, item, request=request, context=changed)
        expected = "modeled_complete" if order[0] == "complete" else "cancel_required"
        assert current.attempts[0].phase == expected


@pytest.mark.parametrize("offset", [59, 60, 61])
def test_exact_expiry_blocks_consumption_and_completion(state, scenario, offset):
    request = scenario
    time = NOW + offset
    attempted = step(state, "attempt", request=request, now=time)
    running = step(state, "attempt", request=request)
    completed = step(running, "complete", request=request, now=time)
    if offset == 59:
        assert len(attempted.consumed) == 1
        assert completed.attempts[0].phase == "modeled_complete"
    else:
        assert_no_consumption(attempted)
        assert completed.attempts[0].phase == "cancel_required"


def test_tick_expiry_does_not_need_completion_request(state, scenario):
    request = scenario
    running = step(state, "attempt", request=request)
    expired = step(running, "tick", now=NOW + 60)
    assert expired.attempts[0].phase == "cancel_required"


@pytest.mark.parametrize("field,value", [
    ("issued_at", NOW + 1), ("issued_at", NOW - 1),
    ("not_before", NOW + 1), ("not_before", NOW - 1),
    ("expires_at", NOW), ("expires_at", NOW + 61),
    ("issued_at", True), ("not_before", None), ("expires_at", float("nan")),
    ("issuer", ""), ("principal", "*"), ("decision", ""),
    ("scope", ()), ("scope", ("b", "a")), ("scope", ("a", "a")),
    ("approval_id", None), ("challenge", {}),
])
def test_malformed_or_invalid_request_never_consumes(state, scenario, field, value):
    request = scenario
    current = step(state, "attempt", request=replace(request, **{field: value}))
    assert_no_consumption(current)
    assert not current.stopped


@pytest.mark.parametrize("field,value", [
    ("domain", "other"), ("supervisor", "other"), ("environment", "other"),
    ("tenant", "other"), ("boot", 2), ("workload_digest", "a" * 64),
    ("action_digest", "a" * 64), ("effects", ("other",)),
    ("policy_digest", "a" * 64), ("policy_epoch", 2), ("grants_epoch", 2),
    ("observation_digest", "a" * 64), ("revocation_generation", 1),
    ("shutdown_generation", 1),
])
def test_every_context_binding_rejects_substitution(state, scenario, field, value):
    request = scenario
    other = replace(request, context=replace(request.context, **{field: value}))
    assert_no_consumption(step(state, "attempt", request=other))


@pytest.mark.parametrize("field,value", [
    ("workload_digest", "a" * 64), ("action_digest", "a" * 64),
    ("effects", ("other",)), ("policy_digest", "a" * 64), ("grants_epoch", 2),
    ("observation_digest", "a" * 64),
])
def test_context_changes_invalidate_pending_and_running(state, scenario, field, value):
    request = scenario
    context = replace(state.context, policy_epoch=2, **{field: value})
    changed = step(state, "context_change", context=context)
    assert_no_consumption(step(changed, "attempt", request=request))
    running = step(state, "attempt", request=request)
    changed = step(running, "context_change", context=context)
    assert changed.attempts[0].phase == "cancel_required"
    assert step(changed, "complete", request=request) == changed


def test_policy_a_b_a_cannot_revive_old_request(state, scenario):
    request = scenario
    current = step(state, "context_change",
                   context=replace(state.context, policy_epoch=2, policy_digest="a" * 64))
    current = step(current, "context_change",
                   context=replace(state.context, policy_epoch=3))
    assert_no_consumption(step(current, "attempt", request=request))
    assert step(current, "context_change", context=state.context).uncertain


@pytest.mark.parametrize("event", [
    "verifier_unavailable", "store_unavailable", "audit_unavailable",
    "crash", "cancellation_uncertain",
])
@pytest.mark.parametrize("running_first", [False, True])
def test_dependency_failure_and_crash_latch_uncertainty(state, scenario, event, running_first):
    request = scenario
    current = step(state, "attempt", request=request) if running_first else state
    current = step(current, event)
    assert current.uncertain
    assert step(current, "attempt", request=request) == current
    assert step(current, "complete", request=request) == current
    if running_first:
        assert current.attempts[0].phase == "cancel_required"
    else:
        assert_no_consumption(current)


@pytest.mark.parametrize("now", [NOW - 1, None, True, float("nan"), 2**63])
def test_untrustworthy_time_blocks_until_independent_recovery(state, scenario, now):
    request = scenario
    running = step(state, "attempt", request=request)
    uncertain = step(running, "tick", now=now)
    assert uncertain.uncertain
    assert uncertain.now == NOW
    assert uncertain.attempts[0].phase == "cancel_required"
    assert step(uncertain, "attempt", request=request, now=NOW + 1).uncertain


@pytest.mark.parametrize("stop_first", [False, True])
def test_restart_preserves_tombstones_and_stop_latch(state, scenario, stop_first):
    request = scenario
    current = step(state, "attempt", request=request)
    if stop_first:
        current = step(current, "shutdown")
    crashed = step(current, "crash")
    restarted = step(crashed, "restart")
    assert restarted.consumed == current.consumed
    assert restarted.challenges == current.challenges
    assert restarted.context.boot == state.context.boot + 1
    assert restarted.stopped == stop_first
    assert restarted.uncertain
    assert step(restarted, "attempt", request=request) == restarted
    fresh = replace(request, approval_id="fresh", challenge="fresh", context=restarted.context)
    assert step(restarted, "attempt", request=fresh) == restarted


def test_stop_cannot_be_cleared_by_new_context_or_unknown_event(state, scenario):
    request = scenario
    stopped = step(state, "shutdown")
    for event in ("unstop", "recover", "attempt", "complete"):
        assert step(stopped, event, request=request).stopped
    changed = step(stopped, "context_change", context=replace(state.context, policy_epoch=2))
    assert changed.stopped and changed.uncertain


@pytest.mark.parametrize("now", [NOW - 1, None, True])
def test_independent_stop_latches_even_when_time_is_uncertain(state, scenario, now):
    running = step(state, "attempt", request=scenario)
    stopped = step(running, "shutdown", now=now)
    assert stopped.stopped and stopped.uncertain
    assert stopped.context.shutdown_generation == 1
    assert stopped.attempts[0].phase == "cancel_required"


def test_request_identity_substitution_cannot_complete_attempt(state, scenario):
    running = step(state, "attempt", request=scenario)
    for changes in (
        {"issuer": "other"}, {"principal": "other"}, {"scope": ("other",)},
        {"decision": "other"}, {"approval_id": "other"}, {"challenge": "other"},
        {"expires_at": NOW + 59},
    ):
        assert step(running, "complete", request=replace(scenario, **changes)) == running


def test_distinct_attempts_complete_without_deleting_replay_history(state, scenario):
    other = replace(scenario, approval_id="other", challenge="other")
    running = step(step(state, "attempt", request=scenario), "attempt", request=other)
    assert len(running.consumed) == len(running.challenges) == 2
    completed = step(step(running, "complete", request=scenario), "complete", request=other)
    assert all(item.phase == "modeled_complete" for item in completed.attempts)
    assert completed.consumed == running.consumed


@pytest.mark.parametrize("field,value", [
    ("domain", "other"), ("supervisor", "other"), ("environment", "other"),
    ("tenant", "other"), ("boot", 0), ("revocation_generation", 1),
    ("shutdown_generation", 1), ("grants_epoch", 0), ("policy_epoch", 1),
])
def test_context_update_cannot_reset_lifecycle_identity(state, scenario, field, value):
    changes = {"policy_epoch": 2, field: value}
    current = step(state, "context_change", context=replace(state.context, **changes))
    assert current.uncertain
    assert_no_consumption(step(current, "attempt", request=scenario))


def test_revocation_persists_across_context_update(state, scenario):
    request = scenario
    revoked = step(state, "revoke", request=request)
    changed = step(revoked, "context_change",
                   context=replace(revoked.context, policy_epoch=2))
    fresh_context = replace(request, context=changed.context)
    assert_no_consumption(step(changed, "attempt", request=fresh_context))
    assert changed.revoked == revoked.revoked


@pytest.mark.parametrize("value", [None, {}, {"approved": True}, "READY", True])
def test_no_registry_or_verifier_result_entry_point(state, value):
    assert_no_consumption(step(state, "attempt", request=value))
    assert step(state, "revoke", request=value).uncertain


def test_no_runtime_callers_or_credential_imports():
    module = ROOT / "gvai/approval_lifecycle_model.py"
    for directory in (ROOT / "gvai", ROOT / "scripts"):
        for path in directory.rglob("*.py"):
            if path != module:
                assert "approval_lifecycle_model" not in path.read_text(encoding="utf-8")
    source = module.read_text(encoding="utf-8")
    for name in ("subprocess", "socket", "external_commands", "execution_approval_envelope"):
        assert name not in source
