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
    if event == "start":
        # Legacy running-state scenarios now traverse all three explicit stages.
        reserved = step(state, "reserve", now=now, **kwargs)
        if len(reserved.attempts) == len(state.attempts):
            return reserved
        sent = step(reserved, "dispatch", now=now, **kwargs)
        return step(sent, "dispatch_ack", now=now, **kwargs)
    if event in ("dispatch", "dispatch_ack", "complete", "promote", "cancel_ack"):
        kwargs.setdefault("fence", state.fence)
    if event in ("complete", "promote"):
        kwargs.setdefault("output_digest", "a" * 64)
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
    running = step(state, "start", request=request)
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
    running = step(state, "start", request=request)
    for base in (running, step(running, "complete", request=request)):
        assert step(base, "attempt", request=request) == base
        assert len(base.consumed) == 1


@pytest.mark.parametrize("different_issuer", [False, True])
def test_challenge_reuse_with_different_approval(state, scenario, different_issuer):
    request = scenario
    running = step(state, "start", request=request)
    other = replace(request, approval_id="synthetic-other",
                    issuer="other-issuer" if different_issuer else request.issuer)
    assert step(running, "attempt", request=other) == running


def test_consumption_id_cannot_be_reused_with_new_challenge(state, scenario):
    request = scenario
    running = step(state, "start", request=request)
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
        current = step(state, "start", request=request)
        current = step(current, event, request=request)
        assert current.attempts[0].phase == "cancel_required"
        assert step(current, "complete", request=request) == current
        assert len(current.consumed) == 1


@pytest.mark.parametrize("event", ["shutdown", "revoke", "context_change"])
def test_completion_and_control_both_orderings(state, scenario, event):
    request = scenario
    changed = replace(state.context, policy_epoch=2, policy_digest="a" * 64)
    for order in permutations(("complete", event)):
        current = step(state, "start", request=request)
        for item in order:
            current = step(current, item, request=request, context=changed)
        expected = "invalidated" if order[0] == "complete" else "cancel_required"
        assert current.attempts[0].phase == expected


@pytest.mark.parametrize("offset", [59, 60, 61])
def test_exact_expiry_blocks_consumption_and_completion(state, scenario, offset):
    request = scenario
    time = NOW + offset
    attempted = step(state, "attempt", request=request, now=time)
    running = step(state, "start", request=request)
    completed = step(running, "complete", request=request, now=time)
    if offset == 59:
        assert len(attempted.consumed) == 1
        assert completed.attempts[0].phase == "modeled_complete"
    else:
        assert_no_consumption(attempted)
        assert completed.attempts[0].phase == "cancel_required"


def test_tick_expiry_does_not_need_completion_request(state, scenario):
    request = scenario
    running = step(state, "start", request=request)
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
    running = step(state, "start", request=request)
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
    current = step(state, "start", request=request) if running_first else state
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
    running = step(state, "start", request=request)
    uncertain = step(running, "tick", now=now)
    assert uncertain.uncertain
    assert uncertain.now == NOW
    assert uncertain.attempts[0].phase == "cancel_required"
    assert step(uncertain, "attempt", request=request, now=NOW + 1).uncertain


@pytest.mark.parametrize("stop_first", [False, True])
def test_restart_preserves_tombstones_and_stop_latch(state, scenario, stop_first):
    request = scenario
    current = step(state, "start", request=request)
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
    running = step(state, "start", request=scenario)
    stopped = step(running, "shutdown", now=now)
    assert stopped.stopped and stopped.uncertain
    assert stopped.context.shutdown_generation == 1
    assert stopped.attempts[0].phase == "cancel_required"


def test_request_identity_substitution_cannot_complete_attempt(state, scenario):
    running = step(state, "start", request=scenario)
    for changes in (
        {"issuer": "other"}, {"principal": "other"}, {"scope": ("other",)},
        {"decision": "other"}, {"approval_id": "other"}, {"challenge": "other"},
        {"expires_at": NOW + 59},
    ):
        assert step(running, "complete", request=replace(scenario, **changes)) == running


def test_distinct_attempts_complete_without_deleting_replay_history(state, scenario):
    other = replace(scenario, approval_id="other", challenge="other")
    running = step(step(state, "start", request=scenario), "start", request=other)
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


STAGES = ("reserve", "dispatch", "dispatch_ack", "complete", "promote")
PHASES = ("reserved", "dispatch_pending", "modeled_running",
          "modeled_complete", "modeled_promoted")


def prefix(state, scenario, length):
    for event in STAGES[:length]:
        state = step(state, event, request=scenario, fence=0)
    if length:
        assert state.attempts[0].phase == PHASES[length - 1]
        assert state.attempts[0].dispatch_count == int(length >= 2)
    return state


def invalidate(state, scenario, control):
    if control == "expiry":
        return step(state, "tick", now=NOW + 60)
    if control == "rollback":
        return step(state, "tick", now=NOW - 1)
    return step(
        state, control, request=scenario,
        context=replace(state.context, policy_epoch=state.context.policy_epoch + 1,
                        policy_digest="b" * 64),
    )


@pytest.mark.parametrize("stage_index", range(len(STAGES)))
@pytest.mark.parametrize("control", [
    "shutdown", "revoke", "context_change", "expiry", "rollback",
    "verifier_unavailable", "store_unavailable", "audit_unavailable",
])
@pytest.mark.parametrize("control_first", [False, True])
def test_control_order_at_every_forward_boundary(state, scenario, stage_index, control, control_first):
    current = prefix(state, scenario, stage_index)
    original_count = sum(item.dispatch_count for item in current.attempts)
    event = STAGES[stage_index]
    if control_first:
        current = invalidate(current, scenario, control)
        before = current
        current = step(current, event, now=current.now, request=scenario, fence=0)
        assert current == before
        assert not any(item.phase == "modeled_promoted" for item in current.attempts)
        assert sum(item.dispatch_count for item in current.attempts) == original_count
    else:
        current = step(current, event, request=scenario, fence=0)
        assert current.attempts[0].phase == PHASES[stage_index]
        current = invalidate(current, scenario, control)
        if event == "promote":
            # A preceding modeled promotion remains historical, not new authority.
            assert current.attempts[0].phase == "modeled_promoted"
        else:
            expected = "cancel_required" if stage_index in (1, 2) else "invalidated"
            assert current.attempts[0].phase == expected
        before = current
        for next_event in STAGES:
            current = step(current, next_event, now=current.now, request=scenario, fence=0)
        assert current == before
    assert sum(item.dispatch_count for item in current.attempts) <= 1
    if stage_index or not control_first:
        assert len(current.consumed) == len(current.challenges) == 1


@pytest.mark.parametrize("cut", range(len(STAGES) + 1))
def test_crash_cuts_never_retry_dispatch_or_infer_success(state, scenario, cut):
    before = prefix(state, scenario, cut)
    current = step(before, "crash")
    current = step(current, "restart")
    assert current.uncertain
    assert current.consumed == before.consumed
    assert current.challenges == before.challenges
    assert [item.dispatch_count for item in current.attempts] == [
        item.dispatch_count for item in before.attempts
    ]
    assert [item.output_digest for item in current.attempts] == [
        item.output_digest for item in before.attempts
    ]
    if cut:
        phase = (
            "modeled_promoted" if cut == 5 else
            "cancel_required" if cut in (2, 3) else "invalidated"
        )
        assert current.attempts[0].phase == phase
    blocked = current
    for event in STAGES:
        current = step(current, event, request=scenario, fence=0)
        fresh = replace(scenario, approval_id="fresh", challenge="fresh", context=current.context)
        current = step(current, event, request=fresh, fence=current.fence)
    assert current == blocked


@pytest.mark.parametrize("control", ["shutdown", "revoke", "context_change", "expiry", "crash"])
@pytest.mark.parametrize("cut", [2, 3])
def test_cancel_ack_records_termination_without_recovery(state, scenario, control, cut):
    current = invalidate(prefix(state, scenario, cut), scenario, control)
    assert current.attempts[0].phase == "cancel_required"
    assert step(current, "cancel_ack", now=current.now, request=scenario, fence=current.fence) == current
    acknowledged = step(current, "cancel_ack", now=current.now, request=scenario, fence=0)
    assert acknowledged.attempts[0].phase == "modeled_cancelled"
    assert acknowledged.stopped == current.stopped
    assert acknowledged.uncertain == current.uncertain
    assert acknowledged.consumed == current.consumed
    assert step(acknowledged, "cancel_ack", now=current.now, request=scenario, fence=0) == acknowledged
    for event in STAGES:
        assert step(acknowledged, event, now=current.now, request=scenario, fence=0) == acknowledged


@pytest.mark.parametrize("event", STAGES[1:])
@pytest.mark.parametrize("bad_fence", [None, True, -1, 1, "0"])
def test_forward_stages_require_exact_typed_fence(state, scenario, event, bad_fence):
    current = prefix(state, scenario, STAGES.index(event))
    assert step(current, event, request=scenario, fence=bad_fence) == current


@pytest.mark.parametrize("prefix_length", range(len(STAGES) + 1))
def test_duplicate_and_out_of_order_events_cannot_skip_stages(state, scenario, prefix_length):
    current = prefix(state, scenario, prefix_length)
    for event in STAGES:
        if prefix_length < len(STAGES) and event == STAGES[prefix_length]:
            continue
        assert step(current, event, request=scenario, fence=0) == current
    if prefix_length:
        other = replace(scenario, approval_id="other")
        assert step(current, "reserve", request=other) == current
        reused_id = replace(scenario, challenge="other")
        assert step(current, "reserve", request=reused_id) == current


@pytest.mark.parametrize("digest", [None, "", "A" * 64, "a" * 63, True])
def test_completion_requires_output_identity(state, scenario, digest):
    current = prefix(state, scenario, 3)
    assert step(current, "complete", request=scenario, output_digest=digest) == current


def test_promotion_requires_exact_completion_artifact(state, scenario):
    completed = prefix(state, scenario, 4)
    for digest in (None, "b" * 64, True):
        assert step(completed, "promote", request=scenario, output_digest=digest) == completed
    promoted = step(completed, "promote", request=scenario)
    assert promoted.attempts[0].phase == "modeled_promoted"
    assert promoted.attempts[0].output_digest == "a" * 64


def test_completed_artifact_retained_but_fenced_after_stop(state, scenario):
    completed = prefix(state, scenario, 4)
    stopped = step(completed, "shutdown")
    assert stopped.fence > completed.fence
    assert stopped.attempts[0].phase == "invalidated"
    assert stopped.attempts[0].output_digest == "a" * 64
    assert step(stopped, "promote", request=scenario, fence=0) == stopped


def test_old_fence_cannot_dispatch_a_fresh_request(state, scenario):
    changed = step(state, "context_change", context=replace(state.context, policy_epoch=2))
    fresh = replace(scenario, context=changed.context)
    reserved = step(changed, "reserve", request=fresh)
    assert reserved.attempts[0].fence == changed.fence == 1
    assert step(reserved, "dispatch", request=fresh, fence=0) == reserved
    dispatched = step(reserved, "dispatch", request=fresh, fence=1)
    assert dispatched.attempts[0].dispatch_count == 1


def test_cancel_ack_cannot_substitute_another_attempt(state, scenario):
    current = step(prefix(state, scenario, 2), "shutdown")
    other = replace(scenario, approval_id="other")
    assert step(current, "cancel_ack", request=other, fence=0) == current


def test_attempt_compatibility_spelling_only_reserves(state, scenario):
    reserved = step(state, "attempt", request=scenario)
    assert reserved.attempts[0].phase == "reserved"
    assert reserved.attempts[0].dispatch_count == 0
    assert step(reserved, "complete", request=scenario) == reserved


def test_bounded_two_consumer_interleavings_dispatch_at_most_once(state, scenario):
    operations = tuple((consumer, index) for consumer in ("a", "b") for index in range(3))
    trace_count = 0
    for order in permutations(operations):
        if any(
            [index for name, index in order if name == consumer] != [0, 1, 2]
            for consumer in ("a", "b")
        ):
            continue
        trace_count += 1
        current = state
        for _, index in order:
            current = step(current, STAGES[index], request=scenario, fence=0)
            assert len(current.consumed) == len(current.challenges) == 1
            assert len(current.attempts) == 1
            assert current.attempts[0].dispatch_count <= 1
        assert current.attempts[0].phase == "modeled_running"
        assert current.attempts[0].dispatch_count == 1
    assert trace_count == 20


def test_acknowledgement_after_stop_cannot_become_completion_evidence(state, scenario):
    pending = prefix(state, scenario, 2)
    stopped = step(pending, "shutdown")
    for event in ("dispatch_ack", "complete", "promote"):
        assert step(stopped, event, request=scenario, fence=0) == stopped
    assert stopped.attempts[0].output_digest is None


def test_crash_cannot_erase_a_fenced_completion_record(state, scenario):
    completed = prefix(state, scenario, 4)
    crashed = step(completed, "crash")
    acknowledged = step(crashed, "cancel_ack", request=scenario, fence=0)
    assert acknowledged == crashed
    assert crashed.attempts[0].phase == "invalidated"
    assert crashed.attempts[0].output_digest == "a" * 64
    assert crashed.attempts[0].dispatch_count == 1
