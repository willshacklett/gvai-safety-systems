"""Offline cross-component conformance, not an execution integration adapter."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
from types import SimpleNamespace

import pytest

from gvai.approval_lifecycle_model import Context, ModelState, SyntheticRequest, transition
from gvai.authority_admission import OfflineAuthorityAdmission
from gvai.execution_approval_envelope import EnvelopeRejected, parse_execution_approval
from gvai.linux_containment_stop import OwnedContainment
from gvai.supervisor_stop import MAX_GENERATION, StopController, StopJournal


NOW = 1_800_000_000
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No network, worker execution or real process signaling.")

    for name in ("socket", "create_connection", "getaddrinfo"):
        monkeypatch.setattr(socket, name, prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)
    for name in ("kill", "killpg", "waitpid", "waitid"):
        monkeypatch.setattr(os, name, prohibited)
    if hasattr(os, "pidfd_send_signal"):
        monkeypatch.setattr(os, "pidfd_send_signal", prohibited)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


@pytest.fixture
def envelope():
    action = {
        "tool_id": "synthetic-tool", "executable_sha256": "1" * 64,
        "arguments": [], "inputs": [], "resources": [], "outputs": [],
        "limits": {"duration_seconds": 1, "memory_bytes": 1024, "output_bytes": 1024},
    }
    return {
        "version": 1, "purpose": "execute-once",
        "approval_id": "00000000-0000-4000-8000-000000000001",
        "challenge": "5" * 64, "issuer_id": "synthetic-issuer",
        "approver_id": "synthetic-human", "scope": ["execute:synthetic"],
        "audience": {
            "supervisor_id": "synthetic-supervisor", "environment_id": "offline",
            "tenant_id": "synthetic-tenant",
            "boot_id": "00000000-0000-4000-8000-000000000002",
        },
        "workload": {"instance_id": "synthetic-worker", "bundle_sha256": "6" * 64,
                     "revision": "7" * 40},
        "action": action, "action_sha256": hashlib.sha256(canonical(action)).hexdigest(),
        "effects": ["effect:a"], "policy": {"sha256": "8" * 64, "epoch": 1},
        "observation": {
            "id": "synthetic-observation", "source_id": "synthetic-sentinel",
            "sha256": "9" * 64, "sequence": 1, "observed_at": NOW - 1,
            "expires_at": NOW + 59, "status": "stable", "halted": False,
        },
        "human_decision_id": "synthetic-decision",
        "control": {"epoch": 1, "revocation_generation": 1, "shutdown_generation": 1},
        "issued_at": NOW - 1, "not_before": NOW, "expires_at": NOW + 59,
        "auth": {"algorithm": "Ed25519", "key_id": "synthetic-key", "signature": "0" * 128},
    }


def unsigned(envelope):
    value = deepcopy(envelope)
    del value["auth"]["signature"]
    return value


@pytest.fixture
def claims(envelope):
    # Independently supplied diagnostic claims, not an envelope conversion.
    target = envelope["workload"]["instance_id"]
    revision = envelope["workload"]["revision"]
    return {
        "target_id": target, "revision": revision, "now": NOW,
        "control_status": "verified",
        "observation": {
            "target_id": target, "revision": revision, "source_id": "synthetic-sentinel",
            "status": "stable", "halted": False,
            "observed_at": NOW - 1, "expires_at": NOW + 59,
        },
        "enforcement": {
            "invariant_ids": ["synthetic-invariant"],
            "effect_requirements": ["synthetic-effect-check"], "independent_shutdown": True,
        },
        "approval": {
            "issuer_id": "synthetic-issuer", "target_id": target, "revision": revision,
            "issued_at": NOW - 1, "expires_at": NOW + 59,
            "signature": "synthetic-unverified-claim",
        },
    }


def candidate(envelope, claims, *, reserve, launch, publish):
    """Test-local negative-path wiring; never imported by production."""
    parsed = parse_execution_approval(
        canonical(envelope), now=NOW, expected_payload=unsigned(envelope),
    )
    denied = OfflineAuthorityAdmission().evaluate(**claims)
    if not denied.allowed:
        return parsed, denied
    reserve()
    launch()
    publish()
    pytest.fail("The deny-only gate unexpectedly admitted a request.")


def unreachable():
    pytest.fail("Gate denial must precede reservation, launch and publication.")


def assert_denied(*results):
    for result in results:
        assert result.allowed is False
        assert not result
        if hasattr(result, "authenticated"):
            assert result.authenticated is False


def test_valid_looking_envelope_and_complete_claims_never_reach_forward_stages(envelope, claims):
    parsed, denied = candidate(
        envelope, claims, reserve=unreachable, launch=unreachable, publish=unreachable,
    )
    assert_denied(parsed, denied)
    assert denied.reasons == (
        "non_operational_contract", "independent_approval_unavailable",
        "external_approval_not_authenticated",
    )
    assert parsed.canonical_envelope == canonical(envelope)


@pytest.fixture
def synthetic():
    # Deliberately independent of the envelope: UUID boot is not converted to int.
    context = Context(
        domain="synthetic-execution", supervisor="synthetic-supervisor",
        environment="offline", tenant="synthetic-tenant", boot=1,
        workload_digest="1" * 64, action_digest="2" * 64, effects=("effect:a",),
        policy_digest="3" * 64, policy_epoch=1, grants_epoch=1,
        observation_digest="4" * 64,
    )
    state = ModelState(context, NOW)
    scenario = SyntheticRequest(
        issuer="synthetic-issuer", principal="synthetic-human", scope=("scope:a",),
        decision="synthetic-decision", approval_id="synthetic-approval",
        challenge="synthetic-challenge", context=context,
        issued_at=NOW, not_before=NOW, expires_at=NOW + 60,
    )
    return state, scenario


@pytest.fixture
def kernel(monkeypatch):
    """Intercept every adapter FD operation; journal IO remains real."""
    state = {"populated": False, "exited": True, "kill_error": False, "calls": []}
    originals = (910001, 910002, 910003)
    retained = {fd: fd + 10 for fd in originals}
    real = {name: getattr(os, name) for name in
            ("dup", "set_inheritable", "close", "write", "read", "lseek")}

    def dup(fd):
        if fd in retained:
            return retained[fd]
        return real["dup"](fd)

    def inherit(fd, flag):
        if fd in retained.values():
            assert flag is False
            return
        return real["set_inheritable"](fd, flag)

    def close(fd):
        if fd in retained.values():
            state["calls"].append(("close", fd))
            return
        return real["close"](fd)

    def write(fd, raw):
        if fd == retained[originals[0]]:
            state["calls"].append(("kill", fd, raw))
            assert raw == b"1"
            if state["kill_error"]:
                raise OSError("Synthetic kill failure.")
            return 1
        assert fd not in retained.values()
        return real["write"](fd, raw)

    def read(fd, size):
        if fd == retained[originals[1]]:
            state["calls"].append(("observe", fd))
            assert size == 4097
            return b"populated 1\n" if state["populated"] else b"populated 0\n"
        assert fd not in retained.values()
        return real["read"](fd, size)

    def seek(fd, offset, whence):
        if fd == retained[originals[1]]:
            assert offset == 0 and whence == os.SEEK_SET
            return 0
        assert fd not in retained.values()
        return real["lseek"](fd, offset, whence)

    def wait(kind, fd, flags):
        assert kind == os.P_PIDFD and fd == retained[originals[2]]
        assert flags == os.WEXITED | os.WNOHANG
        state["calls"].append(("reap", fd))
        if state["exited"]:
            return SimpleNamespace(si_pid=42, si_code=os.CLD_EXITED)
        return None

    for name, operation in (
        ("dup", dup), ("set_inheritable", inherit), ("close", close),
        ("write", write), ("read", read), ("lseek", seek), ("waitid", wait),
    ):
        monkeypatch.setattr(os, name, operation)
    return state, originals


@pytest.fixture
def journal(tmp_path):
    record = tmp_path / "stop.json"
    record.write_text(json.dumps({
        "version": 1, "stopped": True, "generation": 7, "uncertain": False,
    }), encoding="ascii")
    record.chmod(0o600)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        value = StopJournal(fd)
    finally:
        os.close(fd)
    try:
        yield value
    finally:
        value.close()


@pytest.fixture
def containment(kernel):
    _, (kill, events, child) = kernel
    value = OwnedContainment(kill_fd=kill, events_fd=events, child_pidfds=(child,))
    try:
        yield value
    finally:
        value.close()


@pytest.mark.parametrize("stop_first", [False, True])
def test_cleanup_success_cannot_redeem_envelope_gate_or_model(
    envelope, claims, synthetic, journal, containment, kernel, stop_first,
):
    controller = StopController(journal)
    if stop_first:
        assert controller.request_stop().status == "uncertain"  # No containment yet.
    first = controller.register(containment)
    duplicate = controller.request_stop()
    assert first == duplicate
    assert first.status == first.cleanup.status == "terminated"
    assert [call[0] for call in kernel[0]["calls"]].count("reap") == 1
    parsed, denied = candidate(
        envelope, claims, reserve=unreachable, launch=unreachable, publish=unreachable,
    )
    state, scenario = synthetic
    reserved = transition(state, "reserve", now=NOW, request=scenario)
    assert reserved.reason == "reserved_in_model_only"
    assert_denied(first, duplicate, parsed, denied, reserved)
    stopped = transition(reserved.state, "shutdown", now=NOW)
    forward = transition(
        stopped.state, "dispatch", now=NOW, request=scenario, fence=stopped.state.fence,
    )
    assert forward.reason == "blocked"
    assert forward.state.attempts[0].dispatch_count == 0
    assert_denied(stopped, forward)


@pytest.mark.parametrize("populated,exited,kill_error,expected", [
    (True, False, False, "pending"),
    (False, False, False, "pending"),
    (False, True, True, "uncertain"),
])
def test_worker_claims_cannot_replace_kernel_cleanup(
    envelope, claims, journal, containment, kernel, populated, exited, kill_error, expected,
):
    kernel[0].update(populated=populated, exited=exited, kill_error=kill_error)
    controller = StopController(journal)
    worker_claim = {"completed": True, "cancelled": True, "terminated": True}
    with pytest.raises(ValueError):
        controller.register(worker_claim)
    report = controller.register(containment)
    assert report.cleanup.status == report.status == expected
    if not exited:
        assert report.cleanup.reaped is False
    parsed, denied = candidate(
        envelope, claims, reserve=unreachable, launch=unreachable, publish=unreachable,
    )
    assert_denied(report, parsed, denied)


def test_persistence_failure_still_uses_real_adapter_and_reopens_uncertain(
    tmp_path, journal, containment, kernel, monkeypatch, synthetic,
):
    real_sync = os.fsync

    def failed_sync(fd):
        assert any(call[0] == "kill" for call in kernel[0]["calls"])
        raise OSError("Synthetic storage failure.")

    monkeypatch.setattr(os, "fsync", failed_sync)
    report = StopController(journal).register(containment)
    assert report.cleanup.status == "terminated"
    assert report.status == "uncertain" and not report.durable
    assert_denied(report)
    monkeypatch.setattr(os, "fsync", real_sync)
    journal.close()
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reopened = StopJournal(fd)
    finally:
        os.close(fd)
    try:
        restarted = StopController(reopened).register(containment)
        assert restarted.state.uncertain and restarted.status == "uncertain"
        assert not restarted.durable
        assert_denied(restarted)
    finally:
        reopened.close()
    state, scenario = synthetic
    reserved = transition(state, "reserve", now=NOW, request=scenario)
    restart = transition(reserved.state, "restart", now=NOW)
    assert restart.state.uncertain
    assert scenario.approval_id in {key[2] for key in restart.state.consumed}
    assert_denied(reserved, restart)


def test_terminal_generations_are_independently_restrictive(tmp_path, kernel, containment, synthetic):
    record = tmp_path / "stop.json"
    record.write_text(json.dumps({
        "version": 1, "stopped": True, "generation": MAX_GENERATION, "uncertain": False,
    }), encoding="ascii")
    record.chmod(0o600)
    for _ in range(2):
        fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            value = StopJournal(fd)
        finally:
            os.close(fd)
        try:
            report = StopController(value).register(containment)
            assert report.state.generation == MAX_GENERATION and report.state.uncertain
            assert report.status == "uncertain"
            assert_denied(report)
        finally:
            value.close()
    state, scenario = synthetic
    result = transition(replace(state, fence=MAX_GENERATION), "reserve", now=NOW, request=scenario)
    assert result.state.fence == MAX_GENERATION and result.state.uncertain
    assert result.state.attempts == ()
    assert_denied(result)


def correlate(expected, observed):
    """Test-only exact matching, not evidence authentication or a production API."""
    fields = {"tenant", "attempt", "boot", "fence"}
    if type(expected) is not dict or type(observed) is not dict:
        return False
    if set(expected) != fields or set(observed) != fields:
        return False
    for key in ("tenant", "attempt", "boot"):
        if type(expected[key]) is not str or not expected[key]:
            return False
    if type(expected["fence"]) is not int or not 0 <= expected["fence"] < MAX_GENERATION:
        return False
    return all(type(observed[key]) is type(expected[key]) and observed[key] == expected[key]
               for key in fields)


@pytest.mark.parametrize("field,replacement", [
    ("tenant", "other-tenant"), ("attempt", "other-attempt"),
    ("boot", "00000000-0000-4000-8000-000000000003"),
    ("boot", 1), ("fence", 6), ("fence", 8), ("fence", True),
])
def test_test_only_correlation_rejects_substitution(envelope, field, replacement):
    expected = {"tenant": envelope["audience"]["tenant_id"],
                "attempt": "synthetic-attempt", "boot": envelope["audience"]["boot_id"], "fence": 7}
    assert correlate(expected, deepcopy(expected))
    changed = dict(expected, **{field: replacement})
    assert not correlate(expected, changed)
    del changed[field]
    assert not correlate(expected, changed)


@pytest.mark.parametrize("evidence", [
    None, {"terminated": True},
    {"tenant": "synthetic-tenant", "attempt": "synthetic-attempt", "boot": 1, "fence": 7},
])
def test_cleanup_or_worker_claims_supply_no_correlation(envelope, evidence):
    expected = {"tenant": envelope["audience"]["tenant_id"],
                "attempt": "synthetic-attempt", "boot": envelope["audience"]["boot_id"], "fence": 7}
    assert not correlate(expected, evidence)


def test_unbound_cleanup_is_not_a_model_cancellation_ack(journal, containment, synthetic):
    cleanup = StopController(journal).register(containment)
    assert cleanup.cleanup.status == "terminated"
    state, scenario = synthetic
    for event in ("reserve", "dispatch", "dispatch_ack"):
        result = transition(state, event, now=NOW, request=scenario, fence=state.fence)
        assert_denied(result)
        state = result.state
    stopped = transition(state, "shutdown", now=NOW)
    assert stopped.state.attempts[0].phase == "cancel_required"
    for evidence in (cleanup, cleanup.cleanup, {"terminated": True}):
        result = transition(stopped.state, "cancel_ack", now=NOW, request=evidence, fence=0)
        assert result.reason == "no_pending_cancellation"
        assert result.state.attempts[0].phase == "cancel_required"
        assert_denied(result)
    for changed, fence in ((replace(scenario, approval_id="foreign-attempt"), 0),
                           (scenario, stopped.state.fence)):
        mismatch = transition(stopped.state, "cancel_ack", now=NOW, request=changed, fence=fence)
        assert mismatch.reason == "no_pending_cancellation"
        assert mismatch.state.attempts[0].phase == "cancel_required"
        assert_denied(mismatch)
    # An exact synthetic acknowledgement records only a modeled cancellation.
    ack = transition(stopped.state, "cancel_ack", now=NOW, request=scenario, fence=0)
    assert ack.reason == "cancellation_recorded"
    assert ack.state.stopped
    assert_denied(ack, cleanup)


@pytest.mark.parametrize("control", ["shutdown", "revoke"])
def test_stop_or_revocation_prevents_modeled_promotion_without_redeeming_cleanup(
    synthetic, journal, containment, control,
):
    state, scenario = synthetic
    digest = "a" * 64
    for event in ("reserve", "dispatch", "dispatch_ack", "complete"):
        result = transition(state, event, now=NOW, request=scenario,
                            fence=state.fence, output_digest=digest)
        assert_denied(result)
        state = result.state
    assert state.attempts[0].phase == "modeled_complete"
    cleanup = StopController(journal).register(containment)
    assert cleanup.cleanup.status == "terminated"
    fenced = transition(state, control, now=NOW, request=scenario)
    promotion = transition(fenced.state, "promote", now=NOW, request=scenario,
                           fence=state.fence, output_digest=digest)
    assert promotion.state.attempts[0].phase == "invalidated"
    assert promotion.state.fence > state.fence
    assert_denied(cleanup, fenced, promotion)


@pytest.mark.parametrize("field", ["tenant_id", "boot_id"])
def test_envelope_context_substitution_rejects_before_gate(envelope, field):
    expected = unsigned(envelope)
    envelope["audience"][field] = (
        "other-tenant" if field == "tenant_id"
        else "00000000-0000-4000-8000-000000000003"
    )
    with pytest.raises(EnvelopeRejected):
        parse_execution_approval(canonical(envelope), now=NOW, expected_payload=expected)


@pytest.mark.parametrize("field,value", [("tenant", "other-tenant"), ("boot", 2)])
def test_model_context_substitution_and_stale_fence_reject(synthetic, field, value):
    state, scenario = synthetic
    reserved = transition(state, "reserve", now=NOW, request=scenario)
    changed = replace(scenario, context=replace(scenario.context, **{field: value}))
    mismatch = transition(reserved.state, "dispatch", now=NOW, request=changed, fence=0)
    assert mismatch.reason == "context_or_revocation_mismatch"
    stale = transition(reserved.state, "dispatch", now=NOW, request=scenario, fence=1)
    assert stale.reason == "stale_or_missing_fence"
    assert mismatch.state.attempts[0].dispatch_count == stale.state.attempts[0].dispatch_count == 0
    assert_denied(reserved, mismatch, stale)


def test_harness_has_no_production_callers():
    for directory in (ROOT / "gvai", ROOT / "scripts"):
        for path in directory.rglob("*.py"):
            assert "test_independent_switch_contract" not in path.read_text(encoding="utf-8")
