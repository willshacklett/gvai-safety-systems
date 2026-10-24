from dataclasses import FrozenInstanceError, replace
import os
import socket
import subprocess
import threading
from uuid import UUID

import pytest

from gvai.launcher_worker_contract import (
    EvidenceAssessment, EvidenceRequirement as E, LauncherWorkerContract,
    LifecycleReport, LifecycleState as S, PROPOSED_WORKER_LABEL,
    SETUP_APPARMOR_PROFILE, required_evidence, termination_target,
)
from gvai.linux_containment_identity import ContainmentIdentity
from gvai.systemd_worker_contract import ResourceLimits, WorkerIdentity, WorkerSpec


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No processes, sockets, signals, systemd or kernel acceptance operations.")

    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)
    for name in ("kill", "killpg", "waitpid", "waitid", "system", "fork"):
        monkeypatch.setattr(os, name, prohibited)


def spec():
    return WorkerSpec(
        WorkerIdentity(UUID(int=1), UUID(int=2), ContainmentIdentity(8, 91)),
        60001, 60001, ResourceLimits(64 * 1024**2, 32, 200, 16 * 1024**2),
    )


class FixtureVerifier:
    """Test-owned oracle, never independent runtime evidence."""

    def __init__(self):
        self.calls = []
        self.transform = lambda value: value

    def verify(self, request, evidence):
        self.calls.append(request)
        if evidence is not self:
            raise ValueError("Unauthenticated evidence.")
        label = (
            PROPOSED_WORKER_LABEL if request.target in (
                S.WORKER_CONFINEMENT_VERIFIED, S.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION,
            ) else SETUP_APPARMOR_PROFILE
        )
        return self.transform(EvidenceAssessment(
            request, required_evidence(request.target), label,
        ))


PHASES = (
    S.STOPPED, S.SETUP_PENDING, S.SETUP_CONFINED, S.NAMESPACES_ESTABLISHED,
    S.INPUT_AND_SECCOMP_VERIFIED,
)


def fixture_at(state):
    verifier = FixtureVerifier()
    contract = LauncherWorkerContract(spec(), UUID(int=3), verifier)
    for target in PHASES[1:PHASES.index(state) + 1]:
        report = contract.advance(target, verifier)
        assert report.state is target
    return contract, verifier


def denied(report):
    assert not report
    assert report.runtime_verified is False
    assert report.execution_authorized is False
    assert report.output_publication_authorized is False


def test_initial_state_and_planning_never_grant_authority():
    contract = LauncherWorkerContract(spec(), UUID(int=3))
    assert contract.snapshot().state is S.STOPPED
    denied(contract.snapshot())
    denied(contract.advance(S.SETUP_PENDING))
    report = contract.advance(S.SETUP_CONFINED, object())
    assert report.state is S.FAILED_CLOSED
    assert "not implemented" in report.errors[-1]
    denied(report)


@pytest.mark.parametrize("state", PHASES)
@pytest.mark.parametrize("target", list(S))
def test_only_adjacent_phases_can_advance(state, target):
    contract, verifier = fixture_at(state)
    expected = {
        S.STOPPED: S.SETUP_PENDING,
        S.SETUP_PENDING: S.SETUP_CONFINED,
        S.SETUP_CONFINED: S.NAMESPACES_ESTABLISHED,
        S.NAMESPACES_ESTABLISHED: S.INPUT_AND_SECCOMP_VERIFIED,
    }.get(state)
    report = contract.advance(target, verifier)
    assert report.state is (target if target is expected else S.FAILED_CLOSED)
    denied(report)


@pytest.mark.parametrize("label", ["gvai-worker", "unconfined", "gvai-bwrap", "", "gvai-setup (complain)"])
def test_wrong_setup_attachment(label):
    contract, verifier = fixture_at(S.SETUP_PENDING)
    verifier.transform = lambda value: replace(value, apparmor_label=label)
    assert contract.advance(S.SETUP_CONFINED, verifier).state is S.FAILED_CLOSED


@pytest.mark.parametrize("missing", sorted(required_evidence(S.INPUT_AND_SECCOMP_VERIFIED), key=lambda item: item.value))
def test_each_containment_requirement_is_mandatory(missing):
    contract, verifier = fixture_at(S.NAMESPACES_ESTABLISHED)
    verifier.transform = lambda value: replace(value, checks=value.checks - {missing})
    report = contract.advance(S.INPUT_AND_SECCOMP_VERIFIED, verifier)
    assert report.state is S.FAILED_CLOSED
    assert "evidence" in report.errors[-1]


@pytest.mark.parametrize("change", [
    lambda request: replace(request, session=UUID(int=9)),
    lambda request: replace(request, revision=request.revision - 1),
    lambda request: replace(request, revision=True),
    lambda request: replace(request, previous=S.STOPPED),
    lambda request: replace(request, target=S.TERMINATED),
    lambda request: replace(request, spec=replace(
        request.spec, identity=replace(request.spec.identity, boot=UUID(int=9)),
    )),
    lambda request: replace(request, spec=replace(
        request.spec, identity=replace(request.spec.identity, attempt=UUID(int=9)),
    )),
    lambda request: replace(request, spec=replace(
        request.spec, identity=replace(
            request.spec.identity, cgroup=ContainmentIdentity(8, 92),
        ),
    )),
    lambda request: replace(request, spec=replace(request.spec, uid=60002)),
    lambda request: replace(request, spec=replace(
        request.spec, limits=replace(request.spec.limits, scratch_bytes=1),
    )),
])
def test_stale_or_rebound_evidence_fails(change):
    contract, verifier = fixture_at(S.SETUP_PENDING)
    verifier.transform = lambda value: replace(value, request=change(value.request))
    assert contract.advance(S.SETUP_CONFINED, verifier).state is S.FAILED_CLOSED


def test_worker_supplied_assessment_is_not_a_verifier():
    contract, verifier = fixture_at(S.SETUP_PENDING)
    request = contract.request_for(S.SETUP_CONFINED)
    forged = EvidenceAssessment(request, required_evidence(request.target), SETUP_APPARMOR_PROFILE)
    report = contract.advance(S.SETUP_CONFINED, forged)
    assert report.state is S.FAILED_CLOSED
    assert "Unauthenticated" in report.errors[-1]


def test_uid_map_failure_is_explicit_and_sticky():
    contract, verifier = fixture_at(S.SETUP_CONFINED)

    def fail(value):
        raise OSError("bwrap: setting up uid map: Permission denied")

    verifier.transform = fail
    report = contract.advance(S.NAMESPACES_ESTABLISHED, verifier)
    assert report.state is S.FAILED_CLOSED
    assert "uid map" in report.errors[-1]
    assert contract.advance(S.SETUP_PENDING).state is S.FAILED_CLOSED


@pytest.mark.parametrize("missing", sorted(required_evidence(S.WORKER_CONFINEMENT_VERIFIED), key=lambda item: item.value))
def test_final_worker_requirements_cannot_be_omitted(missing):
    contract, verifier = fixture_at(S.INPUT_AND_SECCOMP_VERIFIED)
    verifier.transform = lambda value: replace(value, checks=value.checks - {missing})
    report = contract.advance(S.WORKER_CONFINEMENT_VERIFIED, verifier)
    assert report.state is S.FAILED_CLOSED
    assert "evidence" in report.errors[-1]


@pytest.mark.parametrize("label", [SETUP_APPARMOR_PROFILE, "gvai-worker", "unconfined"])
def test_worker_cannot_enter_under_launcher_or_wrong_label(label):
    contract, verifier = fixture_at(S.INPUT_AND_SECCOMP_VERIFIED)
    verifier.transform = lambda value: replace(value, apparmor_label=label)
    report = contract.advance(S.WORKER_CONFINEMENT_VERIFIED, verifier)
    assert report.state is S.FAILED_CLOSED
    assert "attachment" in report.errors[-1]


def test_even_perfect_fixture_cannot_establish_kernel_transition():
    contract, verifier = fixture_at(S.INPUT_AND_SECCOMP_VERIFIED)
    report = contract.advance(S.WORKER_CONFINEMENT_VERIFIED, verifier)
    assert report.state is S.FAILED_CLOSED
    assert "unreviewed and unverified" in report.errors[-1]
    denied(report)
    assert contract.advance(S.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION, verifier).state is S.FAILED_CLOSED


@pytest.mark.parametrize("state", PHASES)
def test_stop_preempts_every_reachable_setup_phase(state):
    contract, verifier = fixture_at(state)
    report = contract.request_stop()
    assert report.state is S.TERMINATION_PENDING and report.stop_requested
    denied(report)
    assert contract.advance(S.SETUP_PENDING).state is S.FAILED_CLOSED
    assert contract.request_stop().state is S.TERMINATION_PENDING
    report = contract.advance(S.TERMINATED, verifier)
    assert report.state is S.TERMINATED
    denied(report)
    assert contract.request_stop().state is S.TERMINATED


@pytest.mark.parametrize("missing", sorted(required_evidence(S.TERMINATED), key=lambda item: item.value))
def test_incomplete_cleanup_never_becomes_terminated(missing):
    contract, verifier = fixture_at(S.SETUP_PENDING)
    contract.request_stop()
    verifier.transform = lambda value: replace(value, checks=value.checks - {missing})
    report = contract.advance(S.TERMINATED, verifier)
    assert report.state is S.FAILED_CLOSED and report.stop_requested
    denied(report)


def test_stop_after_failed_transition_and_replayed_cleanup():
    contract, verifier = fixture_at(S.INPUT_AND_SECCOMP_VERIFIED)
    contract.advance(S.WORKER_CONFINEMENT_VERIFIED, verifier)
    contract.request_stop()
    old = contract.request_for(S.TERMINATED)
    contract.request_stop()
    verifier.transform = lambda value: replace(value, request=old)
    assert contract.advance(S.TERMINATED, verifier).state is S.FAILED_CLOSED


@pytest.mark.parametrize("state", list(S))
def test_stop_rule_covers_every_declared_phase_including_unreachable_states(state):
    assert termination_target(state) is (
        S.TERMINATED if state is S.TERMINATED else S.TERMINATION_PENDING
    )


@pytest.mark.parametrize("transform", [
    lambda value: True,
    lambda value: None,
    lambda value: replace(value, checks=set(value.checks)),
    lambda value: replace(value, checks=frozenset({"trusted"})),
    lambda value: replace(value, request=None),
    lambda value: replace(value, request=replace(value.request, spec=object())),
    lambda value: replace(value, request=replace(value.request, session="3")),
    lambda value: replace(value, apparmor_label=None),
])
def test_malformed_assessments_fail_explicitly(transform):
    contract, verifier = fixture_at(S.SETUP_PENDING)
    verifier.transform = transform
    report = contract.advance(S.SETUP_CONFINED, verifier)
    assert report.state is S.FAILED_CLOSED and report.errors
    denied(report)


def test_old_assessment_cannot_cross_phases():
    contract, verifier = fixture_at(S.SETUP_PENDING)
    request = contract.request_for(S.SETUP_CONFINED)
    assessment = verifier.verify(request, verifier)
    contract.advance(S.SETUP_CONFINED, verifier)
    verifier.transform = lambda value: assessment
    assert contract.advance(S.NAMESPACES_ESTABLISHED, verifier).state is S.FAILED_CLOSED


def test_missing_cleanup_verifier_and_duplicate_stop():
    contract = LauncherWorkerContract(spec(), UUID(int=3))
    contract.request_stop()
    contract.request_stop()
    report = contract.advance(S.TERMINATED, True)
    assert report.state is S.FAILED_CLOSED and report.stop_requested


def test_unexpected_verifier_error_propagates_but_leaves_failure():
    contract, verifier = fixture_at(S.SETUP_PENDING)

    def fail(value):
        raise LookupError("unexpected verifier bug")

    verifier.transform = fail
    with pytest.raises(LookupError, match="unexpected verifier bug"):
        contract.advance(S.SETUP_CONFINED, verifier)
    assert contract.snapshot().state is S.FAILED_CLOSED
    assert contract.snapshot().errors


def test_reports_are_immutable_and_every_named_state_is_non_authorizing():
    for state in S:
        report = LifecycleReport(state, 1, False, ())
        denied(report)
        with pytest.raises(FrozenInstanceError):
            report.state = S.STOPPED


@pytest.mark.parametrize("bad", [None, True, "SETUP_PENDING", []])
def test_invalid_transition_fails_closed(bad):
    contract = LauncherWorkerContract(spec(), UUID(int=3))
    assert contract.advance(bad).state is S.FAILED_CLOSED


def test_determinism_and_binding():
    first, a = fixture_at(S.SETUP_CONFINED)
    second, b = fixture_at(S.SETUP_CONFINED)
    assert first.request_for(S.NAMESPACES_ESTABLISHED) == second.request_for(S.NAMESPACES_ESTABLISHED)
    assert first.advance(S.NAMESPACES_ESTABLISHED, a) == second.advance(S.NAMESPACES_ESTABLISHED, b)


@pytest.mark.parametrize("bad_spec,bad_session", [
    (None, UUID(int=3)),
    (spec(), UUID(int=0)),
    (spec(), "session"),
])
def test_invalid_identity_configuration_is_rejected(bad_spec, bad_session):
    with pytest.raises(ValueError, match="fixed worker specification"):
        LauncherWorkerContract(bad_spec, bad_session)


@pytest.mark.parametrize("late_error", [None, ValueError, TimeoutError, LookupError])
@pytest.mark.parametrize("state,target", [
    (S.SETUP_PENDING, S.SETUP_CONFINED),
    (S.SETUP_CONFINED, S.NAMESPACES_ESTABLISHED),
    (S.NAMESPACES_ESTABLISHED, S.INPUT_AND_SECCOMP_VERIFIED),
    (S.INPUT_AND_SECCOMP_VERIFIED, S.WORKER_CONFINEMENT_VERIFIED),
])
def test_blocked_verifier_never_blocks_stop_or_independent_cleanup(late_error, state, target):
    contract, verifier = fixture_at(state)
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()
    results = []
    errors = []

    def transform(value):
        if value.request.target is target:
            entered.set()
            if not release.wait(5):
                raise TimeoutError("test callback release deadline")
            if late_error is not None:
                raise late_error("late verifier failure")
        return value

    verifier.transform = transform

    def verify():
        try:
            results.append(contract.advance(target, verifier))
        except Exception as error:
            errors.append(error)

    def stop():
        contract.request_stop()
        contract.request_stop()
        stopped.set()

    verification = threading.Thread(target=verify)
    cancellation = threading.Thread(target=stop)
    verification.start()
    try:
        assert entered.wait(1)
        cancellation.start()
        assert stopped.wait(1), "STOP waited for verifier completion"
        cancellation.join(1)
        assert not cancellation.is_alive()
        pending = contract.snapshot()
        assert pending.stop_requested and pending.state is S.TERMINATION_PENDING
        assert verification.is_alive() and not release.is_set()
        denied(pending)
        # Fresh cleanup verification is independent of the old blocked callback.
        complete = contract.advance(S.TERMINATED, verifier)
        assert complete.state is S.TERMINATED and complete.stop_requested
        denied(complete)
    finally:
        release.set()
        verification.join(6)
        if cancellation.ident is not None:
            cancellation.join(6)
    assert not verification.is_alive() and not cancellation.is_alive()
    assert contract.snapshot().state is S.TERMINATED
    assert contract.snapshot().stop_requested
    if late_error is LookupError:
        assert len(errors) == 1 and isinstance(errors[0], LookupError)
    else:
        assert not errors and results[0].state is S.TERMINATED


def test_reentrant_stop_invalidates_success_without_deadlock():
    contract, verifier = fixture_at(S.SETUP_PENDING)
    reports = []

    class BoundedMutex:
        """A regression must fail the test rather than strand a deadlocked thread."""

        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if not self.lock.acquire(timeout=1):
                raise TimeoutError("reentrant lifecycle lock acquisition")
            return self

        def __exit__(self, *args):
            self.lock.release()

    contract._lock = BoundedMutex()

    def transform(value):
        reports.append(contract.request_stop())
        return value

    verifier.transform = transform
    thread = threading.Thread(
        target=lambda: reports.append(contract.advance(S.SETUP_CONFINED, verifier)),
    )
    thread.start()
    thread.join(2)
    assert not thread.is_alive(), "Reentrant STOP deadlocked"
    assert len(reports) == 2
    assert all(report.stop_requested and report.state is S.TERMINATION_PENDING for report in reports)
    assert contract.snapshot().state is S.TERMINATION_PENDING


def test_many_concurrent_stop_requests_invalidate_outstanding_verification():
    contract, verifier = fixture_at(S.SETUP_PENDING)
    entered = threading.Event()
    release = threading.Event()
    reports = []
    errors = []

    def transform(value):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test callback release deadline")
        return value

    verifier.transform = transform

    def verify():
        try:
            reports.append(contract.advance(S.SETUP_CONFINED, verifier))
        except Exception as error:
            errors.append(error)

    verification = threading.Thread(target=verify)
    stoppers = [
        threading.Thread(target=lambda: reports.append(contract.request_stop()))
        for _ in range(8)
    ]
    verification.start()
    try:
        assert entered.wait(1)
        for thread in stoppers:
            thread.start()
        for thread in stoppers:
            thread.join(1)
        assert all(not thread.is_alive() for thread in stoppers)
        assert contract.snapshot().state is S.TERMINATION_PENDING
    finally:
        release.set()
        verification.join(6)
        for thread in stoppers:
            if thread.ident is not None:
                thread.join(6)
    assert not verification.is_alive()
    assert all(not thread.is_alive() for thread in stoppers)
    assert not errors and len(reports) == 9
    assert all(report.stop_requested and report.state is S.TERMINATION_PENDING for report in reports)
    assert contract.snapshot().state is S.TERMINATION_PENDING


def test_reentrant_advance_cannot_be_overwritten_by_outer_success():
    contract, verifier = fixture_at(S.SETUP_PENDING)

    def transform(value):
        assert contract.advance(S.NAMESPACES_ESTABLISHED).state is S.FAILED_CLOSED
        return value

    verifier.transform = transform
    assert contract.advance(S.SETUP_CONFINED, verifier).state is S.FAILED_CLOSED
    assert contract.snapshot().errors


@pytest.mark.parametrize("error_type", [ValueError, RuntimeError, TimeoutError])
def test_verifier_failure_without_stop_stays_closed(error_type):
    contract, verifier = fixture_at(S.SETUP_PENDING)

    def transform(value):
        raise error_type("verification failed")

    verifier.transform = transform
    report = contract.advance(S.SETUP_CONFINED, verifier)
    assert report.state is S.FAILED_CLOSED and report.errors
    assert contract.request_stop().state is S.TERMINATION_PENDING
    denied(report)
