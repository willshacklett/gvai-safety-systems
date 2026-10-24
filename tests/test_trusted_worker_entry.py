from dataclasses import FrozenInstanceError, replace
import os
import socket
import subprocess
import threading
from uuid import UUID

import pytest

from gvai.launcher_worker_contract import (
    EvidenceAssessment, EvidenceRequest, EvidenceRequirement as E,
    LauncherWorkerContract, LifecycleState as S, PROPOSED_WORKER_LABEL,
    SETUP_APPARMOR_PROFILE, required_evidence,
)
from gvai.linux_containment_identity import ContainmentIdentity
from gvai.systemd_worker_contract import ResourceLimits, WorkerIdentity, WorkerSpec
from gvai.systemd_worker_profile import REQUIRED_NAMESPACES, WORKER_SECCOMP_POLICY_ID
from gvai.trusted_worker_entry import (
    ArtifactIdentity, EntryIdentity, EntryObservation, EntryResponse,
    MappingEvidence, MappingPlan, MappingStage, ObjectPin, ObservationState, ProcessLifetime,
    TrustedEntryExchange, VerifierIdentity,
)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("No host, process, socket, signal or worker operations permitted.")

    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)
    for name in ("kill", "killpg", "waitpid", "waitid", "system", "fork"):
        monkeypatch.setattr(os, name, prohibited)


class Clock:
    def __init__(self):
        self.now = 100

    def __call__(self):
        return self.now


class FixtureAuthenticator:
    """Test-owned oracle; object association is NOT production authentication."""

    def __init__(self):
        self.approved = None
        self.transform = lambda value: value

    def authenticate(self, challenge, response):
        return self.transform(response is self.approved)


def setup(*, authenticator=True):
    spec = WorkerSpec(
        WorkerIdentity(UUID(int=1), UUID(int=2), ContainmentIdentity(8, 91)),
        60001, 60001, ResourceLimits(64 * 1024**2, 32, 200, 16 * 1024**2),
    )
    identity = EntryIdentity(
        spec.identity.boot, spec.identity.attempt, spec.identity.service,
        ProcessLifetime(123, 456, ObjectPin(9, 10), b"p" * 32),
        ObjectPin(8, 91), ArtifactIdentity(ObjectPin(8, 92), "a" * 64),
    )
    verifier = VerifierIdentity(ArtifactIdentity(ObjectPin(8, 93), "b" * 64), "c" * 64)
    clock = Clock()
    auth = FixtureAuthenticator()
    exchange = TrustedEntryExchange(
        identity, verifier,
        (
            MappingPlan(MappingStage.INITIAL, ((0, 60001, 1),), ((0, 60001, 1),)),
            MappingPlan(MappingStage.FINAL, ((60001, 0, 1),), ((60001, 0, 1),)),
        ),
        auth if authenticator else None, lifetime_ns=100, clock=clock,
    )
    request = EvidenceRequest(
        spec, UUID(int=3), 4, S.INPUT_AND_SECCOMP_VERIFIED, S.WORKER_CONFINEMENT_VERIFIED,
    )
    return exchange, request, auth, clock


def response_for(challenge):
    return EntryResponse(
        challenge, challenge.identity, challenge.verifier, 100,
        tuple(
            EntryObservation(check, challenge.identity.process, 100, ObservationState.OBSERVED, "d" * 64)
            for check in sorted(required_evidence(challenge.request.target), key=lambda item: item.value)
        ),
        tuple(
            (name, challenge.identity.process.pid_namespace if name == "pid" else ObjectPin(9, index + 20))
            for index, name in enumerate(sorted(REQUIRED_NAMESPACES))
        ),
        tuple(
            MappingEvidence(
                stage, ObjectPin(9, index + 30), True,
                plan.uid_map, plan.gid_map, True,
            )
            for index, plan in enumerate(challenge.mapping_plan)
            for stage in (plan.stage,)
        ),
        PROPOSED_WORKER_LABEL, WORKER_SECCOMP_POLICY_ID, b"fixture-proof",
    )


def denied(report):
    assert not report
    assert report.authenticated is False and report.runtime_verified is False
    assert report.execution_authorized is False and report.output_publication_authorized is False


def test_default_has_no_authenticator_and_fixture_consistency_has_no_authority():
    exchange, request, _, _ = setup(authenticator=False)
    challenge = exchange.issue(request)
    report = exchange.assess(challenge, response_for(challenge))
    assert not report.consistent and "authenticator" in report.errors[0]
    denied(report)
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)
    report = exchange.assess(challenge, auth.approved)
    assert report.consistent and not report.errors
    denied(report)
    with pytest.raises(FrozenInstanceError):
        report.consistent = False


@pytest.mark.parametrize("transform", [
    lambda identity: replace(identity, process=replace(identity.process, start_ticks=457)),
    lambda identity: replace(identity, process=replace(identity.process, handle_binding=b"q" * 32)),
    lambda identity: replace(identity, process=replace(identity.process, pid_namespace=ObjectPin(9, 11))),
    lambda identity: replace(identity, cgroup=ObjectPin(8, 94)),
    lambda identity: replace(identity, boot=UUID(int=4)),
    lambda identity: replace(identity, attempt=UUID(int=5), service=f"gvai-worker-{UUID(int=5).hex}.service"),
    lambda identity: replace(identity, launcher=replace(identity.launcher, sha256="f" * 64)),
    lambda identity: replace(identity, launcher=replace(identity.launcher, pin=ObjectPin(8, 99))),
])
def test_pid_reuse_and_other_identity_substitution_fail(transform):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    original = response_for(challenge)
    response = replace(original, identity=transform(original.identity))
    auth.approved = response
    report = exchange.assess(challenge, response)
    assert not report.consistent and "mismatch" in report.errors[0]
    denied(report)


@pytest.mark.parametrize("transform", [
    lambda response: replace(response, verifier=replace(response.verifier, trust_anchor_sha256="f" * 64)),
    lambda response: replace(response, challenge=replace(response.challenge, nonce=b"x" * 32)),
    lambda response: replace(response, challenge=replace(
        response.challenge, request=replace(response.challenge.request, revision=5),
    )),
    lambda response: replace(response, challenge=replace(
        response.challenge, request=replace(response.challenge.request, session=UUID(int=9)),
    )),
    lambda response: replace(response, authentication=b""),
    lambda response: replace(response, apparmor_label=SETUP_APPARMOR_PROFILE),
    lambda response: replace(response, apparmor_label="unconfined"),
    lambda response: replace(response, seccomp_policy_id="no-spawn-only"),
    lambda response: replace(response, namespaces=response.namespaces[:-1]),
    lambda response: replace(response, namespaces=(response.namespaces[0],) * 6),
    lambda response: replace(response, mappings=response.mappings[:1]),
    lambda response: replace(response, mappings=(response.mappings[0],) * 2),
    lambda response: replace(response, mappings=(
        replace(response.mappings[0], connected_to_current_namespace=False), response.mappings[1],
    )),
    lambda response: replace(response, mappings=(
        replace(response.mappings[0], uid_map=((0, 0, 1),)), response.mappings[1],
    )),
    lambda response: replace(response, mappings=(
        response.mappings[0], replace(response.mappings[1], setgroups_sequence_verified=False),
    )),
])
def test_incorrect_or_incomplete_entry_evidence_fails(transform):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    response = transform(response_for(challenge))
    auth.approved = response
    report = exchange.assess(challenge, response)
    assert not report.consistent and report.errors
    denied(report)


@pytest.mark.parametrize("requirement", sorted(required_evidence(S.WORKER_CONFINEMENT_VERIFIED), key=lambda check: check.value))
@pytest.mark.parametrize("state", [ObservationState.FAILED, ObservationState.UNVERIFIED])
def test_every_required_observation_must_be_observed(requirement, state):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    response = response_for(challenge)
    response = replace(response, observations=tuple(
        replace(item, state=state) if item.requirement is requirement else item
        for item in response.observations
    ))
    auth.approved = response
    assert not exchange.assess(challenge, response).consistent


def test_individual_observation_cannot_target_other_lifetime():
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    response = response_for(challenge)
    observation = response.observations[0]
    response = replace(response, observations=(
        replace(observation, process=replace(observation.process, start_ticks=999)),
        *response.observations[1:],
    ))
    auth.approved = response
    assert not exchange.assess(challenge, response).consistent


@pytest.mark.parametrize("now,observed", [(99, 100), (200, 100), (201, 100), (150, 99), (150, 151), (True, 100)])
def test_stale_future_and_invalid_time_fails(now, observed):
    exchange, request, auth, clock = setup()
    challenge = exchange.issue(request)
    auth.approved = replace(response_for(challenge), observed_at_ns=observed)
    clock.now = now
    assert not exchange.assess(challenge, auth.approved).consistent


def test_authenticator_delay_expires_evidence():
    exchange, request, auth, clock = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)

    def delay(value):
        clock.now = 200
        return value

    auth.transform = delay
    report = exchange.assess(challenge, auth.approved)
    assert not report.consistent and "expired" in report.errors[0]


def test_one_use_including_failed_attempts_and_superseded_requests():
    exchange, request, auth, _ = setup()
    first = exchange.issue(request)
    second = exchange.issue(request)
    assert first.nonce != second.nonce and first.epoch < second.epoch
    assert not exchange.assess(first, response_for(first)).consistent
    auth.approved = response_for(second)
    forged = replace(auth.approved, authentication=b"forged")
    assert not exchange.assess(second, forged).consistent
    assert not exchange.assess(second, auth.approved).consistent
    third = exchange.issue(request)
    auth.approved = response_for(third)
    assert exchange.assess(third, auth.approved).consistent
    assert not exchange.assess(third, auth.approved).consistent


@pytest.mark.parametrize("error_type", [ValueError, TimeoutError, LookupError])
def test_authenticator_errors_consume_challenge(error_type):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)

    def fail(value):
        raise error_type("authenticator failure")

    auth.transform = fail
    if error_type is LookupError:
        with pytest.raises(LookupError):
            exchange.assess(challenge, auth.approved)
    else:
        assert not exchange.assess(challenge, auth.approved).consistent
    auth.transform = lambda value: value
    assert not exchange.assess(challenge, auth.approved).consistent
    denied(exchange.request_stop())


@pytest.mark.parametrize("during", ["collection", "authentication"])
def test_stop_during_collection_or_authentication_rejects_late_reply(during):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    entered = threading.Event()
    release = threading.Event()
    stopped = threading.Event()
    reports = []
    errors = []

    def block():
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test release deadline")

    def authenticate(value):
        block()
        return value

    if during == "authentication":
        auth.transform = authenticate

    def collect_and_assess():
        try:
            if during == "collection":
                block()
            auth.approved = response_for(challenge)
            reports.append(exchange.assess(challenge, auth.approved))
        except Exception as error:
            errors.append(error)

    def stop():
        reports.append(exchange.request_stop())
        reports.append(exchange.request_stop())
        stopped.set()

    worker = threading.Thread(target=collect_and_assess)
    stopper = threading.Thread(target=stop)
    worker.start()
    try:
        assert entered.wait(1)
        stopper.start()
        assert stopped.wait(1), "STOP waited for evidence collection/authentication"
        assert worker.is_alive()
    finally:
        release.set()
        worker.join(6)
        if stopper.ident is not None:
            stopper.join(6)
    assert not worker.is_alive() and not stopper.is_alive() and not errors
    assert len(reports) == 3
    assert all(report.stop_requested and not report.consistent for report in reports)
    for report in reports:
        denied(report)
    with pytest.raises(ValueError, match="STOP"):
        exchange.issue(request)


def test_reentrant_stop_from_authenticator_is_nonblocking():
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)

    class BoundedLock:
        def __init__(self):
            self.lock = threading.Lock()

        def __enter__(self):
            if not self.lock.acquire(timeout=1):
                raise TimeoutError("callback executed under evidence mutex")
            return self

        def __exit__(self, *args):
            self.lock.release()

    exchange._lock = BoundedLock()

    def stop(value):
        exchange.request_stop()
        return value

    auth.transform = stop
    report = exchange.assess(challenge, auth.approved)
    assert not report.consistent and report.stop_requested


def test_evidence_cannot_unblock_existing_lifecycle_gate():
    exchange, request, auth, _ = setup()

    class FixtureLifecycleVerifier:
        def verify(self, lifecycle_request, evidence):
            return EvidenceAssessment(
                lifecycle_request, required_evidence(lifecycle_request.target),
                PROPOSED_WORKER_LABEL if lifecycle_request.target is S.WORKER_CONFINEMENT_VERIFIED
                else SETUP_APPARMOR_PROFILE,
            )

    lifecycle = LauncherWorkerContract(request.spec, request.session, FixtureLifecycleVerifier())
    for phase in (S.SETUP_PENDING, S.SETUP_CONFINED, S.NAMESPACES_ESTABLISHED, S.INPUT_AND_SECCOMP_VERIFIED):
        assert lifecycle.advance(phase).state is phase
    challenge = exchange.issue(lifecycle.request_for(S.WORKER_CONFINEMENT_VERIFIED))
    auth.approved = response_for(challenge)
    report = exchange.assess(challenge, auth.approved)
    assert report.consistent
    result = lifecycle.advance(S.WORKER_CONFINEMENT_VERIFIED, report)
    assert result.state is S.FAILED_CLOSED and not result.execution_authorized
    lifecycle.request_stop()
    exchange.request_stop()
    assert lifecycle.snapshot().stop_requested


@pytest.mark.parametrize("change", [
    lambda request: replace(request, session=UUID(int=0)),
    lambda request: replace(request, revision=True),
    lambda request: replace(request, previous=S.STOPPED),
    lambda request: replace(request, target=S.TERMINATED),
    lambda request: replace(request, spec=replace(request.spec, identity=replace(
        request.spec.identity, cgroup=ContainmentIdentity(8, 99),
    ))),
])
def test_wrong_request_cannot_issue_challenge(change):
    exchange, request, _, _ = setup()
    with pytest.raises(ValueError):
        exchange.issue(change(request))


def test_process_identity_requires_more_than_pid_and_service_is_fixed():
    with pytest.raises(ValueError):
        ProcessLifetime(123, 456, ObjectPin(9, 10), b"")
    exchange, request, _, _ = setup()
    identity = exchange.issue(request).identity
    with pytest.raises(ValueError):
        replace(identity, service="attacker.service")


@pytest.mark.parametrize("transform", [
    lambda response: replace(response, observations=response.observations[:-1]),
    lambda response: replace(response, observations=(response.observations[0],) * len(response.observations)),
    lambda response: replace(response, observations=(
        replace(response.observations[0], observed_at_ns=99), *response.observations[1:],
    )),
    lambda response: replace(response, observations=(
        replace(response.observations[0], provenance_sha256=""), *response.observations[1:],
    )),
    lambda response: replace(response, namespaces=tuple(
        (name, ObjectPin(1, 2) if name == "pid" else pin) for name, pin in response.namespaces
    )),
    lambda response: replace(response, mappings=(
        response.mappings[0], replace(response.mappings[1], gid_map=((0, 0, 1),)),
    )),
    lambda response: None,
    lambda response: True,
])
def test_ambiguous_or_stale_provenance_is_not_accepted(transform):
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    response = transform(response_for(challenge))
    auth.approved = response
    assert not exchange.assess(challenge, response).consistent


def test_authenticator_must_return_exact_boolean_true():
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)
    auth.transform = lambda value: 1
    assert not exchange.assess(challenge, auth.approved).consistent


@pytest.mark.parametrize("change", [
    lambda request: replace(request, revision=3),
    lambda request: replace(request, session=UUID(int=9)),
    lambda request: replace(request, spec=replace(request.spec, uid=60002)),
    lambda request: replace(request, spec=replace(
        request.spec, limits=replace(request.spec.limits, scratch_bytes=1),
    )),
])
def test_exchange_rejects_session_spec_or_revision_rebinding(change):
    exchange, request, _, _ = setup()
    exchange.issue(request)
    with pytest.raises(ValueError, match="changed"):
        exchange.issue(change(request))


def test_issue_rejects_clock_rollback():
    exchange, request, _, clock = setup()
    exchange.issue(request)
    clock.now = 99
    with pytest.raises(ValueError, match="changed"):
        exchange.issue(request)


def test_new_challenge_during_authentication_invalidates_old_result():
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)
    issued = []

    def supersede(value):
        issued.append(exchange.issue(replace(request, revision=request.revision + 1)))
        return value

    auth.transform = supersede
    report = exchange.assess(challenge, auth.approved)
    assert not report.consistent and "invalidated" in report.errors[0]
    auth.transform = lambda value: value
    auth.approved = response_for(issued[0])
    assert exchange.assess(issued[0], auth.approved).consistent


def test_concurrent_replay_consumes_challenge_only_once():
    exchange, request, auth, _ = setup()
    challenge = exchange.issue(request)
    auth.approved = response_for(challenge)
    reports = []
    errors = []

    def assess():
        try:
            reports.append(exchange.assess(challenge, auth.approved))
        except Exception as error:
            errors.append(error)

    threads = [threading.Thread(target=assess) for _ in range(8)]
    try:
        for thread in threads:
            thread.start()
    finally:
        for thread in threads:
            if thread.ident is not None:
                thread.join(2)
    assert all(not thread.is_alive() for thread in threads)
    assert not errors and len(reports) == 8
    assert sum(report.consistent for report in reports) == 1
    for report in reports:
        denied(report)
