from dataclasses import replace
from uuid import uuid4

import pytest

from gvai.linux_containment_identity import ContainmentIdentity
from gvai.systemd_observation_validator import validate_observation
from gvai.systemd_worker_contract import (
    ManagerObservation,
    REQUIRED_RESTRICTIONS,
    ResourceLimits,
    WorkerIdentity,
    WorkerSpec,
)


def sample():
    session, request, boot = uuid4(), uuid4(), uuid4()
    spec = WorkerSpec(
        WorkerIdentity(uuid4(), boot, ContainmentIdentity(1, 10)),
        1001, 1001,
        ResourceLimits(64 * 1024**2, 8, 50, 1024**2),
    )
    observation = ManagerObservation(
        session, request, spec, spec.identity.service,
        REQUIRED_RESTRICTIONS, "trusted-manager",
        True, True, True, True,
    )
    return observation, spec, session, request


def assert_invalid(observation, spec, session, request):
    result = validate_observation(observation, spec, session, request)
    assert not result.structurally_valid
    assert not result.cleanup_complete
    return result


def test_complete_record_is_structurally_valid_but_never_authoritative():
    observation, spec, session, request = sample()
    result = validate_observation(observation, spec, session, request)

    assert result.structurally_valid
    assert result.cleanup_complete
    assert result.reason == "record structurally complete"
    assert result.authenticated is False
    assert result.execution_authorized is False
    assert result.runtime_isolation_established is False
    assert result.output_publication_authorized is False
    assert not result
    assert not hasattr(result, "accepted")


def test_forged_complete_observation_cannot_authorize_anything():
    observation, spec, session, request = sample()
    forged = replace(
        observation,
        reaper="trusted-manager",
        restrictions=frozenset(REQUIRED_RESTRICTIONS),
    )

    result = validate_observation(forged, spec, session, request)

    assert result.structurally_valid
    assert result.cleanup_complete
    assert result.authenticated is False
    assert result.execution_authorized is False
    assert result.runtime_isolation_established is False
    assert result.output_publication_authorized is False


def test_unknown_or_inactive_looking_records_are_rejected():
    _, spec, session, request = sample()
    for unknown in ({}, None, True, "inactive"):
        assert_invalid(unknown, spec, session, request)


@pytest.mark.parametrize("field", ["session", "request"])
def test_stale_session_or_request_is_rejected(field):
    observation, spec, session, request = sample()
    stale = replace(observation, **{field: uuid4()})
    assert_invalid(stale, spec, session, request)


def test_cached_observation_is_rejected_for_a_new_request():
    observation, spec, session, request = sample()
    assert validate_observation(observation, spec, session, request).structurally_valid
    assert_invalid(observation, spec, session, uuid4())


@pytest.mark.parametrize("field", ["attempt", "cgroup", "uid", "gid", "limits"])
def test_mismatched_worker_identity_or_resource_limits_are_rejected(field):
    observation, spec, session, request = sample()
    if field == "attempt":
        identity = replace(spec.identity, attempt=uuid4())
        other = replace(spec, identity=identity)
    elif field == "cgroup":
        identity = replace(
            spec.identity,
            cgroup=ContainmentIdentity(spec.identity.cgroup.device, 11),
        )
        other = replace(spec, identity=identity)
    elif field == "uid":
        other = replace(spec, uid=1002)
    elif field == "gid":
        other = replace(spec, gid=1002)
    else:
        other = replace(
            spec, limits=ResourceLimits(1, 2, 3, 4),
        )

    assert_invalid(replace(observation, spec=other), spec, session, request)


def test_wrong_service_name_is_rejected():
    observation, spec, session, request = sample()
    assert_invalid(
        replace(observation, service="ssh.service"), spec, session, request,
    )


@pytest.mark.parametrize("restrictions", [
    REQUIRED_RESTRICTIONS - {"private-pid"},
    REQUIRED_RESTRICTIONS | {"unverified-claim"},
    frozenset({"all-restrictions"}),
    set(REQUIRED_RESTRICTIONS),
    ["private-pid"],
    None,
])
def test_missing_extra_forged_or_malformed_restrictions_are_rejected(restrictions):
    observation, spec, session, request = sample()
    assert_invalid(
        replace(observation, restrictions=restrictions),
        spec, session, request,
    )


@pytest.mark.parametrize(("field", "value"), [
    ("session", "session"),
    ("request", None),
    ("service", 17),
    ("reaper", "worker"),
    ("kill_requested", 1),
    ("empty", "true"),
    ("descendants_reaped", None),
    ("terminal", 1),
])
def test_malformed_field_types_are_rejected(field, value):
    observation, spec, session, request = sample()
    assert_invalid(
        replace(observation, **{field: value}), spec, session, request,
    )


@pytest.mark.parametrize("changes", [
    {"kill_requested": False},
    {"terminal": True, "empty": False},
    {"terminal": True, "descendants_reaped": False},
    {"empty": False, "descendants_reaped": True},
    {"terminal": False, "empty": True, "descendants_reaped": True},
])
def test_contradictory_stop_and_reaping_evidence_is_rejected(changes):
    observation, spec, session, request = sample()
    assert_invalid(
        replace(observation, **changes), spec, session, request,
    )


@pytest.mark.parametrize("empty", [False, True])
def test_nonterminal_cleanup_is_structural_only_and_not_success(empty):
    observation, spec, session, request = sample()
    pending = replace(
        observation, empty=empty, descendants_reaped=False, terminal=False,
    )

    result = validate_observation(pending, spec, session, request)

    assert result.structurally_valid
    assert not result.cleanup_complete
    assert result.reason == "cleanup still pending"
    assert result.authenticated is False
    assert result.execution_authorized is False
    assert result.runtime_isolation_established is False
    assert result.output_publication_authorized is False
