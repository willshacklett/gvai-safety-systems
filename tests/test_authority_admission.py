from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import pytest

from gvai.authority_admission import AdmissionDenial, OfflineAuthorityAdmission


ROOT = Path(__file__).resolve().parents[1]
NOW = 1_800_000_000
REVISION = "1" * 40


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("Admission tests cannot use networks or launch workloads.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(socket, "getaddrinfo", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)


@pytest.fixture
def claims():
    return {
        "target_id": "synthetic-worker",
        "revision": REVISION,
        "now": NOW,
        "control_status": "verified",
        "observation": {
            "target_id": "synthetic-worker",
            "revision": REVISION,
            "source_id": "synthetic-sentinel",
            "status": "stable",
            "halted": False,
            "observed_at": NOW - 1,
            "expires_at": NOW + 59,
        },
        "enforcement": {
            "invariant_ids": ["synthetic-invariant"],
            "effect_requirements": ["synthetic-effect-check"],
            "independent_shutdown": True,
        },
        "approval": {
            "issuer_id": "synthetic-not-authenticated",
            "target_id": "synthetic-worker",
            "revision": REVISION,
            "issued_at": NOW - 1,
            "expires_at": NOW + 299,
            "signature": "fixture-only-not-a-verified-signature",
        },
    }


def denied(claims, reason):
    decision = OfflineAuthorityAdmission().evaluate(**claims)
    assert decision.allowed is False
    assert bool(decision) is False
    assert "non_operational_contract" in decision.reasons
    assert "independent_approval_unavailable" in decision.reasons
    assert reason in decision.reasons
    return decision


def test_complete_claims_still_deny(claims):
    decision = denied(claims, "external_approval_not_authenticated")
    assert decision.reasons == (
        "non_operational_contract",
        "independent_approval_unavailable",
        "external_approval_not_authenticated",
    )


def test_all_omitted_claims_deny():
    decision = OfflineAuthorityAdmission().evaluate()
    assert decision.allowed is False
    assert "control_not_explicitly_verified" in decision.reasons
    assert "missing_or_malformed_observation" in decision.reasons
    assert "missing_or_malformed_enforcement" in decision.reasons
    assert "missing_or_malformed_external_approval" in decision.reasons


def test_omitted_control_never_defaults_to_verified(claims):
    del claims["control_status"]
    denied(claims, "control_not_explicitly_verified")


@pytest.mark.parametrize(
    "status",
    [None, "unknown", "unverified", "degraded", "lost", "ambiguous", "VERIFIED",
     True, 1, {}, ["verified"]],
)
def test_unverified_control_ownership_denies(claims, status):
    claims["control_status"] = status
    denied(claims, "control_not_explicitly_verified")


@pytest.mark.parametrize("status", ["UNKNOWN", "ready", "allow", "", None, True, 0, [], {}])
def test_unknown_sentinel_state_denies(claims, status):
    claims["observation"]["status"] = status
    denied(claims, "unknown_sentinel_state")


@pytest.mark.parametrize("status", ["warning", "critical", "irrecoverable"])
def test_nonstable_states_cannot_be_used_as_authority(claims, status):
    claims["observation"]["status"] = status
    claims["observation"]["halted"] = status == "irrecoverable"
    denied(claims, "safety_state_not_admissible")


@pytest.mark.parametrize("value", [None, {}, [], "stable", True])
def test_missing_or_malformed_observations_deny(claims, value):
    claims["observation"] = value
    denied(claims, "missing_or_malformed_observation")


@pytest.mark.parametrize(
    "issued,expires",
    [
        (NOW - 61, NOW + 1),
        (NOW - 60, NOW),
        (NOW - 1, NOW - 1),
        (NOW + 1, NOW + 2),
        (NOW - 1, NOW + 60),
        (-1, NOW + 1),
        (True, NOW + 1),
        (NOW - 1, False),
        (float(NOW), NOW + 1),
        (NOW - 1, float("inf")),
        (float("nan"), NOW + 1),
        (None, NOW + 1),
        ("1800000000", NOW + 1),
    ],
)
def test_stale_future_or_malformed_observation_times_deny(claims, issued, expires):
    claims["observation"].update(observed_at=issued, expires_at=expires)
    denied(claims, "stale_or_invalid_observation_time")


@pytest.mark.parametrize("now", [None, True, -1, "1800000000", float("nan"), float(NOW)])
def test_missing_or_invalid_trusted_time_denies(claims, now):
    claims["now"] = now
    denied(claims, "invalid_trusted_time")


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("target_id", "other-worker", "observation_context_mismatch"),
        ("revision", "2" * 40, "observation_context_mismatch"),
        ("source_id", "", "observation_context_mismatch"),
        ("halted", True, "halted_or_contradictory_observation"),
        ("halted", 0, "halted_or_contradictory_observation"),
        ("halted", None, "halted_or_contradictory_observation"),
    ],
)
def test_mismatched_or_contradictory_safety_evidence_denies(claims, field, value, reason):
    claims["observation"][field] = value
    denied(claims, reason)


def test_irrecoverable_cannot_claim_not_halted(claims):
    claims["observation"].update(status="irrecoverable", halted=False)
    denied(claims, "halted_or_contradictory_observation")


@pytest.mark.parametrize("field", ["invariant_ids", "effect_requirements", "independent_shutdown"])
def test_missing_enforcement_fields_deny(claims, field):
    del claims["enforcement"][field]
    denied(claims, "missing_or_malformed_enforcement")


@pytest.mark.parametrize(
    "field,reason",
    [("invariant_ids", "missing_required_invariants"),
     ("effect_requirements", "missing_effect_enforcement")],
)
@pytest.mark.parametrize("value", [[], None, "", ["same", "same"], ["valid", 1], [""]])
def test_empty_or_malformed_required_enforcement_denies(claims, field, reason, value):
    claims["enforcement"][field] = value
    denied(claims, reason)


@pytest.mark.parametrize("value", [None, {}, [], True])
def test_missing_enforcement_configuration_denies(claims, value):
    claims["enforcement"] = value
    denied(claims, "missing_or_malformed_enforcement")


@pytest.mark.parametrize("value", [False, None, 1, "verified"])
def test_shutdown_claim_must_not_be_missing_or_coerced(claims, value):
    claims["enforcement"]["independent_shutdown"] = value
    denied(claims, "independent_shutdown_not_established")


@pytest.mark.parametrize(
    "evidence",
    [
        {"status": "READY", "approved": True, "human_approval_required": False},
        {"status": "ALLOW", "tests_passed": 114, "compliance": True},
        {"status": "BLOCKED", "approved": True},
        {"publisher_authenticated": True, "sha256": "0" * 64},
        {},
    ],
)
def test_registry_only_approval_cannot_authorize(claims, evidence):
    claims["registry_evidence"] = evidence
    claims["approval"] = evidence
    denied(claims, "registry_evidence_is_not_authority")
    denied(claims, "missing_or_malformed_external_approval")


def test_self_consistent_unsigned_manifest_is_not_approval(claims):
    payload = b"synthetic evidence, not authentication"
    manifest = {"sha256": hashlib.sha256(payload).hexdigest(), "tests_passed": True}
    assert manifest["sha256"] == hashlib.sha256(payload).hexdigest()
    claims["registry_evidence"] = manifest
    claims["approval"] = manifest
    denied(claims, "missing_or_malformed_external_approval")


def test_existing_registry_and_blocked_inventory_never_authorize(claims):
    paths = (
        ROOT / "registry/releases/0.1.0/registry.json",
        ROOT / "registry/releases/0.1.0/integrity.json",
        ROOT / "evidence/iron-switch-viii/prerequisites.json",
    )
    for path in paths:
        document = json.loads(path.read_text(encoding="utf-8"))
        attempt = deepcopy(claims)
        attempt.update(registry_evidence=document, approval=document)
        denied(attempt, "missing_or_malformed_external_approval")


@pytest.mark.parametrize("value", [None, {}, True, 1, "approved", [], b"signature"])
def test_missing_or_malformed_approval_denies(claims, value):
    claims["approval"] = value
    denied(claims, "missing_or_malformed_external_approval")


@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer_id", ""),
        ("target_id", "other-worker"),
        ("revision", "2" * 40),
        ("issued_at", NOW + 1),
        ("issued_at", NOW - 301),
        ("issued_at", True),
        ("expires_at", NOW),
        ("expires_at", NOW + 300),
        ("expires_at", None),
        ("signature", ""),
        ("signature", True),
        ("signature", "x" * 4097),
    ],
)
def test_invalid_external_approval_claims_deny(claims, field, value):
    claims["approval"][field] = value
    denied(claims, "invalid_external_approval_claim")


@pytest.mark.parametrize("error", [RuntimeError("unavailable"), ValueError("invalid"), OSError("failed")])
def test_approval_verification_exceptions_never_authorize(claims, monkeypatch, error):
    def broken(approval):
        raise error

    monkeypatch.setattr(OfflineAuthorityAdmission, "_verify_approval", staticmethod(broken))
    denied(claims, "admission_check_failed_closed")


@pytest.mark.parametrize("result", [True, "verified", {"approved": True}, object()])
def test_even_lying_approval_fixture_cannot_create_allow(claims, monkeypatch, result):
    monkeypatch.setattr(
        OfflineAuthorityAdmission, "_verify_approval", staticmethod(lambda approval: result),
    )
    denied(claims, "independent_approval_unavailable")


def test_registry_data_is_never_interpreted(claims):
    class UntrustedEvidence:
        def __bool__(self):
            raise AssertionError("Registry evidence must remain opaque.")

        def __getattribute__(self, name):
            raise AssertionError("Registry evidence must remain opaque.")

    claims["registry_evidence"] = UntrustedEvidence()
    denied(claims, "registry_evidence_is_not_authority")


def test_errors_during_untrusted_comparison_fail_closed(claims):
    class BrokenComparison:
        def __ne__(self, other):
            raise RuntimeError("malformed context")

    claims["observation"]["target_id"] = BrokenComparison()
    denied(claims, "admission_check_failed_closed")


def test_inputs_are_not_mutated_and_denial_has_no_settable_allow(claims):
    before = deepcopy(claims)
    decision = denied(claims, "external_approval_not_authenticated")
    assert claims == before
    with pytest.raises((FrozenInstanceError, AttributeError)):
        decision.allowed = True
    assert AdmissionDenial(()).allowed is False


def test_unknown_approval_fields_cannot_expand_authority(claims):
    claims["approval"]["override_shutdown"] = True
    denied(claims, "missing_or_malformed_external_approval")


def test_no_runtime_or_publication_imports_admission_contract():
    roots = [ROOT / "gvai", ROOT / "scripts"]
    admission = ROOT / "gvai/authority_admission.py"
    for directory in roots:
        for path in directory.rglob("*.py"):
            if path != admission:
                assert "authority_admission" not in path.read_text(encoding="utf-8")
