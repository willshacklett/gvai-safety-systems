from copy import deepcopy
import json
from pathlib import Path
import socket
import subprocess

from jsonschema import Draft202012Validator, ValidationError
import pytest
from referencing import Registry
from referencing.exceptions import NoSuchResource


ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / "evidence" / "iron-switch-viii"
REQUIRED_IDS = {
    "base-image", "hypervisor", "kernel", "bubblewrap", "apparmor",
    "reviewed-source", "policy-provenance", "python-dependencies",
    "provisioning-inputs", "administrator-export", "independent-ownership",
    "emergency-recovery",
}


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("Prerequisite checks cannot use networks or execute workloads.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(socket, "getaddrinfo", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)


def no_remote_references(uri):
    raise NoSuchResource(ref=uri)


def validate(document):
    schema = json.loads((DIRECTORY / "prerequisites.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(
        schema, registry=Registry(retrieve=no_remote_references),
    ).validate(document)
    ids = [item["id"] for item in document["requirements"]]
    if len(set(ids)) != len(ids) or set(ids) != REQUIRED_IDS:
        raise ValueError("Each prerequisite must appear exactly once.")


@pytest.fixture
def manifest():
    return json.loads((DIRECTORY / "prerequisites.json").read_text(encoding="utf-8"))


def test_inventory_is_valid_but_not_ready(manifest):
    schema = json.loads((DIRECTORY / "prerequisites.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validate(manifest)
    assert manifest["status"] == "blocked"
    assert all(item["status"] == "missing" for item in manifest["requirements"])
    assert not any(manifest["boundaries"].values())
    assert manifest["source"]["authoritative_experiment_revision"] is None
    assert manifest["review"]["approval_evidence"] is None


@pytest.mark.parametrize("identifier", sorted(REQUIRED_IDS))
def test_missing_prerequisite_blocks_validation(manifest, identifier):
    manifest["requirements"] = [
        item for item in manifest["requirements"] if item["id"] != identifier
    ]
    with pytest.raises(ValidationError):
        validate(manifest)


def test_duplicate_id_cannot_replace_missing_prerequisite(manifest):
    manifest["requirements"][1] = deepcopy(manifest["requirements"][0])
    manifest["requirements"][1]["required_evidence"] += " Different text."
    with pytest.raises(ValueError, match="exactly once"):
        validate(manifest)


@pytest.mark.parametrize(
    "path,value",
    [
        (("status",), "ready"),
        (("source", "authoritative_experiment_revision"), "1" * 40),
        (("source", "phase_v_status"), "verified"),
        (("source", "design_revision"), "latest"),
        (("target_claims", "classification"), "independently_verified"),
        (("requirements", 0, "status"), "verified"),
        (("requirements", 0, "verified_pin"), "latest"),
        (("requirements", 0, "evidence_sha256"), "0" * 64),
        (("review", "status"), "approved_by_agent"),
        (("review", "approval_evidence"), "claimed approval"),
    ],
)
def test_unsupported_readiness_or_provenance_claims_fail(manifest, path, value):
    target = manifest
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        validate(manifest)


@pytest.mark.parametrize(
    "boundary",
    [
        "provisioning_authorized", "policy_loading_authorized", "workloads_authorized",
        "digitalocean_access_authorized", "publication_authorized",
        "host_acceptance_verified", "independent_cancellation_verified",
        "emergency_recovery_verified",
    ],
)
def test_manifest_cannot_authorize_execution_or_claim_acceptance(manifest, boundary):
    manifest["boundaries"][boundary] = True
    with pytest.raises(ValidationError):
        validate(manifest)


def test_unknown_fields_and_omitted_review_are_rejected(manifest):
    changed = deepcopy(manifest)
    changed["execute"] = "not an operational instruction"
    with pytest.raises(ValidationError):
        validate(changed)
    del manifest["review"]
    with pytest.raises(ValidationError):
        validate(manifest)


def test_prerequisite_artifacts_are_not_public_site_assets():
    from scripts.prepare_public_site import PUBLIC_FILES

    assert not any(path.startswith("evidence/") for path in PUBLIC_FILES)
