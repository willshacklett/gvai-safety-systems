from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path
import socket
import subprocess

from jsonschema import Draft202012Validator, FormatChecker, ValidationError
import pytest
from referencing import Registry
from referencing.exceptions import NoSuchResource

from scripts.prepare_public_site import PUBLIC_FILES, prepare_site


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = "registry/schema/registry-1.0.0.schema.json"
REGISTRY_PATH = "registry/releases/0.1.0/registry.json"
MANIFEST_PATH = "registry/releases/0.1.0/integrity.json"
ARTIFACT_PATH = "experiments/results/gv_v2_acceptance.json"
TEST_PATH = "tests/test_os_sandbox.py"
GENERATOR_PATH = "experiments/agent_safety/v2_acceptance_report.py"
REFERENCE_FILES = frozenset({ARTIFACT_PATH, TEST_PATH, GENERATOR_PATH})
MANIFEST_FILES = frozenset({SCHEMA_PATH, REGISTRY_PATH})


@pytest.fixture(autouse=True)
def prohibit_network_and_workloads(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("Registry tests must not access the network or run workloads.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(socket, "getaddrinfo", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def load_json(path):
    return json.loads(
        path.read_bytes().decode("utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_constant,
    )


def reject_remote_reference(uri):
    raise NoSuchResource(ref=uri)


FORMATS = FormatChecker()


@FORMATS.checks("date-time", raises=ValueError)
def utc_timestamp(value):
    if not isinstance(value, str):
        return True
    return datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() == timedelta(0)


def validator(schema):
    return Draft202012Validator(
        schema,
        registry=Registry(retrieve=reject_remote_reference),
        format_checker=FORMATS,
    )


def local_file(root, reference, allowed):
    if reference not in allowed:
        raise ValueError("Reference is not explicitly allowlisted.")
    root = root.resolve()
    candidate = root
    for part in Path(reference).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("Symlink references are not allowed.")
    candidate.resolve().relative_to(root)
    if not candidate.is_file():
        raise ValueError("Reference must resolve to a local file.")
    return candidate


def validate_registry(document):
    schema = load_json(ROOT / SCHEMA_PATH)
    validator(schema).validate(document)
    if document["release_version"] != Path(REGISTRY_PATH).parent.name:
        raise ValueError("Release version does not match its directory.")

    records = {}
    all_ids = set()
    for collection in ("safeguards", "scenarios", "failures", "evidence"):
        records[collection] = {}
        for record in document[collection]:
            if record["id"] in all_ids:
                raise ValueError("Record IDs must be globally unique.")
            all_ids.add(record["id"])
            records[collection][record["id"]] = record

    def resolve(collection, references):
        for reference in references:
            if reference not in records[collection]:
                raise ValueError(f"Unresolved {collection} reference: {reference}")

    for safeguard in document["safeguards"]:
        resolve("scenarios", safeguard["scenario_ids"])
        resolve("evidence", safeguard["evidence_ids"])
        for reference in safeguard["evidence_ids"]:
            evidence = records["evidence"][reference]
            if evidence["scenario_id"] not in safeguard["scenario_ids"]:
                raise ValueError("Evidence must describe a linked safeguard scenario.")
        if safeguard["evidence_status"] == "independently_reproduced" and not any(
            records["evidence"][reference]["evidence_status"] == "independently_reproduced"
            for reference in safeguard["evidence_ids"]
        ):
            raise ValueError("Independent safeguard status requires independent evidence.")

    for scenario in document["scenarios"]:
        reproduction = scenario["safe_reproduction"]
        path = local_file(ROOT, reproduction["test_file"], REFERENCE_FILES)
        if f"def {reproduction['test_name']}(" not in path.read_text(encoding="utf-8"):
            raise ValueError("Referenced test name is absent.")

    for failure in document["failures"]:
        resolve("safeguards", [failure["safeguard_id"]])
        resolve("evidence", failure["evidence_ids"])
        resolve("evidence", failure["mitigation"]["evidence_ids"])
        if failure["superseded_by"] is not None:
            resolve("failures", [failure["superseded_by"]])
            if failure["superseded_by"] == failure["id"]:
                raise ValueError("A failure cannot supersede itself.")

    for evidence in document["evidence"]:
        resolve("scenarios", [evidence["scenario_id"]])
        local_file(ROOT, evidence["test_identity"], REFERENCE_FILES)
        artifact = evidence["artifact"]
        path = local_file(ROOT, artifact["path"], REFERENCE_FILES)
        if hashlib.sha256(path.read_bytes()).hexdigest() != artifact["sha256"]:
            raise ValueError("Historical artifact digest mismatch.")


def verify_manifest(manifest, payloads):
    schema = load_json(ROOT / SCHEMA_PATH)
    manifest_schema = {
        "$schema": schema["$schema"],
        "$ref": "#/$defs/integrity",
        "$defs": schema["$defs"],
    }
    validator(manifest_schema).validate(manifest)
    if manifest["release_version"] != Path(MANIFEST_PATH).parent.name:
        raise ValueError("Manifest release version mismatch.")
    paths = [entry["path"] for entry in manifest["files"]]
    if len(set(paths)) != len(paths) or set(paths) != MANIFEST_FILES:
        raise ValueError("Manifest must contain each expected file exactly once.")
    if set(payloads) != MANIFEST_FILES:
        raise ValueError("Unexpected payload set.")
    for entry in manifest["files"]:
        if hashlib.sha256(payloads[entry["path"]]).hexdigest() != entry["sha256"]:
            raise ValueError("Manifest digest mismatch.")


@pytest.fixture
def specimen():
    return load_json(ROOT / REGISTRY_PATH)


def test_schema_and_specimen_are_valid(specimen):
    Draft202012Validator.check_schema(load_json(ROOT / SCHEMA_PATH))
    validate_registry(specimen)
    assert len(specimen["safeguards"]) == len(specimen["scenarios"]) == 1
    assert specimen["failures"] == []
    assert specimen["published_at"] is None
    assert specimen["source_snapshot"]["inspected_revision"] == "14d60a234856fd2c7d097a42cfd38ed6369bf494"


@pytest.mark.parametrize(
    "path,value",
    [
        (("schema_version",), "2.0.0"),
        (("release_version",), "0.2.0"),
        (("publication_status",), "published"),
        (("published_at",), "2026-10-20T00:00:00Z"),
        (("license",), "unlicensed"),
        (("safeguards", 0, "version"), "01.0.0"),
        (("safeguards", 0, "purpose"), "x" * 2001),
        (("safeguards", 0, "implementation_status"), "production_safe"),
        (("safeguards", 0, "evidence_status"), "independently_reproduced"),
        (("safeguards", 0, "scenario_ids"), ["missing-scenario"]),
        (("safeguards", 0, "evidence_ids"), ["missing-evidence"]),
        (("safeguards", 0, "adoption", "human_approval_required"), False),
        (("safeguards", 0, "adoption", "independent_enforcement_required"), False),
        (("safeguards", 0, "adoption", "on_missing_prerequisites"), "fallback"),
        (("safeguards", 0, "adoption", "required_external_controls"), []),
        (("safeguards", 0, "adoption", "verification_requirements"), ["same", "same"]),
        (("scenarios", 0, "safe_reproduction", "test_file"), "../private.json"),
        (("scenarios", 0, "safe_reproduction", "test_file"), "/etc/passwd"),
        (("scenarios", 0, "safe_reproduction", "test_file"), "https://example.org/test.py"),
        (("scenarios", 0, "safe_reproduction", "test_file"), "tests/missing.py"),
        (("scenarios", 0, "safe_reproduction", "test_name"), "test_absent"),
        (("scenarios", 0, "safe_reproduction", "automatic_execution"), True),
        (("evidence", 0, "recorded_at"), "2026-02-30T00:00:00Z"),
        (("evidence", 0, "test_counts", "skipped"), True),
        (("evidence", 0, "test_counts", "passed"), -1),
        (("evidence", 0, "scenario_id"), "missing-scenario"),
        (("evidence", 0, "artifact", "sha256"), "0" * 64),
        (("evidence", 0, "artifact", "path"), "data/sample_combined.csv"),
        (("evidence", 0, "assertion_type"), "measured_observation"),
        (("evidence", 0, "execution_status"), "measured_pass"),
        (("evidence", 0, "reproduction_status"), "independently_reproduced"),
        (("evidence", 0, "independent_reproducer"), "unsubstantiated-reproducer"),
    ],
)
def test_invalid_specimen_is_rejected(specimen, path, value):
    target = specimen
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    with pytest.raises((ValidationError, ValueError)):
        validate_registry(specimen)


@pytest.mark.parametrize(
    "section",
    ["supported_environment", "required_external_controls", "compatibility_exclusions",
     "verification_requirements", "independent_enforcement_required",
     "human_approval_required", "on_missing_prerequisites", "rollback_requirements"],
)
def test_every_adoption_requirement_is_mandatory(specimen, section):
    del specimen["safeguards"][0]["adoption"][section]
    with pytest.raises(ValidationError):
        validate_registry(specimen)


@pytest.mark.parametrize("collection", ["safeguards", "scenarios", "evidence"])
def test_duplicate_record_ids_are_rejected(specimen, collection):
    duplicate = deepcopy(specimen[collection][0])
    duplicate["version"] = "0.1.1"
    specimen[collection].append(duplicate)
    with pytest.raises(ValueError, match="globally unique"):
        validate_registry(specimen)


def test_cross_collection_id_collision_is_rejected(specimen):
    specimen["evidence"][0]["id"] = specimen["scenarios"][0]["id"]
    with pytest.raises(ValueError, match="globally unique"):
        validate_registry(specimen)


@pytest.mark.parametrize("collection", [None, "safeguards", "scenarios", "evidence"])
def test_executable_or_unknown_fields_are_rejected(specimen, collection):
    target = specimen if collection is None else specimen[collection][0]
    target["install_command"] = "not executable registry data"
    with pytest.raises(ValidationError):
        validate_registry(specimen)


def test_historical_provenance_and_outcome_match_retained_artifact(specimen):
    evidence = specimen["evidence"][0]
    artifact = load_json(ROOT / ARTIFACT_PATH)
    assert evidence["assertion_type"] == "attributed_historical_report"
    assert evidence["evidence_status"] == "historical_unreproduced"
    assert evidence["execution_status"] == "reported_pass"
    assert evidence["reproduction_status"] == "not_independently_reproduced"
    for field in ("producing_revision", "dependency_versions", "independent_reproducer"):
        assert evidence[field] is None
    assert evidence["test_counts"] == {"passed": None, "failed": None, "skipped": None}
    assert evidence["recorded_at"] == artifact["timestamp_utc"]
    for key, value in artifact["platform"].items():
        assert evidence["environment"][key] == value
    network = next(item for item in artifact["actions"] if item["action"] == "network_attack")
    assert network == {
        "action": "network_attack", "allowed": False, "committed": False,
        "halted": False, "observed_effects": ["unapproved_network_egress_attempt"],
        "os_boundary_failure": False,
    }
    for fragment in ("allowed=false", "committed=false", "halted=false",
                     "unapproved_network_egress_attempt", "os_boundary_failure=false"):
        assert fragment in evidence["observed_outcome"]
    assert artifact["passed"] is True
    assert specimen["scenarios"][0]["assertion_type"] == "hypothesis"


def synthetic_failure():
    return {
        "id": "synthetic-failure", "version": "0.1.0",
        "classification": "hypothetical", "assertion_type": "hypothesis",
        "safeguard_id": "sandbox-network-isolation", "affected_versions": ["0.1.0"],
        "description": "Synthetic schema fixture only; not an observed finding.",
        "evidence_ids": [],
        "mitigation": {
            "status": "proposed", "requirements": ["Independent review required."],
            "evidence_ids": [],
        },
        "superseded_by": None,
    }


def test_failure_format_accepts_explicitly_hypothetical_fixture(specimen):
    specimen["failures"] = [synthetic_failure()]
    validate_registry(specimen)


@pytest.mark.parametrize(
    "field,value",
    [
        ("classification", "observed"),
        ("assertion_type", "measured_observation"),
        ("affected_versions", []),
        ("safeguard_id", "missing-safeguard"),
        ("evidence_ids", ["missing-evidence"]),
        ("superseded_by", "missing-failure"),
        ("superseded_by", "synthetic-failure"),
        ("mitigation", {"status": "tested", "requirements": ["Synthetic"], "evidence_ids": []}),
    ],
)
def test_invalid_failure_claims_and_references_fail(specimen, field, value):
    failure = synthetic_failure()
    failure[field] = value
    specimen["failures"] = [failure]
    with pytest.raises((ValidationError, ValueError)):
        validate_registry(specimen)


def test_independent_status_requires_a_separate_measured_record(specimen):
    evidence = specimen["evidence"][0]
    evidence.update({
        "reproduction_status": "independently_reproduced",
        "evidence_status": "independently_reproduced",
        "independent_reproducer": "Synthetic fixture, not an actual reproducer.",
        "producing_revision": "1" * 40,
        "dependency_versions": ["Synthetic dependency metadata."],
    })
    with pytest.raises(ValidationError):
        validate_registry(specimen)


def test_integrity_covers_exact_bytes_and_rejects_tampering():
    manifest = load_json(ROOT / MANIFEST_PATH)
    payloads = {
        reference: local_file(ROOT, reference, MANIFEST_FILES).read_bytes()
        for reference in MANIFEST_FILES
    }
    verify_manifest(manifest, payloads)
    for reference in MANIFEST_FILES:
        tampered = dict(payloads)
        tampered[reference] += b" "
        with pytest.raises(ValueError, match="digest mismatch"):
            verify_manifest(manifest, tampered)
    assert manifest["publisher_authenticated"] is False


@pytest.mark.parametrize("mutation", ["duplicate", "unexpected", "wrong-release", "authenticated"])
def test_invalid_manifests_are_rejected(mutation):
    manifest = load_json(ROOT / MANIFEST_PATH)
    if mutation == "duplicate":
        manifest["files"][1] = dict(manifest["files"][0])
        manifest["files"][1]["sha256"] = "0" * 64
    elif mutation == "unexpected":
        manifest["files"][0]["path"] = ARTIFACT_PATH
    elif mutation == "wrong-release":
        manifest["release_version"] = "0.2.0"
    else:
        manifest["publisher_authenticated"] = True
    payloads = {reference: (ROOT / reference).read_bytes() for reference in MANIFEST_FILES}
    with pytest.raises((ValidationError, ValueError)):
        verify_manifest(manifest, payloads)


def test_local_reference_resolution_rejects_symlink_and_missing_file(tmp_path):
    with pytest.raises(ValueError, match="local file"):
        local_file(tmp_path, "missing.json", {"missing.json"})
    (tmp_path / "target.json").write_text("{}", encoding="utf-8")
    (tmp_path / "link.json").symlink_to(tmp_path / "target.json")
    with pytest.raises(ValueError, match="Symlink"):
        local_file(tmp_path, "link.json", {"link.json"})
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="Symlink"):
        local_file(tmp_path, "link/target.json", {"link/target.json"})


@pytest.mark.parametrize("raw", ['{"id": 1, "id": 2}', '{"value": NaN}', '{"value": Infinity}'])
def test_ambiguous_json_is_rejected(tmp_path, raw):
    path = tmp_path / "invalid.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError):
        load_json(path)


def test_schema_uses_only_internal_references():
    def visit(value):
        if isinstance(value, dict):
            if "$ref" in value:
                assert value["$ref"].startswith("#/$defs/")
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(load_json(ROOT / SCHEMA_PATH))
    with pytest.raises(NoSuchResource):
        reject_remote_reference("https://example.invalid/schema.json")


def test_existing_public_artifact_remains_unchanged_and_excludes_registry(tmp_path):
    expected = {
        "index.html", "site.css", "assets/gvai-mark.svg",
        "assets/GvAI-MIT-LICENSE.txt", "examples/gv_geometry_map.png",
    }
    assert set(PUBLIC_FILES) == expected
    output = prepare_site(tmp_path / "site")
    actual = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    assert actual == expected
    for reference in actual:
        assert (output / reference).read_bytes() == (ROOT / reference).read_bytes()
    assert not (output / "registry").exists()
    assert not (output / "docs").exists()
