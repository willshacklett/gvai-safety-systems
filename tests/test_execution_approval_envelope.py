from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import pytest

from gvai.execution_approval_envelope import (
    DOMAIN_PREFIX, MAX_ENVELOPE_BYTES, EnvelopeRejected, parse_execution_approval,
)


NOW = 1_800_000_000
ROOT = Path(__file__).resolve().parents[1]


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def prohibited(*args, **kwargs):
        raise AssertionError("No network or workload execution in envelope tests.")

    monkeypatch.setattr(socket, "socket", prohibited)
    monkeypatch.setattr(socket, "create_connection", prohibited)
    monkeypatch.setattr(socket, "getaddrinfo", prohibited)
    monkeypatch.setattr(subprocess, "Popen", prohibited)


@pytest.fixture
def envelope():
    action = {
        "tool_id": "synthetic-tool", "executable_sha256": "1" * 64,
        "arguments": ["synthetic", "argument"],
        "inputs": [{"id": "input-1", "sha256": "2" * 64}],
        "resources": [{"id": "resource-1", "sha256": "3" * 64}],
        "outputs": [{"id": "output-1", "sha256": "4" * 64}],
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
        "effects": ["effect:a", "effect:b"],
        "policy": {"sha256": "8" * 64, "epoch": 1},
        "observation": {
            "id": "synthetic-observation", "source_id": "synthetic-sentinel",
            "sha256": "9" * 64, "sequence": 1, "observed_at": NOW - 1,
            "expires_at": NOW + 59, "status": "stable", "halted": False,
        },
        "human_decision_id": "synthetic-decision",
        "control": {"epoch": 1, "revocation_generation": 1, "shutdown_generation": 1},
        "issued_at": NOW - 1, "not_before": NOW, "expires_at": NOW + 59,
        # Deliberately invalid cryptographic evidence: no signing keys or credentials.
        "auth": {"algorithm": "Ed25519", "key_id": "synthetic-key", "signature": "0" * 128},
    }


def unsigned(envelope):
    value = deepcopy(envelope)
    del value["auth"]["signature"]
    return value


def parse(envelope, *, expected=None, now=NOW):
    return parse_execution_approval(
        json.dumps(envelope), now=now,
        expected_payload=unsigned(envelope) if expected is None else expected,
    )


def test_canonical_bytes_have_exact_domain_and_never_authorize(envelope):
    result = parse(envelope)
    assert result.signing_bytes == b"GVAI-EXECUTION-APPROVAL-V1\n" + canonical(unsigned(envelope))
    assert result.canonical_envelope == canonical(envelope)
    assert result.allowed is result.authenticated is False
    assert not result
    assert not result.signing_bytes.startswith(b"GVAI-SHUTDOWN")


def test_recursive_key_order_and_whitespace_are_deterministic(envelope):
    def reverse(value):
        if isinstance(value, dict):
            return {key: reverse(child) for key, child in reversed(list(value.items()))}
        if isinstance(value, list):
            return [reverse(child) for child in value]
        return value

    result = parse_execution_approval(
        json.dumps(reverse(envelope), indent=3).encode("ascii"),
        now=NOW, expected_payload=unsigned(envelope),
    )
    assert result == parse(envelope)


@pytest.mark.parametrize("field", [
    "version", "purpose", "approval_id", "challenge", "issuer_id", "approver_id",
    "scope", "audience", "workload", "action", "action_sha256", "effects",
    "policy", "observation", "human_decision_id", "control", "issued_at",
    "not_before", "expires_at", "auth",
])
def test_every_binding_is_required(envelope, field):
    expected = unsigned(envelope)
    del envelope[field]
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


@pytest.mark.parametrize("path,value", [
    (("version",), True), (("version",), 2), (("purpose",), "shutdown"),
    (("purpose",), "READY"), (("issuer_id",), "*"), (("approver_id",), "x" * 129),
    (("approval_id",), "not-a-uuid"), (("approval_id",), "00000000-0000-0000-0000-000000000001"),
    (("scope",), []), (("scope",), ["b", "a"]), (("scope",), ["a", "a"]),
    (("scope",), [f"a{i:02}" for i in range(17)]),
    (("effects",), ["effect:b", "effect:a"]), (("effects",), ["a", "a"]),
    (("effects",), [f"a{i:03}" for i in range(129)]),
    (("policy", "epoch"), True), (("policy", "epoch"), -1),
    (("policy", "epoch"), 2**63), (("policy", "sha256"), "A" * 64),
    (("control", "epoch"), "1"), (("auth", "algorithm"), "HMAC-SHA256"),
    (("auth", "key_id"), "https://untrusted.invalid/key"),
    (("auth", "signature"), ""), (("auth", "signature"), "A" * 128),
    (("auth", "signature"), "0" * 127),
    (("observation", "halted"), True), (("observation", "halted"), 0),
    (("observation", "status"), "unknown"), (("observation", "status"), "irrecoverable"),
    (("observation", "observed_at"), NOW + 1),
    (("observation", "observed_at"), NOW - 61),
    (("observation", "expires_at"), NOW),
    (("observation", "expires_at"), NOW + 60),
    (("issued_at",), NOW + 1), (("issued_at",), NOW - 61),
    (("not_before",), NOW + 1), (("not_before",), NOW - 2),
    (("expires_at",), NOW), (("expires_at",), NOW + 60),
    (("issued_at",), False),
    (("action", "limits", "duration_seconds"), 60),
    (("action", "limits", "memory_bytes"), 0),
    (("action", "arguments"), ["\x00"]), (("action", "arguments"), ["é"]),
    (("action", "arguments"), ["x" * 1025]),
    (("action", "inputs"), [{"id": "a", "sha256": "0" * 64}] * 2),
])
def test_invalid_claims_reject_even_with_matching_expected_context(envelope, path, value):
    target = envelope
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if path[0] == "action":
        envelope["action_sha256"] = hashlib.sha256(canonical(envelope["action"])).hexdigest()
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


@pytest.mark.parametrize("path,value", [
    (("issuer_id",), "other-issuer"), (("approver_id",), "other-approver"),
    (("approval_id",), "00000000-0000-4000-8000-000000000003"),
    (("challenge",), "a" * 64), (("scope",), ["other-scope"]),
    (("audience", "supervisor_id"), "other-supervisor"),
    (("audience", "environment_id"), "other-environment"),
    (("audience", "tenant_id"), "other-tenant"),
    (("audience", "boot_id"), "00000000-0000-4000-8000-000000000003"),
    (("workload", "instance_id"), "other-worker"),
    (("workload", "bundle_sha256"), "a" * 64),
    (("workload", "revision"), "a" * 40),
    (("action", "tool_id"), "other-tool"),
    (("action", "arguments"), ["changed"]),
    (("action", "inputs"), [{"id": "changed", "sha256": "a" * 64}]),
    (("action", "resources"), []), (("action", "outputs"), []),
    (("effects",), ["effect:a"]), (("effects",), ["effect:a", "effect:b", "effect:c"]),
    (("policy", "sha256"), "a" * 64), (("policy", "epoch"), 2),
    (("observation", "sha256"), "a" * 64), (("observation", "sequence"), 2),
    (("human_decision_id",), "other-decision"),
    (("control", "epoch"), 2), (("control", "revocation_generation"), 2),
    (("control", "shutdown_generation"), 2), (("auth", "key_id"), "other-key"),
])
def test_substitution_against_frozen_expected_payload_rejects(envelope, path, value):
    expected = unsigned(envelope)
    target = envelope
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    if path[0] == "action":
        envelope["action_sha256"] = hashlib.sha256(canonical(envelope["action"])).hexdigest()
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


@pytest.mark.parametrize("path", [(), ("auth",), ("action",), ("action", "limits"),
                                ("observation",), ("audience",), ("control",)])
def test_unknown_fields_reject_recursively(envelope, path):
    target = envelope
    for key in path:
        target = target[key]
    target["approved"] = True
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


@pytest.mark.parametrize("raw", [
    b"\xff", "\ufeff{}", "{}", "[]", "null", "true",
    '{"version":1,"version":1}', '{"auth":{"key_id":"a","key_id":"b"}}',
    '{"value":1.0}', '{"value":NaN}', '{"value":Infinity}',
    "[" * 9 + "0" + "]" * 9, " " * (MAX_ENVELOPE_BYTES + 1),
    b"GVAI-SHUTDOWN-V1\n{}", DOMAIN_PREFIX + b"{}",
])
def test_invalid_wire_inputs_reject(envelope, raw):
    with pytest.raises(EnvelopeRejected):
        parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))


def test_nested_duplicates_in_otherwise_complete_envelope_reject(envelope):
    raw = json.dumps(envelope).replace('"epoch": 1', '"epoch": 1, "epoch": 1', 1)
    with pytest.raises(EnvelopeRejected):
        parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))


@pytest.mark.parametrize("now", [None, True, -1, float("nan"), float(NOW), NOW + 59])
def test_untrusted_or_expired_time_rejects(envelope, now):
    with pytest.raises(EnvelopeRejected):
        parse(envelope, now=now)


def test_changed_signature_changes_only_full_envelope_not_signing_bytes(envelope):
    first = parse(envelope)
    envelope["auth"]["signature"] = "f" * 128
    second = parse(envelope)
    assert first.signing_bytes == second.signing_bytes
    assert first.canonical_envelope != second.canonical_envelope
    assert not first.authenticated and not second.authenticated


def test_action_digest_mismatch_rejects(envelope):
    envelope["action"]["arguments"].append("tampered")
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


@pytest.mark.parametrize("expected", [None, True, {}, {"status": "READY"}, {"approved": True}])
def test_no_expected_context_or_registry_claim_is_sufficient(envelope, expected):
    with pytest.raises(EnvelopeRejected):
        parse_execution_approval(json.dumps(envelope), now=NOW, expected_payload=expected)


def test_expected_context_cannot_coerce_boolean_into_integer(envelope):
    expected = unsigned(envelope)
    expected["policy"]["epoch"] = True
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


def test_context_is_bounded_before_serialization(envelope):
    expected = unsigned(envelope)
    nested = expected
    for _ in range(9):
        nested["unexpected"] = {}
        nested = nested["unexpected"]
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)
    expected = unsigned(envelope)
    expected["cycle"] = expected
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)
    expected = unsigned(envelope)
    expected["unexpected"] = "x" * (MAX_ENVELOPE_BYTES + 1)
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


def test_context_rejects_coercible_subclasses_without_running_hooks(envelope):
    class CustomInteger(int):
        def __repr__(self):
            raise AssertionError("Do not invoke caller-controlled hooks.")

    expected = unsigned(envelope)
    expected["policy"]["epoch"] = CustomInteger(1)
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


def test_depth_scanner_respects_strings_and_escapes(envelope):
    envelope["action"]["arguments"] = ['[[[[[[[[[{{{', 'a\\"b', "}}}]]]]]]]]]"]
    envelope["action_sha256"] = hashlib.sha256(canonical(envelope["action"])).hexdigest()
    assert not parse(envelope)


def test_oversized_otherwise_valid_envelope_rejects(envelope):
    envelope["action"]["arguments"] = ["x" * 1024] * 128
    envelope["action_sha256"] = hashlib.sha256(canonical(envelope["action"])).hexdigest()
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


def test_no_runtime_integration_and_hard_gate_unchanged():
    for root in (ROOT / "gvai", ROOT / "scripts"):
        for path in root.rglob("*.py"):
            if path.name != "execution_approval_envelope.py":
                assert "execution_approval_envelope" not in path.read_text(encoding="utf-8")
    # No gate import: the independent existing HARD GATE tests retain their isolation guard.
    source = (ROOT / "gvai/authority_admission.py").read_text(encoding="utf-8")
    assert 'reasons = ["non_operational_contract", "independent_approval_unavailable"]' in source
