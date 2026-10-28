from copy import deepcopy
import hashlib
import json
from pathlib import Path
import socket
import subprocess

import pytest

from gvai.execution_approval_envelope import (
    DOMAIN_PREFIX, MAX_DEPTH, MAX_ENVELOPE_BYTES, EnvelopeRejected,
    _bounded_depth, parse_execution_approval,
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


# Independent, literal known-answer bytes; do not derive these from the serializer.
GOLDEN_PAYLOAD = (
    b'{"action":{"arguments":["synthetic","argument"],"executable_sha256":'
    b'"1111111111111111111111111111111111111111111111111111111111111111",'
    b'"inputs":[{"id":"input-1","sha256":'
    b'"2222222222222222222222222222222222222222222222222222222222222222"}],'
    b'"limits":{"duration_seconds":1,"memory_bytes":1024,"output_bytes":1024},'
    b'"outputs":[{"id":"output-1","sha256":'
    b'"4444444444444444444444444444444444444444444444444444444444444444"}],'
    b'"resources":[{"id":"resource-1","sha256":'
    b'"3333333333333333333333333333333333333333333333333333333333333333"}],'
    b'"tool_id":"synthetic-tool"},'
    b'"action_sha256":"77d60b1dd18bcb2fd3bc5f1e2f436eada1c707c09a705f64f5cfeec1b98e3b00",'
    b'"approval_id":"00000000-0000-4000-8000-000000000001",'
    b'"approver_id":"synthetic-human","audience":{'
    b'"boot_id":"00000000-0000-4000-8000-000000000002","environment_id":"offline",'
    b'"supervisor_id":"synthetic-supervisor","tenant_id":"synthetic-tenant"},'
    b'"auth":{"algorithm":"Ed25519","key_id":"synthetic-key"},'
    b'"challenge":"5555555555555555555555555555555555555555555555555555555555555555",'
    b'"control":{"epoch":1,"revocation_generation":1,"shutdown_generation":1},'
    b'"effects":["effect:a","effect:b"],"expires_at":1800000059,'
    b'"human_decision_id":"synthetic-decision","issued_at":1799999999,'
    b'"issuer_id":"synthetic-issuer","not_before":1800000000,'
    b'"observation":{"expires_at":1800000059,"halted":false,'
    b'"id":"synthetic-observation","observed_at":1799999999,"sequence":1,'
    b'"sha256":"9999999999999999999999999999999999999999999999999999999999999999",'
    b'"source_id":"synthetic-sentinel","status":"stable"},'
    b'"policy":{"epoch":1,'
    b'"sha256":"8888888888888888888888888888888888888888888888888888888888888888"},'
    b'"purpose":"execute-once","scope":["execute:synthetic"],"version":1,'
    b'"workload":{'
    b'"bundle_sha256":"6666666666666666666666666666666666666666666666666666666666666666",'
    b'"instance_id":"synthetic-worker","revision":"7777777777777777777777777777777777777777"}}'
)
GOLDEN_ENVELOPE = GOLDEN_PAYLOAD.replace(
    b'"key_id":"synthetic-key"}',
    b'"key_id":"synthetic-key","signature":"'
    b'0000000000000000000000000000000000000000000000000000000000000000'
    b'0000000000000000000000000000000000000000000000000000000000000000"}',
)


def assert_no_authority(result):
    assert result.allowed is False
    assert result.authenticated is False
    assert bool(result) is False


def at_path(value, path):
    for key in path:
        value = value[key]
    return value


def leaf_paths(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaf_paths(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaf_paths(child, path + (index,))
    else:
        yield path


def object_paths(value, path=()):
    if isinstance(value, dict):
        yield path
        for key, child in value.items():
            yield from object_paths(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from object_paths(child, path + (index,))


def refresh_action_digest(value):
    value["action_sha256"] = hashlib.sha256(canonical(value["action"])).hexdigest()


def wire_value(envelope, path, token):
    value = deepcopy(envelope)
    at_path(value, path[:-1])[path[-1]] = "__WIRE_TOKEN__"
    return canonical(value).replace(b'"__WIRE_TOKEN__"', token)


def reject_before(raw, expected, monkeypatch, stage):
    import gvai.execution_approval_envelope as module

    def unexpected_stage(*args, **kwargs):
        pytest.fail(f"Malformed wire reached {stage}.")

    with monkeypatch.context() as patch:
        patch.setattr(module, stage, unexpected_stage)
        with pytest.raises(EnvelopeRejected):
            parse_execution_approval(raw, now=NOW, expected_payload=expected)


@pytest.mark.parametrize("encoding", ["compact", "pretty", "escaped", "bytes"])
def test_literal_known_answer_for_equivalent_encodings(envelope, encoding):
    raw = json.dumps(envelope, indent=2) if encoding == "pretty" else json.dumps(envelope)
    if encoding == "escaped":
        raw = raw.replace("synthetic", r"\u0073ynthetic").replace("version", r"\u0076ersion")
    if encoding == "bytes":
        raw = raw.encode("ascii")
    result = parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))
    assert result.canonical_payload == GOLDEN_PAYLOAD
    assert result.canonical_envelope == GOLDEN_ENVELOPE
    assert result.signing_bytes == b"GVAI-EXECUTION-APPROVAL-V1\n" + GOLDEN_PAYLOAD
    assert_no_authority(result)


@pytest.mark.parametrize("fault", ["missing", "extra", "duplicate", "escaped-duplicate"])
def test_each_object_boundary_with_otherwise_complete_wire(envelope, fault, monkeypatch):
    expected = unsigned(envelope)
    assert_no_authority(parse(envelope, expected=expected))
    for path in object_paths(envelope):
        original = at_path(envelope, path)
        for key in original:
            value = deepcopy(envelope)
            target = at_path(value, path)
            if fault == "missing":
                del target[key]
            elif fault == "extra":
                target["unexpected"] = False
            if fault in ("missing", "extra"):
                if path and path[0] == "action":
                    refresh_action_digest(value)
                raw = canonical(value)
            else:
                raw_object = canonical(original)
                encoded_key = json.dumps(key).encode("ascii")
                duplicate_key = encoded_key
                if fault == "escaped-duplicate":
                    duplicate_key = ('"\\u%04x%s"' % (ord(key[0]), key[1:])).encode("ascii")
                replacement = (
                    b"{" + duplicate_key + b":" + canonical(original[key]) + b","
                    + raw_object[1:]
                )
                raw = canonical(envelope).replace(raw_object, replacement, 1)
                assert raw != canonical(envelope)
            # Schema faults must reject before snapshot processing; duplicate
            # faults must reject even earlier, before claim validation.
            stage = "_bounded_context" if fault in ("missing", "extra") else "_validate"
            reject_before(raw, expected, monkeypatch, stage)


def test_every_mutable_leaf_is_bound_to_unchanged_snapshot(envelope):
    expected = unsigned(envelope)
    fixed = {("version",), ("purpose",), ("auth", "algorithm"),
             ("observation", "status"), ("observation", "halted")}
    for path in leaf_paths(envelope):
        if path in fixed or path == ("auth", "signature"):
            continue
        value = deepcopy(envelope)
        old = at_path(value, path)
        if path[-1] in ("approval_id", "boot_id"):
            replacement = "00000000-0000-4000-8000-000000000003"
        elif path in (("issued_at",), ("observation", "observed_at")):
            replacement = old + 1
        elif path in (("not_before",), ("expires_at",), ("observation", "expires_at")):
            replacement = old - 1
        elif isinstance(old, int):
            replacement = old + 1
        elif path[-1] in ("sha256", "bundle_sha256", "executable_sha256",
                          "action_sha256", "revision", "challenge"):
            replacement = ("a" if old[0] != "a" else "b") + old[1:]
        else:
            replacement = old + "-changed"
        at_path(value, path[:-1])[path[-1]] = replacement
        if path[0] == "action":
            # Repair only the derived digest, so the substituted action is itself valid.
            refresh_action_digest(value)
        if path != ("action_sha256",):
            assert_no_authority(parse(value))
        with pytest.raises(EnvelopeRejected):
            parse(value, expected=expected)


def test_each_leaf_rejects_wrong_type_before_snapshot_comparison(envelope, monkeypatch):
    expected = unsigned(envelope)
    assert_no_authority(parse(envelope))
    for path in leaf_paths(envelope):
        value = deepcopy(envelope)
        at_path(value, path[:-1])[path[-1]] = {}
        if path[0] == "action":
            refresh_action_digest(value)
        reject_before(canonical(value), expected, monkeypatch, "_bounded_context")


def test_each_object_rejects_wrong_container_type(envelope, monkeypatch):
    expected = unsigned(envelope)
    assert_no_authority(parse(envelope))
    for path in object_paths(envelope):
        value = deepcopy(envelope)
        if path:
            at_path(value, path[:-1])[path[-1]] = None
            if path[0] == "action":
                refresh_action_digest(value)
        else:
            value = []
        reject_before(canonical(value), expected, monkeypatch, "_bounded_context")


@pytest.mark.parametrize("path,value", [
    (("version",), 2), (("purpose",), "shutdown"), (("auth", "algorithm"), "HMAC-SHA256"),
    (("observation", "status"), "critical"), (("observation", "halted"), True),
])
def test_fixed_semantic_fields_reject_with_otherwise_complete_context(envelope, path, value):
    assert_no_authority(parse(envelope))
    at_path(envelope, path[:-1])[path[-1]] = value
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


@pytest.mark.parametrize("token", [b"1.0", b"1e0", b"NaN", b"Infinity", b"-Infinity",
                                 b"true", b"null", b"-1", b"9223372036854775808"])
def test_numeric_faults_in_every_integer_field(envelope, token, monkeypatch):
    expected = unsigned(envelope)
    assert_no_authority(parse(envelope))
    for path in leaf_paths(envelope):
        if type(at_path(envelope, path)) is int:
            value = deepcopy(envelope)
            at_path(value, path[:-1])[path[-1]] = json.loads(token)
            if path[0] == "action":
                refresh_action_digest(value)
            raw = wire_value(value, path, token)
            stage = (
                "_validate"
                if token in (b"1.0", b"1e0", b"NaN", b"Infinity", b"-Infinity")
                else "_bounded_context"
            )
            reject_before(raw, expected, monkeypatch, stage)


@pytest.mark.parametrize("token", [br'"\u00e9"', br'"\ud800"', br'"\udfff"', br'"\u0000"'])
def test_escaped_unicode_faults_in_every_string_field(envelope, token, monkeypatch):
    expected = unsigned(envelope)
    assert_no_authority(parse(envelope))
    for path in leaf_paths(envelope):
        if type(at_path(envelope, path)) is str:
            value = deepcopy(envelope)
            at_path(value, path[:-1])[path[-1]] = json.loads(token)
            if path[0] == "action":
                refresh_action_digest(value)
            reject_before(wire_value(value, path, token), expected, monkeypatch, "_bounded_context")


@pytest.mark.parametrize("token", [br'"\q"', br'"\u00xz"', b'"unterminated', b"01", b"+1"])
def test_invalid_json_tokens_in_otherwise_complete_wire(envelope, token, monkeypatch):
    assert_no_authority(parse(envelope))
    reject_before(wire_value(envelope, ("policy", "epoch"), token),
                  unsigned(envelope), monkeypatch, "_validate")


@pytest.mark.parametrize("kind", ["trailing-object", "trailing-garbage", "bom", "utf8",
                                 "utf16", "truncated", "bad-byte"])
def test_transport_faults_around_complete_envelope(envelope, kind, monkeypatch):
    assert_no_authority(parse(envelope))
    raw = canonical(envelope)
    raw = {
        "trailing-object": raw + b"{}", "trailing-garbage": raw + b"x",
        "bom": b"\xef\xbb\xbf" + raw, "utf8": raw.replace(b"synthetic", b"\xc3\xa9", 1),
        "utf16": raw.decode("ascii").encode("utf-16"),
        "truncated": raw[:-1], "bad-byte": raw + b"\xff",
    }[kind]
    reject_before(raw, unsigned(envelope), monkeypatch, "_validate")


@pytest.mark.parametrize("size", [MAX_ENVELOPE_BYTES - 1, MAX_ENVELOPE_BYTES,
                                MAX_ENVELOPE_BYTES + 1])
@pytest.mark.parametrize("as_bytes", [False, True])
def test_exact_wire_size_boundary(envelope, size, as_bytes):
    raw = canonical(envelope)
    raw += b" " * (size - len(raw))
    if not as_bytes:
        raw = raw.decode("ascii")
    if size > MAX_ENVELOPE_BYTES:
        with pytest.raises(EnvelopeRejected):
            parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))
    else:
        result = parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))
        assert result.canonical_envelope == GOLDEN_ENVELOPE
        assert_no_authority(result)


def test_exact_depth_guard_boundary_before_schema_validation(envelope, monkeypatch):
    _bounded_depth("[" * MAX_DEPTH + "0" + "]" * MAX_DEPTH)
    with pytest.raises(EnvelopeRejected):
        _bounded_depth("[" * (MAX_DEPTH + 1) + "0" + "]" * (MAX_DEPTH + 1))
    # A deep structure cannot satisfy the closed schema; isolate the predecode guard.
    import gvai.execution_approval_envelope as module

    def no_decode(*args, **kwargs):
        pytest.fail("Excessive depth must reject before JSON decoding.")

    raw = wire_value(envelope, ("policy", "epoch"), b"[" * 9 + b"0" + b"]" * 9)
    with monkeypatch.context() as patch:
        patch.setattr(module.json, "loads", no_decode)
        with pytest.raises(EnvelopeRejected):
            parse_execution_approval(raw, now=NOW, expected_payload=unsigned(envelope))


@pytest.mark.parametrize("integer", [0, 2**63 - 1])
def test_integer_endpoints_and_negative_zero_canonicalization(envelope, integer):
    envelope["policy"]["epoch"] = integer
    expected = unsigned(envelope)
    raw = wire_value(envelope, ("policy", "epoch"), b"-0" if integer == 0 else str(integer).encode())
    result = parse_execution_approval(raw, now=NOW, expected_payload=expected)
    assert result.canonical_payload == canonical(expected)
    assert_no_authority(result)


@pytest.mark.parametrize("field,limit", [("scope", 16), ("effects", 128),
                                       ("arguments", 128), ("inputs", 128),
                                       ("resources", 128), ("outputs", 128)])
def test_each_list_size_endpoint_then_single_overflow(envelope, field, limit):
    target = envelope if field in ("scope", "effects") else envelope["action"]
    entries = [
        {"id": f"item-{i:03}", "sha256": "a" * 64}
        if field in ("inputs", "resources", "outputs") else f"item-{i:03}"
        for i in range(limit + 1)
    ]
    target[field] = entries[:-1]
    refresh_action_digest(envelope)
    assert_no_authority(parse(envelope))
    target[field] = entries
    refresh_action_digest(envelope)
    with pytest.raises(EnvelopeRejected):
        parse(envelope)


@pytest.mark.parametrize("field", ["scope", "effects", "inputs", "resources", "outputs"])
@pytest.mark.parametrize("fault", ["duplicate", "unsorted", "wrong-type"])
def test_each_canonical_list_rejects_single_fault(envelope, field, fault, monkeypatch):
    target = envelope if field in ("scope", "effects") else envelope["action"]
    if field in ("scope", "effects"):
        entries = ["item-a", "item-b"]
    else:
        entries = [{"id": name, "sha256": "a" * 64} for name in ("item-a", "item-b")]
    target[field] = entries
    refresh_action_digest(envelope)
    assert_no_authority(parse(envelope))
    expected = unsigned(envelope)
    if fault == "duplicate":
        target[field] = [entries[0], entries[0]]
    elif fault == "unsorted":
        target[field] = list(reversed(entries))
    else:
        target[field] = {}
    refresh_action_digest(envelope)
    reject_before(canonical(envelope), expected, monkeypatch, "_bounded_context")


def test_argument_order_is_bound_even_when_digest_is_repaired(envelope):
    expected = unsigned(envelope)
    envelope["action"]["arguments"].reverse()
    refresh_action_digest(envelope)
    assert_no_authority(parse(envelope))
    with pytest.raises(EnvelopeRejected):
        parse(envelope, expected=expected)


@pytest.mark.parametrize("signature", ["0" * 128, "f" * 128, "ab" * 64])
def test_repeated_tokens_and_altered_signatures_never_grant_authority(envelope, signature):
    expected = unsigned(envelope)
    envelope["auth"]["signature"] = signature
    results = [parse(envelope, expected=expected) for _ in range(3)]
    assert results[0] == results[1] == results[2]
    for result in results:
        assert result.canonical_payload == GOLDEN_PAYLOAD
        assert result.signing_bytes == b"GVAI-EXECUTION-APPROVAL-V1\n" + GOLDEN_PAYLOAD
        assert_no_authority(result)
