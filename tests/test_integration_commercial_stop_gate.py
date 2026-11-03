"""Integration of the commercial advisory stack with the external STOP gate.

Scope and honesty: the runtime tests use the SIMULATED separation model from
gvai.experimental_external_gate (child processes, one UID, one kernel). They show that the
commercial service's *permitted interfaces* give no path to gate keys, latch state or the trusted
anchor and that the protected backend fails closed. They do NOT prove host-level isolation; the
static checks only inspect inactive deployment files. See docs/integration_advisory_launch_v1.md.
"""

import ast
import configparser
import glob
import hashlib
import json
import os
import time

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_external_gate as eg
from gvai.commercial_service import CommercialEvaluationService, ServiceOutcome
from test_commercial_service import valid_telemetry  # noqa: F401  (shared fixtures)
from test_commercial_service import service_fixture  # noqa: F401
from test_experimental_external_gate import Deployment, signed

ROOT = os.path.join(os.path.dirname(__file__), "..")
GVAI = os.path.join(ROOT, "gvai")
PRIVATE_HTTPS = os.path.join(ROOT, "deploy", "private_https")
STOP_GATE = os.path.join(ROOT, "deploy", "stop_gate")

GATE_MODULES = {
    "gvai.experimental_external_gate",
    "gvai.experimental_stop_latch",
    "gvai.external_gate_service",
    "gvai.host_isolation_acceptance",
}
COMMERCIAL_FILES = sorted(
    glob.glob(os.path.join(GVAI, "commercial_*.py"))
    + glob.glob(os.path.join(GVAI, "postgresql_*.py"))
    + [os.path.join(GVAI, "private_staging.py"), os.path.join(GVAI, "evaluation.py")]
)
GATE_FILES = [
    os.path.join(GVAI, "experimental_external_gate.py"),
    os.path.join(GVAI, "experimental_stop_latch.py"),
    os.path.join(GVAI, "external_gate_service.py"),
]
FORBIDDEN_TEXT = (
    "gvai-stop-gate", "gvai-protected-backend", "stop_gate", "gate_seed", "experimental_stop_latch",
    "external_gate", "FileTrustedAnchor", "GateCore", "BackendCore",
)


def _imports(path):
    found = set()
    for node in ast.walk(ast.parse(open(path).read())):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = "gvai" + ("." + base if base else "")
            found.add(base)
            found.update(f"{base}.{alias.name}" for alias in node.names)
    return found


# ---------------------------------------------------------------- static separation


def test_commercial_code_cannot_import_or_name_gate_internals():
    assert COMMERCIAL_FILES
    for path in COMMERCIAL_FILES:
        assert not (_imports(path) & GATE_MODULES), path
        text = open(path).read()
        for word in FORBIDDEN_TEXT:
            assert word not in text, (os.path.basename(path), word)


def test_gate_code_does_not_depend_on_commercial_code():
    for path in GATE_FILES:
        for name in _imports(path):
            leaf = name.rsplit(".", 1)[-1]
            assert not leaf.startswith(("commercial_", "postgresql_", "private_staging")), (path, name)


def _unit(path):
    items = {}
    section = None
    for line in open(path).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        key, _, value = line.partition("=")
        items.setdefault((section, key), []).append(value)
    return items


def _paths(*units):
    out = set()
    for u in units:
        for value in u.get(("[Service]", "InaccessiblePaths"), []):
            out.update(value.split())
    return out


def test_advisory_unit_with_dropin_hides_everything_the_gate_owns():
    base = _unit(os.path.join(PRIVATE_HTTPS, "gvai-advisory.service"))
    dropin = _unit(os.path.join(STOP_GATE, "gvai-advisory-stop-gate.conf"))
    hidden = _paths(base, dropin)
    for owned in (
        "/etc/gvai-stop-gate", "/var/lib/gvai-stop-gate", "/etc/gvai-backend",
        "/run/gvai-stop-gate/control.sock", "/run/gvai-protected-backend/notice.sock",
    ):
        assert owned in hidden, owned
    # The base unit alone is not sufficient: the drop-in is a required install step.
    assert "/var/lib/gvai-stop-gate" not in _paths(base)


def test_advisory_unit_never_mounts_or_loads_gate_material():
    base = _unit(os.path.join(PRIVATE_HTTPS, "gvai-advisory.service"))
    service_section = {k: v for (s, k), v in base.items() if s == "[Service]"}
    assert service_section["User"] == ["gvai-api"]
    for key in ("ReadWritePaths", "ReadOnlyPaths", "BindPaths", "BindReadOnlyPaths",
                "LoadCredential", "EnvironmentFile", "SetCredential", "SupplementaryGroups"):
        for value in service_section.get(key, []):
            for word in ("gate", "backend", "anchor", "latch"):
                assert word not in value.lower().replace("gvai-runtime", ""), (key, value)


def test_gate_and_backend_identities_differ_from_api_and_have_no_commercial_access():
    gate = _unit(os.path.join(STOP_GATE, "gvai-stop-gate.service"))
    backend = _unit(os.path.join(STOP_GATE, "gvai-protected-backend.service"))
    users = {
        "api": "gvai-api",
        "gate": gate[("[Service]", "User")][0],
        "backend": backend[("[Service]", "User")][0],
    }
    assert len(set(users.values())) == 3, users
    for unit in (gate, backend):
        hidden = _paths(unit)
        assert {"/etc/gvai-runtime", "/etc/gvai-operator", "/var/lib/gvai-operator"} <= hidden
    assert "/etc/gvai-backend" in _paths(gate)
    assert {"/etc/gvai-stop-gate", "/var/lib/gvai-stop-gate"} <= _paths(backend)


def test_only_operator_identity_can_reach_the_control_socket_unit():
    sock = os.path.join(STOP_GATE, "gvai-stop-gate.socket")
    cp = configparser.RawConfigParser(strict=False)
    cp.optionxform = str
    text = open(sock).read()
    blocks = text.split("ListenStream=")[1:]
    by_name = {}
    for block in blocks:
        path = block.splitlines()[0]
        by_name[path] = block
    control = next(b for p, b in by_name.items() if p.endswith("control.sock"))
    service = next(b for p, b in by_name.items() if p.endswith("service.sock"))
    assert "SocketUser=gvai-operator" in control and "SocketMode=0600" in control
    assert "gvai-api" not in control
    assert "SocketUser=gvai-api" in service and "SocketMode=0600" in service


# ---------------------------------------------------------------- runtime (simulated)


@pytest.fixture
def dep():
    d = Deployment()
    yield d
    d.close()


def _state_fingerprint(directory):
    out = {}
    for name in sorted(os.listdir(directory)):
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            out[name] = hashlib.sha256(open(full, "rb").read()).hexdigest()
    return out


def _secret_material(dep):
    secrets_ = [
        dep.stop_key.private_bytes_raw().hex(),
        dep.arm_key.private_bytes_raw().hex(),
    ]
    for name in os.listdir(dep.state):
        full = os.path.join(dep.state, name)
        if os.path.isfile(full) and os.path.getsize(full) == 32:
            data = open(full, "rb").read()
            secrets_.extend([data.hex(), data.decode("latin-1")])
    assert len(secrets_) > 2, "gate seed file not found; test would be vacuous"
    return secrets_


def test_service_interfaces_expose_no_keys_or_state(dep):
    dep.arm(1)
    svc = dep.service()
    replies = [
        svc._gate.status(),
        svc._gate.authorize("echo", {"x": 1}),
        svc._backend.audit(),
        svc.call("charge", {"amount": 3}),
    ]
    blob = json.dumps(replies)
    for secret in _secret_material(dep):
        assert secret not in blob
    assert "BEGIN" not in blob and "seed" not in blob.lower()


def test_service_cannot_change_latch_anchor_or_keys_through_permitted_interfaces(dep):
    dep.arm(1)
    before = _state_fingerprint(dep.state)
    service_gate, service_backend = dep.gate(), dep.backend()
    attacker = Ed25519PrivateKey.generate()

    # Service socket refuses command traffic even when well formed and validly signed by an
    # attacker key, and refuses every control-plane message type.
    for kind in ("stop", "arm"):
        cmd = signed(attacker, "stop-k1" if kind == "stop" else "arm-k1", 2, kind)
        reply = service_gate.request({"type": "command", "envelope": cmd})
        assert reply == {"ok": False, "reason": "request_not_permitted"}
    for kind in ("notice", "heartbeat", "set_key", "anchor", "export_key", "reload"):
        assert not service_gate.request({"type": kind})["ok"]
        assert not service_backend.request({"type": kind})["ok"]

    # Notices may only arrive on the gate-only notice channel, never the service socket.
    assert service_backend.request({"type": "notice", "notice": {}}) == {
        "ok": False, "reason": "request_not_permitted",
    }

    assert _state_fingerprint(dep.state) == before
    assert dep.gate().status()["status"] == "armed"
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_stolen_service_credentials_cannot_arm_after_stop(dep):
    dep.arm(1)
    dep.stop(2)
    before = _state_fingerprint(dep.state)
    attacker = Ed25519PrivateKey.generate()
    reply = dep.control().submit_command(signed(attacker, "arm-k1", 3, "arm"))
    assert not reply["ok"]
    # Replaying a legitimate earlier ARM must not re-arm either.
    reply = dep.control().submit_command(signed(dep.arm_key, "arm-k1", 1, "arm"))
    assert not reply["ok"]
    assert _state_fingerprint(dep.state) == before
    assert not dep.service().call("charge", {"amount": 1})["ok"]
    assert dep.backend().audit()["executed"] == []


def test_advisory_evaluation_grants_no_authority_and_survives_stopped_gate(dep, service_fixture):
    advisory, _usage, _store, _keys, _issued, credential, _now = service_fixture
    assert isinstance(advisory, CommercialEvaluationService)
    dep.arm(1)
    dep.stop(2)
    response = advisory.evaluate(
        credential, "project-a", "request-1", valid_telemetry(), []
    )
    assert response.outcome is ServiceOutcome.EVALUATED
    serialized = json.dumps(response.to_dict(), default=str).lower()
    for word in ("token", "permit", "signature", "nonce", "gate"):
        assert word not in serialized, word
    # Advisory success never changes what the gate allows.
    assert dep.service().call("charge", {"amount": 5})["ok"] is False
    assert dep.backend().audit()["executed"] == []


# ---------------------------------------------------------------- fail-closed behaviour


def test_never_armed_gate_denies_protected_operations(dep):
    result = dep.service().call("charge", {"amount": 1})
    assert result["ok"] is False
    assert dep.backend().audit()["executed"] == []


def test_stale_gate_authorization_denies_protected_operation():
    d = Deployment(notice_max_age=0.6)
    try:
        d.arm(1)
        token = d.gate().authorize("charge", {"amount": 2})["token"]
        d.kill_gate()
        time.sleep(1.0)
        reply = d.backend().execute("charge", {"amount": 2}, token)
        assert reply == {"ok": False, "reason": "gate_notice_stale"}
        assert d.backend().audit()["executed"] == []
    finally:
        d.close()


def test_unavailable_gate_denies_new_authorization(dep):
    dep.arm(1)
    service = dep.service()
    assert service.call("echo", {"x": 1})["ok"]
    dep.kill_gate()
    reply = service.call("charge", {"amount": 1})
    assert reply["ok"] is False and reply["reason"] == "communication_failure"
    assert [op for op, _ in dep.backend().audit()["executed"]] == ["echo"]


def test_unavailable_backend_means_no_execution_and_no_bypass(dep):
    dep.arm(1)
    service = dep.service()
    dep.kill_backend()
    reply = service.call("charge", {"amount": 1})
    assert reply["ok"] is False
    # Nothing else can run the operation: restarting the backend starts with no executed history
    # and refuses the earlier unused token because it predates the new backend.
    token = dep.gate().authorize("charge", {"amount": 1})["token"]
    dep.start_backend()
    time.sleep(0.5)
    assert dep.backend().execute("charge", {"amount": 1}, token)["ok"] is False
    assert dep.backend().audit()["executed"] == []


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda t: None, "malformed_request"),
        (lambda t: {}, "token_authentication_failed"),
        (lambda t: dict(t, signature="00" * 64), "token_authentication_failed"),
        (lambda t: dict(t, operation="echo"), "token_authentication_failed"),
        (lambda t: dict(t, sequence=t["sequence"] + 1), "token_authentication_failed"),
        (lambda t: dict(t, expires_at=t["expires_at"] + 3600), "token_authentication_failed"),
    ],
)
def test_invalid_authorization_is_denied(dep, mutate, reason):
    dep.arm(1)
    token = dep.gate().authorize("charge", {"amount": 1})["token"]
    reply = dep.backend().execute("charge", {"amount": 1}, mutate(token))
    assert reply == {"ok": False, "reason": reason}
    assert dep.backend().audit()["executed"] == []


def test_token_signed_by_non_gate_key_is_denied(dep):
    dep.arm(1)
    token = dep.gate().authorize("charge", {"amount": 1})["token"]
    body = {k: v for k, v in token.items() if k != "signature"}
    body["signature"] = Ed25519PrivateKey.generate().sign(eg._PERMIT_DOMAIN + eg._canon(body)).hex()
    reply = dep.backend().execute("charge", {"amount": 1}, body)
    assert reply["reason"] == "token_authentication_failed"
    for key in (dep.stop_key, dep.arm_key):
        body["signature"] = key.sign(eg._PERMIT_DOMAIN + eg._canon({
            k: v for k, v in body.items() if k != "signature"})).hex()
        assert not dep.backend().execute("charge", {"amount": 1}, body)["ok"]
    assert dep.backend().audit()["executed"] == []


def test_token_held_across_stop_is_denied(dep):
    dep.arm(1)
    token = dep.gate().authorize("charge", {"amount": 1})["token"]
    dep.stop(2)
    reply = dep.backend().execute("charge", {"amount": 1}, token)
    assert reply["ok"] is False
    assert dep.backend().audit()["executed"] == []


def test_simulation_flags_remain_declared():
    assert eg.SEPARATION_MODEL == "simulated_process_separation_same_uid"
    assert eg.OS_ENFORCED_ISOLATION_IMPLEMENTED is False


def test_integration_ci_cannot_deploy_or_trigger_on_main():
    path = os.path.join(ROOT, ".github", "workflows", "integration-tests.yml")
    lines = [l for l in open(path).read().splitlines() if l.strip() and not l.strip().startswith("#")]
    text = "\n".join(lines)
    assert text.count('branches: ["integration/**"]') == 2
    assert "main" not in text and "workflow_dispatch" not in text
    assert "permissions:\n  contents: read" in text
    for word in ("write", "deploy", "pages", "secrets.", "id-token", "environment:"):
        assert word not in text.lower(), word
