"""Static checks of the (inactive) STOP-gate deployment files and the staging tool."""

import configparser
import importlib.util
import json
import os
import re

import pytest

DEPLOY = os.path.join(os.path.dirname(__file__), "..", "deploy", "stop_gate")


def path(name):
    return os.path.join(DEPLOY, name)


def unit(name):
    """Parse a unit file, keeping repeated keys (e.g. ListenStream)."""
    cp = configparser.RawConfigParser(strict=False, delimiters=("=",))
    cp.optionxform = str
    items = {}
    section = None
    for line in open(path(name)).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        k, _, v = line.partition("=")
        items.setdefault((section, k), []).append(v)
    return items


def one(u, section, key):
    return u[(section, key)][0]


GATE, BACKEND = "gvai-stop-gate.service", "gvai-protected-backend.service"
REQUIRED_HARDENING = {
    "NoNewPrivileges": "true", "ProtectSystem": "strict", "PrivateTmp": "true",
    "PrivateDevices": "true", "ProtectProc": "invisible", "CapabilityBoundingSet": "",
    "AmbientCapabilities": "", "RestrictAddressFamilies": "AF_UNIX", "IPAddressDeny": "any",
    "MemoryDenyWriteExecute": "true", "RestrictNamespaces": "true", "UMask": "0077",
    "LockPersonality": "true", "ProtectKernelTunables": "true", "ProtectHome": "true",
}


@pytest.mark.parametrize("name", [GATE, BACKEND])
def test_hardening_present_and_nonroot(name):
    u = unit(name)
    for key, value in REQUIRED_HARDENING.items():
        assert one(u, "[Service]", key) == value, (name, key)
    assert one(u, "[Service]", "User") not in ("root", "")
    assert one(u, "[Service]", "Group") not in ("root", "")
    assert "TasksMax" in {k for (_, k) in u} and "MemoryMax" in {k for (_, k) in u}


def test_identities_are_distinct_and_not_existing_ones():
    users = {one(unit(n), "[Service]", "User") for n in (GATE, BACKEND)}
    assert users == {"gvai-gate", "gvai-backend"}
    assert not users & {"gvai-api", "gvai-proxy", "gvai-operator", "root"}
    sysusers = open(path("gvai-stop-gate.sysusers")).read()
    assert "gvai-gate" in sysusers and "gvai-backend" in sysusers
    assert not re.search(r"^m\s", sysusers, re.M)  # no group memberships


def test_credentials_and_state_are_not_shared():
    g, b = unit(GATE), unit(BACKEND)
    assert ("[Service]", "LoadCredential") not in g
    assert one(b, "[Service]", "LoadCredential").startswith("downstream:/etc/gvai-backend/")
    assert one(g, "[Service]", "ReadWritePaths") == "/var/lib/gvai-stop-gate"
    assert ("[Service]", "ReadWritePaths") not in b
    assert "/var/lib/gvai-stop-gate" in one(b, "[Service]", "InaccessiblePaths")
    assert "/etc/gvai-stop-gate" in one(b, "[Service]", "InaccessiblePaths")
    assert "/etc/gvai-backend" in one(g, "[Service]", "InaccessiblePaths")


def test_socket_ownership_separation():
    gs = unit("gvai-stop-gate.socket")
    names = gs[("[Socket]", "FileDescriptorName")]
    assert names == ["service", "control"]
    assert gs[("[Socket]", "SocketUser")] == ["gvai-api", "gvai-operator"]
    bs = unit("gvai-protected-backend.socket")
    assert bs[("[Socket]", "FileDescriptorName")] == ["service", "notice"]
    assert bs[("[Socket]", "SocketUser")] == ["gvai-api", "gvai-gate"]
    for s in (gs, bs):
        assert set(s[("[Socket]", "SocketMode")]) == {"0600"}
    # the API must never own a control or notice socket
    assert gs[("[Socket]", "SocketUser")][1] != "gvai-api"
    assert bs[("[Socket]", "SocketUser")][1] != "gvai-api"


def test_api_dropin_hides_authority_and_privileged_sockets():
    text = open(path("gvai-advisory-stop-gate.conf")).read()
    for needed in ("/etc/gvai-stop-gate", "/var/lib/gvai-stop-gate", "/etc/gvai-backend",
                   "/run/gvai-stop-gate/control.sock", "/run/gvai-protected-backend/notice.sock"):
        assert needed in text
    assert "service.sock" not in text  # the API must still reach the service sockets


def test_examples_contain_no_secrets_and_match_loader_keys():
    gate = json.load(open(path("gate.json.example")))
    backend = json.load(open(path("backend.json.example")))
    assert {"state_dir", "latch_id", "stop_keys", "arm_keys", "operations"} <= set(gate)
    assert "downstream_sign" in gate["operations"]
    blob = json.dumps(gate) + json.dumps(backend)
    assert "seed" not in blob and "private" not in blob.lower()
    assert all("REPLACE_WITH" in v for v in list(gate["stop_keys"].values()) + list(gate["arm_keys"].values()))
    assert not re.search(r"[0-9a-f]{64}", blob)


def test_apparmor_drafts_deny_cross_access_and_network():
    for name, other in (("gvai-stop-gate", "/etc/gvai-backend"), ("gvai-protected-backend", "/etc/gvai-stop-gate")):
        text = open(path(f"apparmor/{name}")).read()
        assert "deny network inet," in text and "deny ptrace" in text
        assert f"deny {other}/**" in text
        assert "NOT LOADED" in text


# ---- staging tool -----------------------------------------------------------------------


@pytest.fixture()
def stage():
    spec = importlib.util.spec_from_file_location("lab01_stage", path("lab01_stage.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def snapshot(root):
    out = {}
    for d, _, files in os.walk(root):
        for f in files:
            p = os.path.join(d, f)
            out[os.path.relpath(p, root)] = open(p, "rb").read()
    return out


def test_dry_run_changes_nothing(stage, tmp_path):
    root = str(tmp_path)
    assert stage.main(["apply", "--root", root]) == 0
    assert snapshot(root) == {}


def test_apply_is_idempotent_and_verifies(stage, tmp_path):
    root = str(tmp_path)
    assert stage.main(["apply", "--root", root, "--execute"]) == 0
    first = snapshot(root)
    assert stage.main(["verify", "--root", root]) == 0
    assert stage.main(["apply", "--root", root, "--execute"]) == 0
    second = snapshot(root)
    assert {k: v for k, v in first.items() if "manifest" not in k} == {
        k: v for k, v in second.items() if "manifest" not in k
    }
    assert all(a["action"] == "unchanged" for a in stage.plan(root))
    assert not os.path.exists(os.path.join(root, "etc/gvai-backend/downstream.cred"))


def test_rollback_restores_preexisting_and_removes_created(stage, tmp_path):
    root = str(tmp_path)
    dropin_dir = os.path.join(root, "etc/systemd/system/gvai-advisory.service.d")
    os.makedirs(dropin_dir)
    pre = os.path.join(dropin_dir, "stop-gate.conf")
    open(pre, "w").write("# pre-existing operator file\n")
    unrelated = os.path.join(root, "etc/gvai-runtime")
    os.makedirs(unrelated)
    open(os.path.join(unrelated, "runtime.json"), "w").write("{}")
    before = snapshot(root)
    stage.main(["apply", "--root", root, "--execute"])
    assert stage.main(["backup-verify", "--root", root]) == 0
    assert open(pre).read() != "# pre-existing operator file\n"
    stage.main(["rollback", "--root", root, "--execute"])
    after = snapshot(root)
    kept = {k for k in after if k not in before}
    assert {k: v for k, v in after.items() if k in before} == before
    assert all("stop_gate_backup" in k for k in kept) and kept  # backups are kept as records
    assert not os.path.exists(os.path.join(root, "etc/gvai-stop-gate"))
    assert stage.main(["rollback", "--root", root, "--execute"]) == 0  # idempotent


def test_corrupted_backup_blocks_rollback_and_is_detected(stage, tmp_path):
    root = str(tmp_path)
    d = os.path.join(root, "etc/systemd/system/gvai-advisory.service.d")
    os.makedirs(d)
    open(os.path.join(d, "stop-gate.conf"), "w").write("orig")
    stage.main(["apply", "--root", root, "--execute"])
    bdir = os.path.join(root, "var/lib/gvai-stage/stop_gate_backup")
    for f in os.listdir(bdir):
        open(os.path.join(bdir, f), "w").write("tampered")
    assert stage.main(["backup-verify", "--root", root]) == 1
    with pytest.raises(SystemExit):
        stage.main(["rollback", "--root", root, "--execute"])


def test_verify_fails_on_drift_and_tool_never_shells_out(stage, tmp_path):
    root = str(tmp_path)
    stage.main(["apply", "--root", root, "--execute"])
    open(os.path.join(root, "etc/systemd/system/gvai-stop-gate.service"), "a").write("# drift\n")
    assert stage.main(["verify", "--root", root]) == 1
    src = open(path("lab01_stage.py")).read()
    assert "subprocess" not in src and "os.system" not in src
