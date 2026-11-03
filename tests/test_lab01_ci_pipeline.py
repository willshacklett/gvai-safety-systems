"""Cloud tests for the Lab-01 CI pipeline: policy checker, collector, evidence verifier, host files."""

import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


policy = load("scripts/pipeline_security_check.py", "pipeline_policy")
verify_mod = load("scripts/verify_lab01_evidence.py", "verify_evidence")
collector = load("deploy/lab01_ci/host/lab01_readonly_collect.py", "collector")

ACTIVE = os.path.join(ROOT, ".github/workflows/lab01-readonly-validate.yml")
INACTIVE_DIR = os.path.join(ROOT, "deploy/lab01_ci/workflows_inactive")
HOST_DIR = os.path.join(ROOT, "deploy/lab01_ci/host")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def code(path):
    """File content without full-line comments."""
    return "\n".join(l for l in read(path).splitlines() if not l.lstrip().startswith("#"))


# ---------- policy checker ----------

def test_repository_pipeline_passes_policy():
    errors, _ = policy.run()
    assert errors == []


def test_only_readonly_validator_is_active():
    names = sorted(os.listdir(os.path.join(ROOT, ".github/workflows")))
    assert [n for n in names if n.startswith("lab01-")] == ["lab01-readonly-validate.yml"]
    assert sorted(os.listdir(INACTIVE_DIR)) == [
        "lab01-host-validation.yml.inactive", "lab01-rollback.yml.inactive",
        "lab01-staging-deploy.yml.inactive"]


def mutate(src, fn, inactive=False, name="lab01-readonly-validate.yml"):
    text = read(src)
    doc = yaml.safe_load(text)
    doc = copy.deepcopy(doc)
    fn(doc)
    path = os.path.join(ROOT, ".github/workflows", name)
    return policy.check_file(path, yaml.safe_dump(doc), doc, inactive)[0]


def doc_job(doc, jid):
    return doc["jobs"][jid]


@pytest.mark.parametrize("label,fn,needle", [
    ("pr trigger", lambda d: d.__setitem__(True, {"pull_request": None, "workflow_dispatch": None}),
     "workflow_dispatch only"),
    ("no env", lambda d: doc_job(d, "collect").pop("environment"), "protected `environment`"),
    ("job perms", lambda d: doc_job(d, "collect").__setitem__("permissions", {"contents": "read"}),
     "permissions: {}"),
    ("checkout on host", lambda d: doc_job(d, "collect")["steps"].insert(
        0, {"uses": "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"}), "check out"),
    ("sudo on host", lambda d: doc_job(d, "collect")["steps"].__setitem__(
        0, {"run": "/usr/local/libexec/gvai-ci/x; sudo true"}), "forbidden command"),
    ("docker on host", lambda d: doc_job(d, "collect")["steps"].__setitem__(
        0, {"run": "/usr/local/libexec/gvai-ci/x; docker ps"}), "forbidden command"),
    ("arbitrary host cmd", lambda d: doc_job(d, "collect")["steps"].__setitem__(
        0, {"run": "echo hi"}), "installed gvai-ci helpers"),
    ("no timeout", lambda d: doc_job(d, "collect").pop("timeout-minutes"), "timeout"),
    ("no concurrency", lambda d: d.pop("concurrency"), "concurrency"),
    ("cancel in progress", lambda d: d["concurrency"].__setitem__("cancel-in-progress", True),
     "must not cancel"),
    ("unpinned action", lambda d: doc_job(d, "verify")["steps"].__setitem__(
        0, {"uses": "actions/checkout@v4"}), "not pinned"),
    ("expression in run", lambda d: doc_job(d, "gate")["steps"].__setitem__(
        0, {"name": "x", "run": "echo ${{ github.event.inputs.x }}"}), "expression inside run"),
    ("top perms", lambda d: d.__setitem__("permissions", {"contents": "write"}), "permissions: {}"),
    ("stop path", lambda d: doc_job(d, "gate")["steps"].__setitem__(
        0, {"run": "ls /etc/gvai-stop-gate"}), "STOP-authority"),
    ("secrets", lambda d: doc_job(d, "gate")["steps"].__setitem__(
        0, {"run": "true", "env": {"S": "${{ secrets.X }}"}}), "must not use secrets"),
    ("container", lambda d: doc_job(d, "collect").__setitem__("container", "x"), "containers"),
])
def test_policy_rejects_violation(label, fn, needle):
    errors = mutate(ACTIVE, fn)
    assert any(needle in e for e in errors), (label, errors)


def test_policy_rejects_extra_active_lab01_workflow(tmp_path, monkeypatch):
    wf = tmp_path / ".github/workflows"
    wf.mkdir(parents=True)
    shutil.copy(ACTIVE, wf / "lab01-readonly-validate.yml")
    shutil.copy(os.path.join(INACTIVE_DIR, "lab01-rollback.yml.inactive"), wf / "lab01-rollback.yml")
    monkeypatch.setattr(policy, "ROOT", str(tmp_path))
    errors, _ = policy.run()
    assert any("only the read-only validator" in e for e in errors)


def test_policy_fails_closed_with_no_workflows(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, "ROOT", str(tmp_path))
    errors, _ = policy.run()
    assert errors


def test_inactive_templates_gated_and_not_loaded():
    for name in os.listdir(INACTIVE_DIR):
        text = read(os.path.join(INACTIVE_DIR, name))
        assert "ACTIVATED" in text and "INACTIVE TEMPLATE" in text
        assert name.endswith(".yml.inactive")
        doc = yaml.safe_load(text)
        assert doc["permissions"] == {}
        for job in doc["jobs"].values():
            assert job["timeout-minutes"] <= 20
            if "gvai-lab01" in str(job["runs-on"]):
                assert job["environment"].startswith("lab01-")
    stage = read(os.path.join(INACTIVE_DIR, "lab01-staging-deploy.yml.inactive"))
    assert "^[0-9a-f]{40}$" in stage and "STAGE" in stage


def test_readonly_workflow_shape():
    doc = yaml.safe_load(read(ACTIVE))
    assert set(doc[True]) == {"workflow_dispatch"}
    assert doc["permissions"] == {}
    assert doc["concurrency"]["group"] == "lab01-host-access"
    collect = doc["jobs"]["collect"]
    assert collect["environment"] == "lab01-readonly" and collect["permissions"] == {}
    assert "self-hosted" in collect["runs-on"]
    assert not any("checkout" in s.get("uses", "") for s in collect["steps"])
    assert doc["jobs"]["verify"]["needs"] == "collect" and doc["jobs"]["collect"]["needs"] == "gate"
    assert "LAB01_VALIDATION_ENABLED" in read(ACTIVE)


# ---------- collector ----------

class FakeRoot:
    def __init__(self, tmp, status=None, os_release='ID=ubuntu\nVERSION_ID="24.04"\n', tcp=None):
        self.path = str(tmp)
        for rel, body in {
            "proc/self/status": status or "CapEff:\t0000000000000000\nNoNewPrivs:\t1\n",
            "etc/os-release": os_release,
            "proc/net/tcp": tcp or "  sl local_address rem_address st\n",
            "proc/net/tcp6": "  sl local_address rem_address st\n",
        }.items():
            full = os.path.join(self.path, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as fh:
                fh.write(body)
        os.makedirs(os.path.join(self.path, "var"), exist_ok=True)


def fake_runner(argv):
    return 0, "LoadState=loaded\nActiveState=active\nSubState=running\nUser=gvai-api\n"


def run_collect(tmp_path, **kw):
    fr = FakeRoot(tmp_path, **kw.pop("fake", {}))
    return collector.collect(root=fr.path, runner=fake_runner, euid=kw.pop("euid", 1001),
                             group_names=kw.pop("groups", ["gvai-ci"]), now=1)


def statuses(ev):
    return {c["id"]: c["status"] for c in ev["checks"]}


def test_collector_clean_run_is_partial_pass_never_validated(tmp_path):
    ev = run_collect(tmp_path)
    assert ev["overall"] == "partial_pass" and ev["failed_ids"] == []
    assert ev["host_level_security_validated"] is False and ev["mutated_host"] is False
    assert statuses(ev)["host.firewall_ufw_and_do_cloud_firewall"] == "not_collected"
    verify_mod.verify(json.dumps(ev).encode())


def test_collector_fails_as_root(tmp_path):
    ev = run_collect(tmp_path, euid=0)
    assert "identity.non_root" in ev["failed_ids"]


@pytest.mark.parametrize("group", ["docker", "sudo", "gvai-gate", "gvai-backend", "root", "adm"])
def test_collector_fails_in_privileged_group(tmp_path, group):
    ev = run_collect(tmp_path, groups=["gvai-ci", group])
    assert "identity.no_privileged_groups" in ev["failed_ids"]


def test_collector_fails_with_capabilities_or_missing_status(tmp_path):
    ev = run_collect(tmp_path, fake={"status": "CapEff:\t0000000000000001\nNoNewPrivs:\t1\n"})
    assert "identity.no_capabilities" in ev["failed_ids"]
    ev = run_collect(tmp_path / "b", fake={"status": "NoNewPrivs:\t0\n"})
    assert {"identity.no_capabilities", "identity.no_new_privs"} <= set(ev["failed_ids"])


def test_collector_fails_on_wrong_os(tmp_path):
    ev = run_collect(tmp_path, fake={"os_release": 'ID=ubuntu\nVERSION_ID="22.04"\n'})
    assert "host.ubuntu_2404" in ev["failed_ids"]


def test_collector_flags_unexpected_public_listener(tmp_path):
    tcp = ("  sl local_address rem_address st\n"
           "   0: 00000000:1F90 00000000:0000 0A 0:0\n"   # 0.0.0.0:8080
           "   1: 0100007F:1F91 00000000:0000 0A 0:0\n"   # 127.0.0.1:8081 ok
           "   2: 00000000:0016 00000000:0000 0A 0:0\n")  # 22 ok
    ev = run_collect(tmp_path, fake={"tcp": tcp})
    assert ev["failed_ids"] == ["network.unexpected_public_listeners"]


def test_protected_paths_denied_semantics(tmp_path):
    """A readable protected path is a FAIL; absent/denied is a PASS."""
    protected = tmp_path / "root/etc/gvai-stop-gate"
    protected.mkdir(parents=True)
    results = {c["id"]: c for c in collector.check_protected_paths(str(tmp_path / "root"))}
    open_path = results["protected.denied:/etc/gvai-stop-gate"]
    if os.geteuid() == 0:
        assert open_path["status"] == "fail"
    else:
        os.chmod(protected, 0o755)
        again = {c["id"]: c for c in collector.check_protected_paths(str(tmp_path / "root"))}
        assert again["protected.denied:/etc/gvai-stop-gate"]["status"] == "fail"
        os.chmod(protected, 0)
        denied = {c["id"]: c for c in collector.check_protected_paths(str(tmp_path / "root"))}
        assert denied["protected.denied:/etc/gvai-stop-gate"]["status"] == "pass"
        os.chmod(protected, 0o755)
    assert results["protected.denied:/var/lib/gvai-stop-gate"]["status"] == "pass"


def test_collector_never_opens_protected_paths_and_only_runs_fixed_argv():
    src = read(os.path.join(HOST_DIR, "lab01_readonly_collect.py"))
    body = src.split("PROTECTED_PATHS = (", 1)[1].split(")\n", 1)[1]
    for token in policy.STOP_AUTHORITY_TOKENS:
        assert token not in body, token
    for banned in ("shell=True", "os.system", "eval(", "exec(", "os.remove",
                   "os.unlink", "shutil.rmtree", "os.chmod", "os.rename"):
        assert banned not in src, banned
    assert src.count("subprocess.run(") == 1 and "shell=False" in src
    assert src.count('["systemctl", "show"') == 1


def test_collector_output_is_exclusive_0600(tmp_path):
    out = tmp_path / "ev.json"
    fr = FakeRoot(tmp_path / "r")
    rc = collector.main(["--output", str(out), "--root", fr.path])
    assert rc in (0, 1) and out.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        collector.main(["--output", str(out), "--root", fr.path])


# ---------- evidence verifier ----------

def good_evidence(tmp_path):
    return run_collect(tmp_path)


def test_verifier_accepts_good_and_rejects_tampering(tmp_path):
    ev = good_evidence(tmp_path)
    verify_mod.verify(json.dumps(ev).encode())
    cases = {
        "wrong schema": lambda e: e.__setitem__("schema", "x"),
        "mutated": lambda e: e.__setitem__("mutated_host", True),
        "validated claim": lambda e: e.__setitem__("host_level_security_validated", True),
        "overall": lambda e: e.__setitem__("overall", "pass"),
        "failed": lambda e: e["checks"][0].__setitem__("status", "fail"),
        "bad status": lambda e: e["checks"][0].__setitem__("status", "ok"),
        "extra key": lambda e: e["checks"][0].__setitem__("x", 1),
        "dup": lambda e: e["checks"].append(dict(e["checks"][0])),
        "missing": lambda e: e.__setitem__("checks", e["checks"][1:]),
        "empty": lambda e: e.__setitem__("checks", []),
        "required not pass": lambda e: [c.__setitem__("status", "not_collected")
                                        for c in e["checks"] if c["id"] == "identity.non_root"],
        "secret": lambda e: e["checks"][0].__setitem__(
            "detail", "-----BEGIN OPENSSH PRIVATE KEY-----"),
        "token": lambda e: e["checks"][0].__setitem__("detail", "ghp_" + "a" * 36),
        "kv secret": lambda e: e["checks"][0].__setitem__("detail", "password=hunter2hunter2"),
    }
    for label, fn in cases.items():
        bad = copy.deepcopy(ev)
        fn(bad)
        with pytest.raises(verify_mod.EvidenceError):
            verify_mod.verify(json.dumps(bad).encode())
    for raw in (b"not json", b"[]", b"x" * (verify_mod.MAX_BYTES + 1)):
        with pytest.raises(verify_mod.EvidenceError):
            verify_mod.verify(raw)


# ---------- host files and isolation ----------

def unit_items(text):
    items = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", "[")):
            k, _, v = line.partition("=")
            items[k] = v
    return items


def test_runner_unit_is_unprivileged_and_isolated():
    text = read(os.path.join(HOST_DIR, "gvai-ci-runner.service"))
    u = unit_items(text)
    assert u["User"] == "gvai-ci" and u["Group"] == "gvai-ci"
    assert u["NoNewPrivileges"] == "true" and u["CapabilityBoundingSet"] == ""
    assert u["ProtectSystem"] == "strict" and u["PrivateDevices"] == "true"
    assert u["SupplementaryGroups"] == ""
    assert u["RestrictAddressFamilies"] == "AF_UNIX AF_INET AF_INET6"
    for p in collector.PROTECTED_PATHS + ("/var/run/docker.sock", "/run/docker.sock"):
        assert p in u["InaccessiblePaths"].split(), p
    for key in ("Requires", "Wants", "BindsTo", "PartOf", "Before", "After"):
        value = u.get(key, "")
        assert not re.search(r"gvai-(advisory|ingress|stop-gate|protected-backend)", value), key
    assert not re.search(r"^(User|Group)=(root|gvai-(gate|backend|operator|api|proxy))$", text, re.M)


def test_bootstrap_is_dry_run_by_default_and_never_touches_authority():
    src = code(os.path.join(HOST_DIR, "bootstrap_lab01_ci.sh"))
    assert "EXECUTE=0" in src and "[dry-run]" in src and 'usage: $0 [--execute]' in src
    for banned in ("sudoers", "usermod", "docker", "ufw", "iptables", "systemctl", "ssh-keygen",
                   "passwd", "curl", "wget", "/etc/gvai-stop-gate", "/var/lib/gvai-stop-gate",
                   "/etc/gvai-backend", "/etc/gvai-operator", "chmod 777", "--groups", "-G "):
        assert banned not in src.replace("NOT enabled or started", ""), banned
    assert "--shell /usr/sbin/nologin" in src and "--system" in src
    assert subprocess.run(["bash", "-n", os.path.join(HOST_DIR, "bootstrap_lab01_ci.sh")]).returncode == 0
    # A non-root dry run must refuse (fail closed) and change nothing.
    if os.geteuid() != 0:
        done = subprocess.run(["bash", os.path.join(HOST_DIR, "bootstrap_lab01_ci.sh")],
                              capture_output=True, text=True)
        assert done.returncode == 1 and "must run as root" in done.stdout


@pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck not installed (CI runs it)")
def test_bootstrap_shellcheck():
    assert subprocess.run(["shellcheck", os.path.join(HOST_DIR, "bootstrap_lab01_ci.sh")]).returncode == 0


def test_no_pipeline_file_references_stop_authority_secrets_or_grants_root():
    files = [ACTIVE, os.path.join(ROOT, ".github/workflows/pipeline-security.yml")]
    files += [os.path.join(INACTIVE_DIR, n) for n in os.listdir(INACTIVE_DIR)]
    files += [os.path.join(HOST_DIR, "gvai-ci-runner.service"),
              os.path.join(HOST_DIR, "bootstrap_lab01_ci.sh")]
    for f in files:
        text = read(f)
        for line in text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            for tok in ("gate_key", "downstream.cred", "trusted_anchor", "stop_key", "arm_key", ".seed"):
                assert tok not in line, (f, tok)
        assert "${{ secrets." not in text, f


def test_existing_stop_gate_staging_tool_still_forbids_authority_paths():
    stage = read(os.path.join(ROOT, "deploy/stop_gate/lab01_stage.py"))
    assert "FORBIDDEN_TARGETS" in stage and "gate_key.seed" in stage
