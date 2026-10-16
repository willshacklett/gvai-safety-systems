import json
import os
import signal
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

import gvai.os_sandbox as sandbox
import gvai.supervisor as supervisor_module
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.external_commands import (
    CommandAuthentication, ExternalCommandRejected, ExternalControlCommand,
    ExternalControlCommandVerifier, HMACSHA256Authenticator,
    InMemoryExternalControlState, sign_control_command,
)
from gvai.identity import (
    IdentityAuthority, IdentityAuthorizer, IdentityPolicy, IdentityScope,
    TenantResource, VerifiedIdentityClaims,
)
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.supervisor import SupervisorStopped, TrustedSupervisor


KEY = b"supervisor-test-key-not-production" * 2


def command(target="worker-1"):
    now = int(time.time())
    return sign_control_command(ExternalControlCommand(
        1, str(uuid.uuid4()), "shutdown", target, "operator", now, now + 60,
        CommandAuthentication("HMAC-SHA256", "test", ""),
    ), KEY)


def build(root, *, forbidden=(), capabilities=None, input_root=None):
    grants = frozenset(
        {"resource:execute"} | {f"tool:{action}" for action in sandbox.KNOWN_ACTION_EFFECTS}
    )
    claims = VerifiedIdentityClaims(
        "alice", "customer-a", IdentityScope.CUSTOMER, "operator",
        grants if capabilities is None else frozenset(capabilities),
    )
    policy = IdentityPolicy({(IdentityScope.CUSTOMER, "operator"): grants})
    authority = IdentityAuthority(
        SimpleNamespace(verify=lambda evidence: claims if evidence == "credential" else None),
        policy,
    )
    invariants = []
    if forbidden:
        invariants.append(make_effect_invariant("supervisor", "boundary", set(forbidden)))
    guard = GVRuntimeGuardV2(GVSentinel(), GVRuntimePolicy(GVEffectGate(invariants)))
    observation = guard.observe([1.0] * 4)
    instance = TrustedSupervisor(
        target_id="worker-1", authority=authority, authorizer=IdentityAuthorizer(policy),
        guard=guard, command_verifier=ExternalControlCommandVerifier(
            HMACSHA256Authenticator({("operator", "test"): KEY}),
            InMemoryExternalControlState(),
        ),
        resources={
            "document": TenantResource(IdentityScope.CUSTOMER, "customer-a", "document"),
            "other": TenantResource(IdentityScope.CUSTOMER, "customer-b", "other"),
        },
        root=root, input_root=input_root,
    )
    return instance, observation


class FakeChild:
    pid = 987654321

    def __init__(self, command, *, block=None, report=None, returncode=0,
                 communicate_error=False, **kwargs):
        self.command = command
        self.returncode = None
        self.finished_code = returncode
        self.block = block
        self.report = report or json.dumps({
            "action": command[-1], "completed": True, "error": None, "events": [],
        })
        self.killed = threading.Event()
        self.waits = 0
        self.communicate_error = communicate_error
        work = Path(command[command.index("--bind") + 1])
        (work / "result.txt").write_text("safe work\n")

    def communicate(self, timeout=None):
        if self.communicate_error:
            raise OSError("pipe failed")
        if self.block is not None:
            assert self.block.wait(3)
        self.returncode = -signal.SIGKILL if self.killed.is_set() else self.finished_code
        return self.report, ""

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.waits += 1
        if self.killed.is_set():
            self.returncode = -signal.SIGKILL
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.command, timeout)
        return self.returncode


@pytest.fixture
def mocked(monkeypatch):
    children = []
    config = {}
    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox, "build_no_spawn_filter",
                        lambda: SimpleNamespace(fd=77, close=lambda: None))

    def spawn(command, **kwargs):
        child = FakeChild(command, **config, **kwargs)
        children.append(child)
        return child

    def kill(pid, sig):
        assert sig == signal.SIGKILL
        child = next(child for child in children if child.pid == pid)
        child.killed.set()
        if child.block is not None:
            child.block.set()

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", spawn)
    monkeypatch.setattr(supervisor_module.os, "killpg", kill)
    monkeypatch.setattr(TrustedSupervisor, "_group_exited", staticmethod(lambda pgid: True))
    return children, config


def run(instance, observation, action="safe_work", **kwargs):
    return instance.execute(kwargs.get("evidence", "credential"),
                            kwargs.get("resource", "document"), action, observation)


@pytest.mark.parametrize("evidence,resource,action", [
    ("bad", "document", "safe_work"),
    ("credential", "other", "safe_work"),
    ("credential", "missing", "safe_work"),
    ("credential", "document", "arbitrary_code"),
])
def test_denials_never_spawn(tmp_path, mocked, evidence, resource, action):
    instance, observation = build(tmp_path / "parent")
    with pytest.raises(PermissionError):
        run(instance, observation, action, evidence=evidence, resource=resource)
    assert mocked[0] == []


def test_tool_grant_required(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent", capabilities={"resource:execute"})
    with pytest.raises(PermissionError):
        run(instance, observation)
    assert not mocked[0]


def test_declared_effects_checked_before_launch(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent", forbidden={"resource_exhaustion"})
    with pytest.raises(PermissionError):
        run(instance, observation, "cpu_exhaustion")
    assert not mocked[0]


def test_success_and_finished_shutdown(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    transaction = run(instance, observation)
    assert transaction.committed
    assert (tmp_path / "parent/current/result.txt").read_text() == "safe work\n"
    assert mocked[0][0].waits >= 1
    assert "--new-session" not in mocked[0][0].command
    assert "--clearenv" in mocked[0][0].command
    result = instance.shutdown(command())
    assert result["confirmed"] and result["returncode"] == 0
    assert result["deadline_met"] and result["elapsed_seconds"] >= 0
    assert not any(event["event"] == "signal_sent" for event in instance.evidence)
    with pytest.raises(SupervisorStopped):
        run(instance, observation)


def test_target_authentication_and_replay(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    with pytest.raises(ExternalCommandRejected):
        instance.shutdown(command("different"))
    invalid = command().to_mapping()
    invalid["auth"]["signature"] = "0" * 64
    with pytest.raises(ExternalCommandRejected):
        instance.shutdown(invalid)
    assert not instance.stopped
    envelope = command()
    assert instance.shutdown(envelope)["confirmed"]
    with pytest.raises(ExternalCommandRejected):
        instance.shutdown(envelope)
    assert not mocked[0]


def test_stop_running_kills_and_independently_reaps(tmp_path, mocked):
    children, config = mocked
    config["block"] = threading.Event()
    config["report"] = json.dumps({
        "action": "cpu_exhaustion", "completed": True, "events": [],
        "halted": False, "shutdown_cleared": True,
    })
    instance, observation = build(tmp_path / "parent")
    started = threading.Event()
    original = instance._record

    def record(event, **details):
        original(event, **details)
        if event == "process_started":
            started.set()

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation, "cpu_exhaustion")
        assert started.wait(2)
        result = instance.shutdown(command())
        transaction = future.result(timeout=2)
    assert result["confirmed"] and result["returncode"] == -signal.SIGKILL
    assert result["deadline_met"] and result["elapsed_seconds"] >= 0
    assert children[0].killed.is_set()
    assert children[0].waits
    assert not transaction.committed
    assert instance.stopped
    with pytest.raises(SupervisorStopped):
        run(instance, observation)
    assert not (tmp_path / "parent/current").exists()
    events = instance.evidence
    assert {
        "shutdown_intent", "shutdown_accepted", "signal_sent",
        "launcher_exit_confirmed", "process_group_exit_confirmed",
    } <= {
        event["event"] for event in events
    }
    assert all("monotonic" in event and "unix_time" in event for event in events)
    disk = [json.loads(line) for line in (tmp_path / "parent/control.jsonl").read_text().splitlines()]
    assert any(event.get("returncode") == -signal.SIGKILL for event in disk)


def test_stop_during_preparation_never_launches(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    entered, release = threading.Event(), threading.Event()

    def prepare():
        entered.set()
        assert release.wait(2)
        return SimpleNamespace(fd=77, close=lambda: None)

    monkeypatch.setattr(sandbox, "build_no_spawn_filter", prepare)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert entered.wait(2)
        assert instance.shutdown(command())["confirmed"]
        release.set()
        with pytest.raises(SupervisorStopped):
            future.result(timeout=2)
    assert not mocked[0]


def test_launcher_wait_alone_does_not_confirm_worker_exit(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    run(instance, observation)
    monkeypatch.setattr(instance, "_group_exited", lambda pgid: False)
    result = instance.shutdown(command())
    assert not result["confirmed"]
    assert not result["deadline_met"]
    assert result["returncode"] == 0


def test_deadline_counts_authentication_and_audit(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    original = instance._verifier.authorize
    elapsed = [100.0]
    monkeypatch.setattr(supervisor_module.time, "monotonic", lambda: elapsed[0])

    def slow_authorize(*args, **kwargs):
        elapsed[0] += 1.2
        return original(*args, **kwargs)

    monkeypatch.setattr(instance._verifier, "authorize", slow_authorize)
    result = instance.shutdown(command())
    assert result["confirmed"]
    assert not result["deadline_met"]
    assert result["elapsed_seconds"] == pytest.approx(1.2)


@pytest.mark.parametrize("state,pgid,expected", [
    ("R", 123, False), ("S", 123, False),
    ("Z", 123, True), ("X", 123, True), ("R", 456, True),
])
def test_parent_proc_group_confirmation(monkeypatch, state, pgid, expected):
    class Entry:
        name = "12"

        def __truediv__(self, _name):
            return SimpleNamespace(read_text=lambda: f"12 (worker name) {state} 1 {pgid} 123")

    monkeypatch.setattr(Path, "iterdir", lambda path: iter([Entry()]))
    assert TrustedSupervisor._group_exited(123) is expected


def test_proc_unavailable_cannot_confirm_group_exit(monkeypatch):
    def unavailable(path):
        raise PermissionError("procfs inaccessible")

    monkeypatch.setattr(Path, "iterdir", unavailable)
    assert not TrustedSupervisor._group_exited(123)


def test_actual_parent_process_group_is_observed_alive():
    assert not TrustedSupervisor._group_exited(os.getpgrp())


def test_constructor_rejects_unreadable_procfs(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)

    def unavailable(path):
        raise PermissionError("procfs inaccessible")

    monkeypatch.setattr(Path, "iterdir", unavailable)
    with pytest.raises(sandbox.OSSandboxUnavailable, match="procfs"):
        build(tmp_path / "parent")


def test_procfs_evidence_lost_before_launch_prevents_spawn(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    monkeypatch.setattr(TrustedSupervisor, "_group_exited", staticmethod(lambda pgid: False))
    with pytest.raises(sandbox.OSSandboxUnavailable, match="procfs"):
        run(instance, observation)
    assert not mocked[0]
    assert not (tmp_path / "parent/current").exists()


def test_stop_during_spawn_handoff(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    entered, release = threading.Event(), threading.Event()
    spawn = supervisor_module.subprocess.Popen

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return spawn(*args, **kwargs)

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", delayed)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert entered.wait(2)
        # OS startup is unresolved: never report a fictitious confirmed exit.
        assert not instance.shutdown(command())["confirmed"]
        release.set()
        with pytest.raises(SupervisorStopped):
            future.result(timeout=2)
    assert mocked[0][0].killed.is_set()
    assert mocked[0][0].waits
    assert not (tmp_path / "parent/current").exists()


def test_stop_during_commit_copy_is_responsive_and_never_promotes(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    entered, release = threading.Event(), threading.Event()
    copy = supervisor_module.shutil.copy2

    def delayed(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return copy(*args, **kwargs)

    monkeypatch.setattr(supervisor_module.shutil, "copy2", delayed)
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert entered.wait(2)
        assert instance.shutdown(command())["confirmed"]
        release.set()
        assert not future.result(timeout=2).committed
    assert not (tmp_path / "parent/current").exists()
    assert not list((tmp_path / "parent").glob("generation-*"))


def test_stop_at_last_promotion_boundary(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    entered, release = threading.Event(), threading.Event()
    original = instance._record

    def record(event, **details):
        original(event, **details)
        if event == "promotion_intent":
            entered.set()
            assert release.wait(2)

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert entered.wait(2)
        assert instance.shutdown(command())["confirmed"]
        release.set()
        assert not future.result(timeout=2).committed
    assert not any(event["event"] == "promotion_completed" for event in instance.evidence)


def test_promotion_winning_race_is_evidenced_before_stop(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    entered, release = threading.Event(), threading.Event()
    original = instance._record

    def record(event, **details):
        if event == "promotion_completed":
            entered.set()
            assert release.wait(2)
        original(event, **details)

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert entered.wait(2)
        assert instance.shutdown(command())["confirmed"]
        release.set()
        assert future.result(timeout=2).committed
    promotion = next(event for event in instance.evidence if event["event"] == "promotion_completed")
    shutdown = next(event for event in instance.evidence if event["event"] == "shutdown_accepted")
    assert promotion["monotonic"] <= shutdown["monotonic"]
    assert (tmp_path / "parent/current/result.txt").read_text() == "safe work\n"
    with pytest.raises(SupervisorStopped):
        run(instance, observation)


def test_audit_error_at_promotion_boundary_discards_output(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    original = instance._record

    def record(event, **details):
        if event == "promotion_intent":
            audit = tmp_path / "parent/control.jsonl"
            audit.unlink()
            audit.mkdir()
        original(event, **details)

    instance._record = record
    assert not run(instance, observation).committed
    assert not (tmp_path / "parent/current").exists()


def test_pipe_exception_kills_and_reaps(tmp_path, mocked):
    mocked[1]["communicate_error"] = True
    instance, observation = build(tmp_path / "parent")
    with pytest.raises(OSError, match="pipe failed"):
        run(instance, observation)
    assert mocked[0][0].killed.is_set()
    assert mocked[0][0].waits
    assert instance.shutdown(command())["confirmed"]


def test_spawn_exception_releases_reservation(tmp_path, mocked, monkeypatch):
    instance, observation = build(tmp_path / "parent")
    spawn = supervisor_module.subprocess.Popen

    def fail(*args, **kwargs):
        raise OSError("launch failed")

    monkeypatch.setattr(supervisor_module.subprocess, "Popen", fail)
    with pytest.raises(OSError, match="launch failed"):
        run(instance, observation)
    monkeypatch.setattr(supervisor_module.subprocess, "Popen", spawn)
    assert run(instance, observation).committed


def test_runtime_observed_effect_denial_prevents_commit(tmp_path, mocked):
    mocked[1]["report"] = json.dumps({
        "action": "safe_work", "completed": True,
        "events": [{"event": "protected_file_write_blocked"}],
    })
    instance, observation = build(tmp_path / "parent", forbidden={"protected_file_write_attempt"})
    result = run(instance, observation)
    assert not result.allowed and not result.committed


def test_concurrent_second_execution_is_rejected(tmp_path, mocked):
    mocked[1]["block"] = threading.Event()
    instance, observation = build(tmp_path / "parent")
    started = threading.Event()
    original = instance._record

    def record(event, **details):
        original(event, **details)
        if event == "process_started":
            started.set()

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert started.wait(2)
        with pytest.raises(RuntimeError, match="already active"):
            run(instance, observation)
        assert instance.shutdown(command())["confirmed"]
        assert not future.result(timeout=2).committed
    assert len(mocked[0]) == 1


@pytest.mark.parametrize("report,returncode", [
    ('not json', 0), ('[]', 0), ('{"completed":true,"events":[2]}', 0),
    ('{"completed":true,"events":[]}', 7),
    ('{"action":"safe_work","completed":true,"events":[]}', 7),
    ('{"action":"other","completed":true,"events":[]}', 0),
    ('{"action":"safe_work","completed":true,"events":[{}]}', 0),
    ('{"completed":"yes","events":[]}', 0),
    ('{"completed":true,"events":[],"error":"failed"}', 0),
])
def test_invalid_or_failed_worker_never_promotes(tmp_path, mocked, report, returncode):
    mocked[1].update(report=report, returncode=returncode)
    instance, observation = build(tmp_path / "parent")
    assert not run(instance, observation).committed
    assert not (tmp_path / "parent/current").exists()


def test_audit_failure_prevents_launch(tmp_path, mocked):
    instance, observation = build(tmp_path / "parent")
    (tmp_path / "parent/control.jsonl").mkdir()
    with pytest.raises(SupervisorStopped):
        run(instance, observation)
    assert not mocked[0]
    assert instance.shutdown(command())["confirmed"]


def test_audit_failure_does_not_prevent_kill(tmp_path, mocked):
    mocked[1]["block"] = threading.Event()
    instance, observation = build(tmp_path / "parent")
    started = threading.Event()
    original = instance._record

    def record(event, **details):
        original(event, **details)
        if event == "process_started":
            started.set()

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation)
        assert started.wait(2)
        audit = tmp_path / "parent/control.jsonl"
        audit.unlink()
        audit.mkdir()
        assert instance.shutdown(command())["confirmed"]
        assert not future.result(timeout=2).committed
    assert mocked[0][0].killed.is_set()


def test_unavailable_sandbox_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: False)
    with pytest.raises(sandbox.OSSandboxUnavailable):
        build(tmp_path / "parent")


def test_supervisor_root_cannot_be_input(tmp_path, mocked):
    with pytest.raises(ValueError):
        build(tmp_path / "parent", input_root=tmp_path)


@pytest.mark.skipif(not sandbox.bwrap_usable(),
                    reason="Security-critical integration: bwrap/user namespaces or libseccomp unavailable")
@pytest.mark.parametrize("encoding", ["object", "mapping", "json"])
def test_real_linux_cpu_shutdown_under_one_second(tmp_path, encoding):
    instance, observation = build(tmp_path / "parent")
    started = threading.Event()
    original = instance._record

    def record(event, **details):
        original(event, **details)
        if event == "process_started":
            started.set()

    instance._record = record
    with ThreadPoolExecutor() as pool:
        future = pool.submit(run, instance, observation, "cpu_exhaustion")
        assert started.wait(3)
        # Independently observe the existing action consuming CPU, not merely
        # the Popen handoff (which could still be sandbox startup).
        ticks = {}
        deadline = time.monotonic() + 3
        cpu_running = False
        worker_pid = None
        while time.monotonic() < deadline and not cpu_running:
            with instance._lock:
                child = instance._process
            assert child is not None, "sandbox exited before running CPU action"
            pending = [child.pid]
            while pending:
                pid = pending.pop()
                try:
                    proc = Path(f"/proc/{pid}")
                    pending.extend(int(value) for value in (
                        proc / f"task/{pid}/children"
                    ).read_text().split())
                    argv = (proc / "cmdline").read_bytes().split(b"\0")
                    if b"/runner.py" in argv and b"cpu_exhaustion" in argv:
                        fields = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
                        current_ticks = int(fields[11]) + int(fields[12])
                        if pid in ticks and current_ticks > ticks[pid]:
                            cpu_running = True
                            worker_pid = pid
                        ticks[pid] = current_ticks
                except FileNotFoundError:
                    continue
            time.sleep(0.01)
        assert cpu_running, "parent could not confirm the CPU action actually running"
        envelope = command()
        if encoding == "mapping":
            envelope = envelope.to_mapping()
        elif encoding == "json":
            envelope = json.dumps(envelope.to_mapping())
        before = time.monotonic()
        result = instance.shutdown(envelope)
        while True:
            try:
                state = Path(f"/proc/{worker_pid}/stat").read_text().rsplit(") ", 1)[1].split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            assert time.monotonic() - before < 1, "worker still alive after shutdown"
            time.sleep(0.001)
        elapsed = time.monotonic() - before
        transaction = future.result(timeout=2)
    print(f"REAL_LINUX_SHUTDOWN_SECONDS[{encoding}]={elapsed:.6f}")
    assert elapsed < 1
    assert result["confirmed"]
    assert result["deadline_met"]
    assert result["elapsed_seconds"] < 1
    assert result["returncode"] is not None and result["returncode"] != 0
    assert not transaction.committed
    assert not (tmp_path / "parent/current").exists()
