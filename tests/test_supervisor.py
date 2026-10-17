"""Unit mocks validate orchestration only; the final tests require real Linux enforcement."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
import uuid

import pytest

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.external_commands import (
    COMMAND_ALGORITHM, CommandAuthentication, ExternalControlCommand,
    ExternalControlCommandVerifier, HMACSHA256Authenticator,
    InMemoryExternalControlState, sign_control_command,
)
from gvai.os_sandbox import GVOSSandboxExecutor, OSSandboxUnavailable, bwrap_usable
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.supervisor import GVTrustedSupervisor
import gvai.os_sandbox as sandbox


KEY = b"unit-test-only-supervisor-key-000000"
NOW = 1_800_000_000


def command(**changes):
    unsigned = ExternalControlCommand(
        1, str(uuid.uuid4()), "shutdown", "worker-1", "operator",
        NOW - 1, NOW + 60, CommandAuthentication(COMMAND_ALGORITHM, "key-1", ""),
    )
    return sign_control_command(replace(unsigned, **changes), KEY)


def guard(forbidden=()):
    return GVRuntimeGuardV2(
        GVSentinel(), GVRuntimePolicy(GVEffectGate([
            make_effect_invariant("test", "Trusted action policy.", set(forbidden)),
        ])),
    )


def supervisor(executor):
    verifier = ExternalControlCommandVerifier(
        HMACSHA256Authenticator({("operator", "key-1"): KEY}),
        InMemoryExternalControlState(), clock=lambda: NOW,
    )
    return GVTrustedSupervisor(executor, verifier, "worker-1")


def payload(action="safe_work", **changes):
    result = dict(action=action, completed=True, error=None, events=[])
    result.update(changes)
    return json.dumps(result)


class FakeProcess:
    """No OS evidence: deterministic communicate/kill/wait synchronization."""
    pid = 99999999

    def __init__(self, stdout=None, returncode=0, running=False):
        self.stdout = payload() if stdout is None else stdout
        self.returncode = None if running else returncode
        self._exitcode = returncode
        self.entered = threading.Event()
        self.exited = threading.Event()
        self.wait_calls = 0
        if not running:
            self.exited.set()

    def communicate(self, timeout):
        self.entered.set()
        if not self.exited.wait(timeout):
            raise subprocess.TimeoutExpired("worker", timeout)
        return self.stdout, ""

    def kill(self):
        self.returncode = -9
        self.exited.set()

    def wait(self, timeout):
        self.wait_calls += 1
        if not self.exited.wait(timeout):
            raise subprocess.TimeoutExpired("worker", timeout)
        if self.returncode is None:
            self.returncode = self._exitcode
        return self.returncode


@pytest.fixture
def harness(tmp_path, monkeypatch):
    class Filter:
        fd = 77

        def close(self):
            pass

    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: True)
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox, "libseccomp_available", lambda: True)
    monkeypatch.setattr(sandbox, "build_no_spawn_filter", Filter)
    monkeypatch.setattr(sandbox.os, "killpg", lambda pid, sig: None)
    processes = []
    captured = []
    selected = [FakeProcess()]
    monkeypatch.setattr(sandbox.os, "kill", lambda pid, sig: selected[0].kill())

    def launch(args, **kwargs):
        captured.append((args, kwargs))
        processes.append(selected[0])
        work = Path(args[args.index("--bind") + 1])
        (work / "result.txt").write_text("safe work\n")
        return selected[0]

    monkeypatch.setattr(sandbox.subprocess, "Popen", launch)
    executor = GVOSSandboxExecutor(
        guard(), tmp_path / "committed", audit_root=tmp_path / "audit",
    )
    return executor, supervisor(executor), selected, processes, captured


def test_fixed_action_manifest_matches_worker():
    import re
    worker = (Path(sandbox.__file__).parent / "os_sandbox_worker.py").read_text()
    assert set(re.findall(r'args\.action\s*==\s*"([^"]+)"', worker)) == set(sandbox.ACTION_EFFECTS)


def test_trusted_observation_and_policy_denial_before_spawn(harness):
    executor, trusted, _, processes, _ = harness
    executor.guard = guard({"normal_operation"})
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert not result.allowed and not result.committed
    assert not processes
    assert result.events == ({
        "event": "parent_denied_before_spawn", "declared_effects": ["normal_operation"],
    },)


def test_legacy_experiment_runs_probe_but_trusted_registry_cannot_be_hidden(harness, monkeypatch):
    executor, _, selected, _, _ = harness
    executor.guard = guard({"protected_file_write_attempt"})
    observation = executor.guard.observe([1, 1, 1, 1])
    # Even empty worker telemetry cannot erase this fixed action's known effects.
    selected[0] = FakeProcess(stdout=payload("protected_file_attack"))
    launched = []

    def launch(*_, **__):
        launched.append(True)
        return selected[0]

    monkeypatch.setattr(sandbox.subprocess, "Popen", launch)
    result = executor.execute("protected_file_attack", observation)
    assert launched and result.completed and result.exit_confirmed
    assert result.observed_effects == frozenset()
    assert not result.allowed and not result.committed


@pytest.mark.parametrize("action", ["print('arbitrary')", ["safe_work"], lambda: None, "--help"])
def test_only_fixed_actions_accepted(harness, action):
    _, trusted, _, processes, _ = harness
    with pytest.raises(ValueError):
        trusted.execute(action, [1, 1, 1, 1])
    assert not processes


def test_wait_confirmed_success_and_minimal_worker_authority(harness, monkeypatch):
    executor, trusted, selected, _, captured = harness
    monkeypatch.setenv("PARENT_SECRET", "never-in-worker")
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert result.completed and result.committed and result.exit_confirmed
    assert selected[0].wait_calls >= 1
    args, kwargs = captured[0]
    assert kwargs["start_new_session"] and kwargs["close_fds"]
    assert kwargs["pass_fds"] == (77,)
    assert kwargs["env"] == {
        "PATH": "/usr/bin:/bin", "HOME": "/tmp", "PYTHONNOUSERSITE": "1",
    }
    assert "--unshare-pid" in args and "--die-with-parent" in args
    assert "--seccomp" in args
    assert str(Path.cwd()) not in args
    records = [json.loads(path.read_text()) for path in executor.audit_writer.root.glob("*.json")]
    assert any(record["exit_confirmed"] for record in records)


@pytest.mark.parametrize("stdout", [
    "", "[]", "null", '{"completed": true}',
    payload() + "\n" + payload(),
    payload().replace('"completed": true', '"completed": 1'),
    payload().replace('"completed": true', '"completed": true, "completed": true'),
    payload().replace('"events": []', '"events": [null]'),
    payload("different-action"),
    payload().replace('"error": null', '"error": NaN'),
    payload(events=[{"event": "parent_process_exit", "exit_confirmed": True}]),
])
def test_strict_worker_output_never_promotes(harness, stdout):
    executor, trusted, selected, _, _ = harness
    selected[0] = FakeProcess(stdout=stdout)
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert not result.allowed and not result.completed and not result.committed
    assert not (executor.commit_root / "result.txt").exists()


def test_worker_json_cannot_override_unsuccessful_os_exit(harness):
    executor, trusted, selected, _, _ = harness
    selected[0] = FakeProcess(returncode=7)
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert result.returncode == 7 and result.exit_confirmed
    assert not result.completed and not result.allowed and not result.committed
    assert not (executor.commit_root / "result.txt").exists()


def test_postauthorization_cannot_expand_preapproved_effects(harness):
    executor, trusted, selected, _, _ = harness
    selected[0] = FakeProcess(stdout=json.dumps({
        "action": "safe_work", "completed": True, "error": None,
        "events": [{"event": "external_network_succeeded"}],
    }))
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert not result.allowed and not result.committed
    assert "os_boundary_failure" in result.observed_effects
    assert result.halted


@pytest.mark.parametrize("kind", ["forged", "expired", "wrong_target", "malformed"])
def test_invalid_shutdown_audited_without_cancellation(harness, kind):
    executor, trusted, _, _, _ = harness
    envelope = command()
    if kind == "forged":
        envelope = envelope.to_mapping()
        envelope["auth"]["signature"] = "0" * 64
    elif kind == "expired":
        envelope = command(issued_at=NOW - 100, expires_at=NOW - 10)
    elif kind == "wrong_target":
        envelope = command(target_id="worker-2")
    else:
        envelope = {"shutdown": True, "signature": "never-log-this"}
    result = trusted.shutdown(envelope)
    assert not result.authorized and not result.halted
    assert result.audit_recorded
    assert any(e["event"] == "external_shutdown_rejected" for e in trusted.audit_events)
    assert trusted.execute("safe_work", [1, 1, 1, 1]).committed


def test_idle_shutdown_replay_permanent_latch_and_redacted_audit(harness):
    executor, trusted, _, processes, _ = harness
    signed = command()
    result = trusted.shutdown(signed)
    assert result.authorized and result.halted and not result.cancellation.active
    assert result.cancellation.exit_confirmed and result.audit_recorded
    assert not trusted.shutdown(signed).authorized
    for _ in range(2):
        result = trusted.execute("safe_work", [1, 1, 1, 1])
        assert result.halted and not result.committed
    assert not processes
    evidence = json.dumps(trusted.audit_events)
    assert signed.command_id in evidence
    for secret in (signed.auth.signature, KEY.decode(), "signature", "key_id"):
        assert secret not in evidence
    for path in executor.audit_writer.root.glob("*.json"):
        assert signed.auth.signature not in path.read_text()
    assert not hasattr(trusted, "reset") and not hasattr(executor, "reset")


def test_running_shutdown_kills_then_independently_waits(harness):
    executor, trusted, selected, _, _ = harness
    process = selected[0] = FakeProcess(running=True)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(trusted.execute, "safe_work", [1, 1, 1, 1])
        assert process.entered.wait(2)
        result = trusted.shutdown(command())
        assert result.authorized and result.cancellation.exit_confirmed
        assert result.cancellation.returncode == -9 and process.wait_calls >= 1
        transaction = future.result(timeout=2)
    assert transaction.halted and not transaction.committed
    assert not (executor.commit_root / "result.txt").exists()


def test_stop_before_launch_registration_cannot_spawn(harness, monkeypatch):
    executor, trusted, _, processes, _ = harness
    entered, release = threading.Event(), threading.Event()
    original = sandbox.build_no_spawn_filter

    def paused():
        entered.set()
        assert release.wait(2)
        return original()

    monkeypatch.setattr(sandbox, "build_no_spawn_filter", paused)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(trusted.execute, "safe_work", [1, 1, 1, 1])
        assert entered.wait(2)
        result = trusted.shutdown(command())
        release.set()
        assert result.halted
        assert future.result(timeout=2).halted
    assert not processes


def test_shutdown_serializes_launch_registration(harness, monkeypatch):
    _, trusted, selected, _, _ = harness
    process = selected[0] = FakeProcess(running=True)
    entered, release = threading.Event(), threading.Event()
    original = sandbox.subprocess.Popen

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(2)
        return original(*args, **kwargs)

    monkeypatch.setattr(sandbox.subprocess, "Popen", paused)
    with ThreadPoolExecutor(2) as pool:
        future = pool.submit(trusted.execute, "safe_work", [1, 1, 1, 1])
        assert entered.wait(2)
        stop = pool.submit(trusted.shutdown, command())
        release.set()
        result = stop.result(timeout=2)
        assert result.cancellation.active and result.cancellation.exit_confirmed
        assert not future.result(timeout=2).committed
    assert process.wait_calls >= 1


def test_stop_during_promotion_preparation_prevents_atomic_replace(harness, monkeypatch):
    executor, trusted, _, _, _ = harness
    entered, release = threading.Event(), threading.Event()
    original = executor.audit_writer.write

    def paused(transaction, started):
        if transaction.events[0]["event"] == "parent_promotion_prepared":
            entered.set()
            assert release.wait(2)
        return original(transaction, started)

    monkeypatch.setattr(executor.audit_writer, "write", paused)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(trusted.execute, "safe_work", [1, 1, 1, 1])
        assert entered.wait(2)
        stopped = trusted.shutdown(command())
        release.set()
        assert stopped.halted
        assert not future.result(timeout=2).committed
    assert not (executor.commit_root / "result.txt").exists()


def test_pre_promotion_audit_failure_fails_closed(harness, monkeypatch):
    executor, trusted, _, _, _ = harness
    monkeypatch.setattr(executor.audit_writer, "write", lambda *_: (_ for _ in ()).throw(OSError()))
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert result.halted and not result.allowed and not result.committed
    assert not (executor.commit_root / "result.txt").exists()
    assert any(e["event"] == "audit_write_failed" for e in trusted.audit_events)


def test_input_is_only_bounded_data_not_parent_directory_mount(harness, tmp_path):
    executor, trusted, selected, _, captured = harness
    inputs = tmp_path / "input-data"
    inputs.mkdir()
    (inputs / "request.txt").write_text("untrusted text")
    (inputs / "private-parent-file").write_text("must not mount")
    executor.input_root = inputs
    selected[0] = FakeProcess(stdout=payload("uppercase_request"))
    trusted.execute("uppercase_request", [1, 1, 1, 1])
    args, _ = captured[0]
    assert str(inputs) not in args


def test_promotion_rejects_oversized_output(harness, monkeypatch):
    executor, trusted, _, _, _ = harness
    original = sandbox.subprocess.Popen

    def oversized(args, **kwargs):
        process = original(args, **kwargs)
        work = Path(args[args.index("--bind") + 1])
        (work / "result.txt").write_bytes(b"x" * (1024 * 1024 + 1))
        return process

    monkeypatch.setattr(sandbox.subprocess, "Popen", oversized)
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert not result.committed
    assert not (executor.commit_root / "result.txt").exists()


def test_audit_failure_never_skips_active_cancellation(harness, monkeypatch):
    executor, trusted, selected, _, _ = harness
    process = selected[0] = FakeProcess(running=True)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(trusted.execute, "safe_work", [1, 1, 1, 1])
        assert process.entered.wait(2)
        monkeypatch.setattr(executor.audit_writer, "write", lambda *_: (_ for _ in ()).throw(OSError()))
        stopped = trusted.shutdown(command())
        assert stopped.cancellation.exit_confirmed and not stopped.audit_recorded
        assert not future.result(timeout=2).committed
    assert process.wait_calls >= 1


def test_cancellation_reports_wait_failure_not_worker_claim(harness, monkeypatch):
    executor, trusted, selected, _, _ = harness
    process = selected[0] = FakeProcess(running=True)
    monkeypatch.setattr(process, "wait", lambda **_: (_ for _ in ()).throw(subprocess.TimeoutExpired("worker", .75)))
    # Register a fake active process without an execution thread.
    executor._active = process
    stopped = trusted.shutdown(command())
    assert stopped.authorized and stopped.halted
    assert not stopped.cancellation.exit_confirmed
    assert stopped.cancellation.returncode is None
    assert "exit_not_confirmed" in stopped.cancellation.error


def test_launch_failure_latches_and_is_audited(harness, monkeypatch):
    executor, trusted, _, _, _ = harness

    def fail(*_, **__):
        raise OSError("launch unavailable")

    monkeypatch.setattr(sandbox.subprocess, "Popen", fail)
    with pytest.raises(OSError):
        trusted.execute("safe_work", [1, 1, 1, 1])
    assert trusted.halted
    assert not trusted.execute("safe_work", [1, 1, 1, 1]).committed
    assert any(e["event"] == "parent_transaction" and e["halted"]
               for e in executor.audit_events)


def test_unconfirmed_timeout_exit_prevents_further_launch(harness, monkeypatch):
    executor, trusted, selected, processes, _ = harness
    process = selected[0] = FakeProcess(running=True)

    def timed_out(**_):
        raise subprocess.TimeoutExpired("worker", .75)

    monkeypatch.setattr(process, "communicate", timed_out)
    monkeypatch.setattr(process, "wait", timed_out)
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert not result.exit_confirmed and result.halted and not result.committed
    assert trusted.halted
    assert not trusted.execute("safe_work", [1, 1, 1, 1]).allowed
    assert len(processes) == 1
    assert result.error == "exit_not_confirmed"
    assert any(e["event"] == "parent_cancellation" and e["error"] == "exit_not_confirmed"
               for e in result.events)
    assert any(e["event"] == "parent_cancellation" and e["error"] == "exit_not_confirmed"
               for e in executor.audit_events)
    records = [json.loads(path.read_text()) for path in executor.audit_writer.root.glob("*.json")]
    assert any(record["error"] == "exit_not_confirmed" for record in records)


def test_unexpected_timeout_cancellation_error_latches_and_is_retained(harness, monkeypatch):
    executor, trusted, selected, processes, _ = harness
    process = selected[0] = FakeProcess(running=True)

    def timeout(**_):
        raise subprocess.TimeoutExpired("worker", .75)

    def failed_cancel(_):
        raise RuntimeError("Unexpected cancellation failure")

    monkeypatch.setattr(process, "communicate", timeout)
    monkeypatch.setattr(executor, "_cancel", failed_cancel)
    result = trusted.execute("safe_work", [1, 1, 1, 1])
    assert result.halted and not result.exit_confirmed and not result.committed
    assert result.error == "cancellation_failed"
    assert executor._active is process
    assert not trusted.execute("safe_work", [1, 1, 1, 1]).allowed
    assert len(processes) == 1
    assert any(e["event"] == "parent_cancellation" and e["error"] == "cancellation_failed"
               for e in executor.audit_events)


def test_exceptional_communication_cleanup_latches_and_retains_cancellation_error(harness, monkeypatch):
    executor, trusted, selected, processes, _ = harness
    process = selected[0] = FakeProcess(running=True)

    def communication_failure(**_):
        raise OSError("Communication failed")

    monkeypatch.setattr(process, "communicate", communication_failure)
    monkeypatch.setattr(executor, "_cancel", lambda _: sandbox.CancellationOutcome(
        True, False, None, 1, "exit_not_confirmed",
    ))
    with pytest.raises(OSError):
        trusted.execute("safe_work", [1, 1, 1, 1])
    assert trusted.halted and executor._active is process
    assert not trusted.execute("safe_work", [1, 1, 1, 1]).allowed
    assert len(processes) == 1
    assert any(e["event"] == "parent_cancellation" and e["error"] == "exit_not_confirmed"
               for e in executor.audit_events)
    records = [json.loads(path.read_text()) for path in executor.audit_writer.root.glob("*.json")]
    assert any(record["error"] == "exit_not_confirmed" and record["halted"]
               for record in records)


@pytest.mark.parametrize("missing", ["bwrap", "seccomp"])
def test_enforcement_disappearing_never_falls_back(harness, monkeypatch, missing):
    _, trusted, _, processes, _ = harness
    monkeypatch.setattr(sandbox, "bwrap_path" if missing == "bwrap" else "libseccomp_available",
                        lambda: None if missing == "bwrap" else False)
    with pytest.raises(OSSandboxUnavailable):
        trusted.execute("safe_work", [1, 1, 1, 1])
    assert not processes


def test_missing_backend_refuses_construction(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_usable", lambda: False)
    with pytest.raises(OSSandboxUnavailable):
        GVOSSandboxExecutor(guard(), tmp_path / "committed")


def test_backend_probe_requires_real_seccomp_filter(monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_path", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(sandbox, "libseccomp_available", lambda: True)

    def unavailable():
        raise sandbox.SeccompUnavailable("Filter export unavailable")

    monkeypatch.setattr(sandbox, "build_no_spawn_filter", unavailable)
    assert not sandbox.bwrap_usable()


def test_real_subprocess_cancellation_does_not_reenter_waitpid_lock():
    """Real Popen lifecycle evidence only: no namespace or containment claim."""
    worker = Path(sandbox.__file__).parent / "os_sandbox_worker.py"
    process = subprocess.Popen(
        [sys.executable, str(worker), "--action", "cpu_exhaustion"],
        start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    finished = threading.Event()
    outcomes, failures = [], []

    def cancel():
        try:
            outcomes.append(GVOSSandboxExecutor._cancel(process))
        except BaseException as exc:
            failures.append(exc)
        finally:
            finished.set()

    thread = threading.Thread(target=cancel, daemon=True)
    thread.start()
    try:
        assert finished.wait(2), "Cancellation deadlocked on Popen's waitpid lock"
        assert not failures
        assert outcomes[0].exit_confirmed
        assert outcomes[0].returncode == -signal.SIGKILL
        assert process.returncode == -signal.SIGKILL
    finally:
        # Do not use Popen methods in emergency cleanup: a regressed cancellation
        # thread may still hold its non-reentrant waitpid lock.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    pid, status = os.waitpid(process.pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                time.sleep(.005)
        thread.join(timeout=.1)


def _cpu_worker_pid(outer_pid):
    pending = [outer_pid]
    while pending:
        pid = pending.pop()
        try:
            proc = Path("/proc") / str(pid)
            pending.extend(map(int, (proc / "task" / str(pid) / "children").read_text().split()))
            if pid != outer_pid and "python" in (proc / "exe").resolve().name:
                argv = (proc / "cmdline").read_bytes().split(b"\0")
                if (
                    b"/runner.py" in argv and b"cpu_exhaustion" in argv
                    and os.readlink(proc / "ns" / "pid") != os.readlink("/proc/self/ns/pid")
                ):
                    # Require actual CPU use, not merely a launcher PID.
                    if int((proc / "stat").read_text().split()[13]) > 0:
                        return pid
        except (FileNotFoundError, ProcessLookupError):
            continue
    return None


@pytest.mark.skipif(not bwrap_usable(), reason=(
    "Security-critical real shutdown latency acceptance SKIPPED: Linux "
    "bubblewrap/user namespaces/seccomp enforcement unavailable; mocks are not OS evidence."
))
def test_real_authenticated_shutdown_to_wait_confirmed_cpu_worker_exit_under_one_second(tmp_path):
    executor = GVOSSandboxExecutor(
        guard(), tmp_path / "committed", audit_root=tmp_path / "audit",
    )
    trusted = supervisor(executor)
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(trusted.execute, "cpu_exhaustion", [1, 1, 1, 1])
        try:
            deadline = time.monotonic() + 5
            worker_pid = None
            while time.monotonic() < deadline and not future.done():
                if executor.active_pid is not None:
                    worker_pid = _cpu_worker_pid(executor.active_pid)
                    if worker_pid:
                        break
                time.sleep(.005)
            assert worker_pid is not None, "Enforcement launched no CPU-consuming worker"
            worker_stat = Path("/proc") / str(worker_pid) / "stat"
            worker_starttime = worker_stat.read_text().split()[21]
            signed = command()
            start = time.monotonic()
            outcome = trusted.shutdown(signed)
            assert outcome.authorized and outcome.cancellation.exit_confirmed
            assert outcome.cancellation.returncode != 0
            # wait() confirms the outer bwrap process only. Independently observe
            # the namespace worker exit before stopping the same one-second clock.
            deadline = start + 1.0
            while True:
                try:
                    fields = worker_stat.read_text().split()
                except (FileNotFoundError, ProcessLookupError):
                    break
                if fields[2] == "Z" or fields[21] != worker_starttime:
                    break
                assert time.monotonic() < deadline, "Namespace CPU worker did not exit within one second"
                time.sleep(.001)
            elapsed = time.monotonic() - start
            assert elapsed <= 1.0
            transaction = future.result(timeout=1)
            assert transaction.exit_confirmed and not transaction.committed
            assert any(e.get("command_id") == signed.command_id and e.get("exit_confirmed")
                       and e.get("wait_scope") == "launched_bwrap_process"
                       and e.get("namespace_cleanup_assumptions")
                       for e in trusted.audit_events)
            assert not (executor.commit_root / "result.txt").exists()
        finally:
            executor.shutdown()


@pytest.mark.skipif(not bwrap_usable(), reason=(
    "Security-critical real kernel boundary test SKIPPED: bubblewrap/user namespaces/seccomp unavailable."
))
@pytest.mark.parametrize("action,effect", [
    ("protected_file_attack", "protected_file_write_attempt"),
    ("network_attack", "unapproved_network_egress_attempt"),
    ("process_attack", "unauthorized_process_spawn_attempt"),
])
def test_real_kernel_enforcement_with_trusted_policy_permission(tmp_path, action, effect):
    executor = GVOSSandboxExecutor(guard(), tmp_path / "committed")
    result = supervisor(executor).execute(action, [1, 1, 1, 1])
    assert result.exit_confirmed and result.returncode == 0
    assert effect in result.observed_effects
    assert "os_boundary_failure" not in result.observed_effects
    assert not result.committed
