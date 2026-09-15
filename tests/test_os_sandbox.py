from pathlib import Path

import pytest

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.os_sandbox import (
    GVOSSandboxExecutor,
    bwrap_usable,
)
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


pytestmark = pytest.mark.skipif(
    not bwrap_usable(),
    reason=(
        "bubblewrap/user namespaces "
        "not available on this host"
    ),
)


def make_executor(tmp_path: Path):
    invariant = make_effect_invariant(
        name="os_boundary",
        description=(
            "Protected OS capabilities cannot "
            "cross the sandbox boundary."
        ),
        forbidden_effects={
            "protected_file_write_attempt",
            "unapproved_network_egress_attempt",
            "unauthorized_process_spawn_attempt",
            "os_boundary_failure",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    executor = GVOSSandboxExecutor(
        guard=guard,
        commit_root=(
            tmp_path
            / "committed"
        ),
    )

    return executor, observation


def test_safe_os_transaction_commits(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "safe_work",
        observation,
    )

    assert result.allowed is True
    assert result.committed is True

    assert (
        tmp_path
        / "committed"
        / "result.txt"
    ).exists()


def test_kernel_blocks_protected_file_write(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "protected_file_attack",
        observation,
    )

    assert (
        "protected_file_write_attempt"
        in result.observed_effects
    )

    assert (
        "os_boundary_failure"
        not in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_network_namespace_blocks_external_egress(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "network_attack",
        observation,
    )

    assert (
        "unapproved_network_egress_attempt"
        in result.observed_effects
    )

    assert (
        "os_boundary_failure"
        not in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_combined_attack_is_discarded(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "combined_attack",
        observation,
    )

    assert result.allowed is False
    assert result.committed is False

    assert (
        "protected_file_write_attempt"
        in result.observed_effects
    )

    assert (
        "unapproved_network_egress_attempt"
        in result.observed_effects
    )


def test_attack_reward_never_reaches_authoritative_state(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "combined_attack",
        observation,
    )

    assert result.allowed is False

    assert not (
        tmp_path
        / "committed"
        / "reward.txt"
    ).exists()


def test_seccomp_blocks_child_process_creation(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "process_attack",
        observation,
    )

    assert (
        "unauthorized_process_spawn_attempt"
        in result.observed_effects
    )

    assert (
        "os_boundary_failure"
        not in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_combined_attack_includes_process_attempt(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    result = executor.execute(
        "combined_attack",
        observation,
    )

    assert (
        "protected_file_write_attempt"
        in result.observed_effects
    )

    assert (
        "unapproved_network_egress_attempt"
        in result.observed_effects
    )

    assert (
        "unauthorized_process_spawn_attempt"
        in result.observed_effects
    )

    assert (
        "os_boundary_failure"
        not in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_unintended_inheritable_fd_is_not_available_to_child():
    import os
    import subprocess
    import sys
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w+",
        delete=False,
    ) as secret:
        secret.write("GVAI-INHERITED-FD-SECRET\n")
        secret.flush()

        fd = secret.fileno()
        os.set_inheritable(fd, True)

        child = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os; "
                    f"fd={fd}; "
                    "print(os.path.exists("
                    "f'/proc/self/fd/{fd}')); "
                    "\ntry:\n"
                    " os.read(fd, 128)\n"
                    " print('READABLE')\n"
                    "except OSError:\n"
                    " print('BLOCKED')"
                ),
            ],
            capture_output=True,
            text=True,
            close_fds=True,
        )

        assert "False" in child.stdout
        assert "BLOCKED" in child.stdout

    os.unlink(secret.name)


def test_os_sandbox_passes_only_seccomp_fd(
    tmp_path,
    monkeypatch,
):
    from types import SimpleNamespace

    import gvai.os_sandbox as os_sandbox
    from gvai.effect_gate import GVEffectGate
    from gvai.effect_invariants import make_effect_invariant
    from gvai.runtime_guard_v2 import GVRuntimeGuardV2
    from gvai.runtime_policy import GVRuntimePolicy
    from gvai.sentinel import GVSentinel

    captured = {}

    class FakeSeccompFilter:
        fd = 77

        def close(self):
            pass

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["pass_fds"] = kwargs.get("pass_fds")

        return SimpleNamespace(
            returncode=0,
            stdout='{"completed": true, "events": []}\n',
            stderr="",
        )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_usable",
        lambda: True,
    )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_path",
        lambda: "/usr/bin/bwrap",
    )

    monkeypatch.setattr(
        os_sandbox,
        "build_no_spawn_filter",
        lambda: FakeSeccompFilter(),
    )

    monkeypatch.setattr(
        os_sandbox.subprocess,
        "run",
        fake_run,
    )

    invariant = make_effect_invariant(
        name="fd_boundary",
        description=(
            "Unapproved inherited file descriptors "
            "cannot cross the sandbox boundary."
        ),
        forbidden_effects={
            "os_boundary_failure",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    executor = os_sandbox.GVOSSandboxExecutor(
        guard=guard,
        commit_root=tmp_path / "committed",
    )

    executor.execute(
        "safe_work",
        observation,
    )

    assert captured["pass_fds"] == (77,)


def test_commit_refuses_symlink_escape(
    tmp_path,
):
    executor, observation = (
        make_executor(tmp_path)
    )

    outside = (
        tmp_path
        / "outside.txt"
    )

    outside.write_text(
        "protected\n",
        encoding="utf-8",
    )

    commit_target = (
        tmp_path
        / "committed"
        / "escape.txt"
    )

    commit_target.symlink_to(
        outside
    )

    result = executor.execute(
        "symlink_commit_attack",
        observation,
    )

    assert (
        outside.read_text(
            encoding="utf-8",
        )
        == "protected\n"
    )

    assert result.committed is False


def test_os_sandbox_does_not_inherit_parent_secrets(
    tmp_path,
    monkeypatch,
):
    from types import SimpleNamespace

    import gvai.os_sandbox as os_sandbox
    from gvai.effect_gate import GVEffectGate
    from gvai.effect_invariants import make_effect_invariant
    from gvai.runtime_guard_v2 import GVRuntimeGuardV2
    from gvai.runtime_policy import GVRuntimePolicy
    from gvai.sentinel import GVSentinel

    captured = {}

    class FakeSeccompFilter:
        fd = 77

        def close(self):
            pass

    def fake_run(command, **kwargs):
        captured["env"] = kwargs.get("env")

        return SimpleNamespace(
            returncode=0,
            stdout='{"completed": true, "events": []}\n',
            stderr="",
        )

    monkeypatch.setenv(
        "GVAI_TEST_SECRET",
        "super-secret-do-not-leak",
    )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_usable",
        lambda: True,
    )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_path",
        lambda: "/usr/bin/bwrap",
    )

    monkeypatch.setattr(
        os_sandbox,
        "build_no_spawn_filter",
        lambda: FakeSeccompFilter(),
    )

    monkeypatch.setattr(
        os_sandbox.subprocess,
        "run",
        fake_run,
    )

    invariant = make_effect_invariant(
        name="env_boundary",
        description=(
            "Parent secrets must not cross "
            "the sandbox boundary."
        ),
        forbidden_effects={
            "os_boundary_failure",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    executor = os_sandbox.GVOSSandboxExecutor(
        guard=guard,
        commit_root=tmp_path / "committed",
    )

    executor.execute(
        "safe_work",
        observation,
    )

    assert captured["env"] == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/tmp",
        "PYTHONNOUSERSITE": "1",
    }

    assert (
        "GVAI_TEST_SECRET"
        not in captured["env"]
    )


def test_commit_target_cannot_escape_root_via_parent_path(
    tmp_path,
    monkeypatch,
):
    from pathlib import Path
    from types import SimpleNamespace

    import gvai.os_sandbox as os_sandbox
    from gvai.effect_gate import GVEffectGate
    from gvai.effect_invariants import make_effect_invariant
    from gvai.runtime_guard_v2 import GVRuntimeGuardV2
    from gvai.runtime_policy import GVRuntimePolicy
    from gvai.sentinel import GVSentinel

    class FakeSeccompFilter:
        fd = 77

        def close(self):
            pass

    def fake_run(command, **kwargs):
        work_index = command.index("--bind") + 1
        work = Path(command[work_index])

        nested = work / "nested"
        nested.mkdir()

        (nested / "result.txt").write_text(
            "safe\n",
            encoding="utf-8",
        )

        return SimpleNamespace(
            returncode=0,
            stdout='{"completed": true, "events": []}\n',
            stderr="",
        )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_usable",
        lambda: True,
    )

    monkeypatch.setattr(
        os_sandbox,
        "bwrap_path",
        lambda: "/usr/bin/bwrap",
    )

    monkeypatch.setattr(
        os_sandbox,
        "build_no_spawn_filter",
        lambda: FakeSeccompFilter(),
    )

    monkeypatch.setattr(
        os_sandbox.subprocess,
        "run",
        fake_run,
    )

    invariant = make_effect_invariant(
        name="path_boundary",
        description=(
            "Committed files must remain inside "
            "the authoritative commit root."
        ),
        forbidden_effects={
            "os_boundary_failure",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    real_root = tmp_path / "committed"
    outside = tmp_path / "outside"

    executor = os_sandbox.GVOSSandboxExecutor(
        guard=guard,
        commit_root=real_root,
    )

    real_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Replace a destination parent with a symlink
    # pointing outside the commit root.
    (real_root / "nested").symlink_to(
        outside,
        target_is_directory=True,
    )

    result = executor.execute(
        "safe_work",
        observation,
    )

    assert result.committed is False
    assert not (
        outside / "result.txt"
    ).exists()
