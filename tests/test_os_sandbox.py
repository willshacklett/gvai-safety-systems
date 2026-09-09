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
