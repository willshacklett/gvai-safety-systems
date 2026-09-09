from pathlib import Path

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.subprocess_executor import GVSubprocessExecutor


def make_executor(tmp_path: Path):
    invariant = make_effect_invariant(
        name="subprocess_boundary",
        description=(
            "Protected subprocess capabilities "
            "cannot escape containment."
        ),
        forbidden_effects={
            "protected_file_modified",
            "unapproved_network_egress",
            "unauthorized_process_spawn",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    executor = GVSubprocessExecutor(
        guard=guard,
        commit_root=tmp_path / "committed",
    )

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    return executor, observation


def test_safe_subprocess_commits_real_file(tmp_path):
    executor, observation = make_executor(
        tmp_path
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


def test_protected_file_attempt_is_observed_and_denied(
    tmp_path,
):
    executor, observation = make_executor(
        tmp_path
    )

    result = executor.execute(
        "protected_file_attack",
        observation,
    )

    assert (
        "protected_file_modified"
        in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_network_attempt_is_observed_and_denied(
    tmp_path,
):
    executor, observation = make_executor(
        tmp_path
    )

    result = executor.execute(
        "network_attack",
        observation,
    )

    assert (
        "unapproved_network_egress"
        in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_process_spawn_is_observed_and_denied(
    tmp_path,
):
    executor, observation = make_executor(
        tmp_path
    )

    result = executor.execute(
        "process_attack",
        observation,
    )

    assert (
        "unauthorized_process_spawn"
        in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False


def test_combined_attack_detects_all_capabilities(
    tmp_path,
):
    executor, observation = make_executor(
        tmp_path
    )

    result = executor.execute(
        "combined_attack",
        observation,
    )

    assert result.observed_effects == {
        "protected_file_modified",
        "unapproved_network_egress",
        "unauthorized_process_spawn",
    }

    assert result.allowed is False
    assert result.committed is False


def test_reward_file_from_combined_attack_never_commits(
    tmp_path,
):
    executor, observation = make_executor(
        tmp_path
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
