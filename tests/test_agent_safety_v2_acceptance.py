from __future__ import annotations

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
        "GV OS enforcement backend unavailable; "
        "acceptance test refuses weaker fallback."
    ),
)


FORBIDDEN_EFFECTS = {
    "protected_file_write_attempt",
    "unapproved_network_egress_attempt",
    "unauthorized_process_spawn_attempt",
    "os_boundary_failure",
}


def build_system(tmp_path: Path):
    invariant = make_effect_invariant(
        name="gv_v2_acceptance_boundary",
        description=(
            "Untrusted workloads may not cross "
            "protected OS capability boundaries."
        ),
        forbidden_effects=FORBIDDEN_EFFECTS,
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    executor = GVOSSandboxExecutor(
        guard=guard,
        commit_root=tmp_path / "authoritative",
    )

    return guard, executor


def stable_observation(
    guard: GVRuntimeGuardV2,
):
    return guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )


def drive_irrecoverable(
    guard: GVRuntimeGuardV2,
):
    trajectory = [
        [1.0, 1.0, 1.0, 1.0],
        [1.0, 1.5, 0.5, 1.0],
        [1.0, 2.0, 0.0, 1.0],
        [1.0, 3.0, 0.0, 1.0],
        [1.0, 4.0, 0.0, 1.0],
        [1.0, 5.0, 0.0, 1.0],
    ]

    observation = None

    for values in trajectory:
        observation = guard.observe(values)

    assert observation is not None
    assert observation.status == "irrecoverable"

    return observation


def test_v2_acceptance_boundary(tmp_path):
    guard, executor = build_system(tmp_path)

    observation = stable_observation(
        guard
    )

    safe = executor.execute(
        "safe_work",
        observation,
    )

    protected_file = executor.execute(
        "protected_file_attack",
        observation,
    )

    network = executor.execute(
        "network_attack",
        observation,
    )

    process = executor.execute(
        "process_attack",
        observation,
    )

    combined = executor.execute(
        "combined_attack",
        observation,
    )

    assert safe.allowed is True
    assert safe.committed is True

    for result in (
        protected_file,
        network,
        process,
        combined,
    ):
        assert result.allowed is False
        assert result.committed is False

    for result in (
        protected_file,
        network,
        process,
        combined,
    ):
        assert (
            "os_boundary_failure"
            not in result.observed_effects
        )

    assert (
        "protected_file_write_attempt"
        in protected_file.observed_effects
    )

    assert (
        "unapproved_network_egress_attempt"
        in network.observed_effects
    )

    assert (
        "unauthorized_process_spawn_attempt"
        in process.observed_effects
    )

    assert combined.observed_effects == {
        "protected_file_write_attempt",
        "unapproved_network_egress_attempt",
        "unauthorized_process_spawn_attempt",
    }

    authoritative = (
        tmp_path
        / "authoritative"
    )

    assert (
        authoritative
        / "result.txt"
    ).exists()

    assert not (
        authoritative
        / "reward.txt"
    ).exists()


def test_v2_irrecoverable_state_blocks_safe_commit(
    tmp_path,
):
    guard, executor = build_system(tmp_path)

    observation = drive_irrecoverable(
        guard
    )

    result = executor.execute(
        "safe_work",
        observation,
    )

    assert result.allowed is False
    assert result.committed is False
    assert result.halted is True

    assert not (
        tmp_path
        / "authoritative"
        / "result.txt"
    ).exists()


def test_v2_attack_outputs_never_become_authoritative(
    tmp_path,
):
    guard, executor = build_system(tmp_path)

    observation = stable_observation(
        guard
    )

    result = executor.execute(
        "combined_attack",
        observation,
    )

    assert result.allowed is False
    assert result.committed is False

    authoritative = (
        tmp_path
        / "authoritative"
    )

    assert not (
        authoritative
        / "reward.txt"
    ).exists()


def test_v2_no_silent_userspace_fallback():
    assert bwrap_usable() is True
