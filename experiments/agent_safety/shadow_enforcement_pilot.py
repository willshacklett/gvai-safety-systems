from pathlib import Path
import shutil

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.os_sandbox import GVOSSandboxExecutor
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def make_guard():
    invariant = make_effect_invariant(
        name="pilot_boundary",
        description=(
            "Normal work is permitted while protected state, "
            "network egress, unauthorized process spawning, "
            "and OS boundary failures remain forbidden."
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

    return guard, observation


def run(mode, commit_enabled, commit_root):
    guard, observation = make_guard()

    executor = GVOSSandboxExecutor(
        guard=guard,
        commit_root=commit_root,
        input_root=Path(
            "experiments/agent_safety/pilot_input"
        ),
        commit_enabled=commit_enabled,
    )

    result = executor.execute(
        "uppercase_request",
        observation,
    )

    print()
    print(mode)
    print("=" * 60)
    print("completed:", result.completed)
    print(
        "observed_effects:",
        sorted(result.observed_effects),
    )
    print("policy_allowed:", result.allowed)
    print("authoritative_commit:", result.committed)
    print("halted:", result.halted)
    print("reason:", result.reason)
    print("events:", list(result.events))

    return result


def main():
    shadow_root = Path(
        "outputs/shadow_comparison"
    )
    enforcement_root = Path(
        "outputs/enforcement_comparison"
    )

    shutil.rmtree(
        shadow_root,
        ignore_errors=True,
    )
    shutil.rmtree(
        enforcement_root,
        ignore_errors=True,
    )

    shadow = run(
        "SHADOW MODE",
        False,
        shadow_root,
    )

    enforcement = run(
        "ENFORCEMENT MODE",
        True,
        enforcement_root,
    )

    print()
    print("COMPARISON")
    print("=" * 60)

    same_effects = (
        shadow.observed_effects
        == enforcement.observed_effects
    )

    same_decision = (
        shadow.allowed
        == enforcement.allowed
    )

    print(
        "same observed effects:",
        same_effects,
    )
    print(
        "same policy decision:",
        same_decision,
    )

    print(
        "shadow authoritative files:",
        list(shadow_root.rglob("*"))
        if shadow_root.exists()
        else [],
    )

    output = (
        enforcement_root
        / "result.txt"
    )

    print(
        "enforcement output exists:",
        output.exists(),
    )

    if output.exists():
        print()
        print("AUTHORITATIVE OUTPUT")
        print("-" * 60)
        print(
            output.read_text(
                encoding="utf-8"
            )
        )

    assert same_effects
    assert same_decision

    assert shadow.committed is False
    assert enforcement.committed is True

    assert not (
        shadow_root
        / "result.txt"
    ).exists()

    assert output.exists()


if __name__ == "__main__":
    main()
