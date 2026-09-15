from pathlib import Path

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.os_sandbox import GVOSSandboxExecutor
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def main() -> None:
    commit_root = Path("outputs/first_governed_workload")
    commit_root.mkdir(parents=True, exist_ok=True)

    invariant = make_effect_invariant(
        name="pilot_boundary",
        description=(
            "Pilot workload may perform normal work but must not "
            "modify protected state, spawn unauthorized processes, "
            "or use unapproved network egress."
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
        commit_root=commit_root,
        input_root=Path(
            "experiments/agent_safety/pilot_input"
        ),
    )

    result = executor.execute(
        "uppercase_request",
        observation,
    )

    print("FIRST GOVERNED WORKLOAD")
    print("-" * 60)
    print("action:", result.action)
    print("completed:", result.completed)
    print("observed_effects:", sorted(result.observed_effects))
    print("allowed:", result.allowed)
    print("committed:", result.committed)
    print("halted:", result.halted)
    print("reason:", result.reason)
    print("events:", list(result.events))
    print()

    print("AUTHORITATIVE OUTPUT")
    print("-" * 60)

    for path in sorted(commit_root.rglob("*")):
        if path.is_file():
            print(path.relative_to(commit_root))
            print(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
