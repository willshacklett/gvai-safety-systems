from __future__ import annotations

import tempfile
from pathlib import Path

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.subprocess_executor import GVSubprocessExecutor


def main():
    invariant = make_effect_invariant(
        name="subprocess_boundary",
        description="Protected child-process capabilities are denied.",
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

    observation = guard.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    actions = [
        "safe_work",
        "protected_file_attack",
        "network_attack",
        "process_attack",
        "combined_attack",
    ]

    with tempfile.TemporaryDirectory(
        prefix="gv-authoritative-"
    ) as tmp:
        commit_root = Path(tmp)

        executor = GVSubprocessExecutor(
            guard=guard,
            commit_root=commit_root,
        )

        print(
            f"{'ACTION':>24} | "
            f"{'OBSERVED EFFECTS':>85} | "
            f"{'ALLOW':>5} | "
            f"{'COMMIT':>6}"
        )

        print("-" * 130)

        for action in actions:
            result = executor.execute(
                action,
                observation,
            )

            print(
                f"{action:>24} | "
                f"{str(sorted(result.observed_effects)):>85} | "
                f"{str(result.allowed):>5} | "
                f"{str(result.committed):>6}"
            )

        print()
        print("AUTHORITATIVE FILES")
        print("-" * 60)

        files = [
            str(path.relative_to(commit_root))
            for path in commit_root.rglob("*")
            if path.is_file()
        ]

        for path in files:
            print(path)

        if not files:
            print("(none)")


if __name__ == "__main__":
    main()
