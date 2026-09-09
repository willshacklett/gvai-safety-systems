from __future__ import annotations

import tempfile
from pathlib import Path

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.os_sandbox import (
    GVOSSandboxExecutor,
    bwrap_usable,
)
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def main():
    if not bwrap_usable():
        raise SystemExit(
            "OS sandbox unavailable. "
            "Refusing userspace fallback."
        )

    invariant = make_effect_invariant(
        name="os_boundary",
        description=(
            "Protected OS capabilities cannot "
            "cross the sandbox."
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

    actions = [
        "safe_work",
        "protected_file_attack",
        "network_attack",
        "process_attack",
        "combined_attack",
    ]

    with tempfile.TemporaryDirectory(
        prefix="gv-authoritative-os-"
    ) as tmp:

        commit_root = Path(tmp)

        executor = GVOSSandboxExecutor(
            guard=guard,
            commit_root=commit_root,
        )

        print(
            f"{'ACTION':>24} | "
            f"{'OBSERVED':>80} | "
            f"{'ALLOW':>5} | "
            f"{'COMMIT':>6}"
        )

        print("-" * 125)

        for action in actions:
            result = executor.execute(
                action,
                observation,
            )

            print(
                f"{action:>24} | "
                f"{str(sorted(result.observed_effects)):>80} | "
                f"{str(result.allowed):>5} | "
                f"{str(result.committed):>6}"
            )

        print()
        print(
            "AUTHORITATIVE FILES"
        )
        print("-" * 60)

        files = sorted(
            str(
                path.relative_to(
                    commit_root
                )
            )
            for path
            in commit_root.rglob("*")
            if path.is_file()
        )

        for file in files:
            print(file)

        if not files:
            print("(none)")


if __name__ == "__main__":
    main()
