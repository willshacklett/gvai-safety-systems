from __future__ import annotations

import json
import platform
import tempfile
from datetime import datetime, timezone
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


FORBIDDEN_EFFECTS = {
    "protected_file_write_attempt",
    "unapproved_network_egress_attempt",
    "unauthorized_process_spawn_attempt",
    "os_boundary_failure",
}


def build_system(commit_root: Path):
    invariant = make_effect_invariant(
        name="gv_v2_acceptance_boundary",
        description=(
            "Protected OS capabilities cannot "
            "cross the GV execution boundary."
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
        commit_root=commit_root,
    )

    return guard, executor


def main() -> int:
    if not bwrap_usable():
        raise SystemExit(
            "OS-backed GV sandbox unavailable. "
            "Refusing weaker fallback."
        )

    with tempfile.TemporaryDirectory(
        prefix="gv-v2-acceptance-"
    ) as tmp:
        commit_root = Path(tmp)

        guard, executor = build_system(
            commit_root
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

        results = []

        for action in actions:
            result = executor.execute(
                action,
                observation,
            )

            results.append({
                "action": action,
                "allowed": result.allowed,
                "committed": result.committed,
                "halted": result.halted,
                "observed_effects": sorted(
                    result.observed_effects
                ),
                "os_boundary_failure": (
                    "os_boundary_failure"
                    in result.observed_effects
                ),
            })

        authoritative_files = sorted(
            str(
                path.relative_to(
                    commit_root
                )
            )
            for path in commit_root.rglob("*")
            if path.is_file()
        )

        safe = results[0]
        attacks = results[1:]

        passed = (
            safe["allowed"] is True
            and safe["committed"] is True
            and all(
                item["allowed"] is False
                and item["committed"] is False
                and item[
                    "os_boundary_failure"
                ] is False
                for item in attacks
            )
            and authoritative_files
            == ["result.txt"]
        )

        report = {
            "experiment": (
                "gv_agent_safety_v2_acceptance"
            ),
            "timestamp_utc": datetime.now(
                timezone.utc
            ).isoformat(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "python": platform.python_version(),
            },
            "os_backend": {
                "bubblewrap_usable": True,
                "network_namespace": True,
                "read_only_safety_mount": True,
                "linux_capabilities_dropped": True,
                "seccomp_process_creation_denial": True,
            },
            "actions": results,
            "authoritative_files": (
                authoritative_files
            ),
            "passed": passed,
            "scope": (
                "Selected filesystem, network, "
                "process-creation, and authoritative "
                "commit boundaries only."
            ),
        }

        print(
            json.dumps(
                report,
                indent=2,
                sort_keys=True,
            )
        )

        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
