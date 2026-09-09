from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet

from gvai.effects import ActionSpec
from gvai.runtime_guard_v2 import GVRuntimeGuardV2


@dataclass(frozen=True)
class SubprocessTransaction:
    action: str
    returncode: int
    completed: bool
    error: str | None
    observed_effects: FrozenSet[str]
    audit_events: tuple[dict, ...]
    committed: bool
    allowed: bool
    halted: bool
    reason: str


class GVSubprocessExecutor:
    def __init__(
        self,
        guard: GVRuntimeGuardV2,
        commit_root: Path,
    ) -> None:
        self.guard = guard
        self.commit_root = Path(
            commit_root
        ).resolve()

        self.commit_root.mkdir(
            parents=True,
            exist_ok=True,
        )

    @staticmethod
    def effects_from_events(
        events: list[dict],
        workspace_changed: bool,
    ) -> frozenset[str]:
        effects: set[str] = set()

        mapping = {
            "protected_file_write":
                "protected_file_modified",

            "unapproved_network_egress":
                "unapproved_network_egress",

            "unauthorized_process_spawn":
                "unauthorized_process_spawn",
        }

        for event in events:
            mapped = mapping.get(
                event.get("event")
            )

            if mapped:
                effects.add(mapped)

        protected = {
            "protected_file_modified",
            "unapproved_network_egress",
            "unauthorized_process_spawn",
        }

        if (
            workspace_changed
            and not effects.intersection(protected)
        ):
            effects.add(
                "normal_operation"
            )

        return frozenset(effects)

    def execute(
        self,
        action: str,
        observation,
    ) -> SubprocessTransaction:
        with tempfile.TemporaryDirectory(
            prefix="gv-subprocess-"
        ) as tmp:
            root = Path(tmp)

            workspace = root / "workspace"
            safety = root / "safety"
            audit_log = root / "audit.jsonl"

            workspace.mkdir()
            safety.mkdir()

            # Seed disposable protected files.
            (safety / "policy.json").write_text(
                '{"gate": true}\n',
                encoding="utf-8",
            )

            (safety / "gate.conf").write_text(
                "enabled\n",
                encoding="utf-8",
            )

            worker = (
                Path(__file__).resolve().parent
                / "subprocess_worker.py"
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(worker),
                    "--action",
                    action,
                    "--root",
                    str(root),
                    "--audit-log",
                    str(audit_log),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            events: list[dict] = []

            if audit_log.exists():
                for line in audit_log.read_text(
                    encoding="utf-8"
                ).splitlines():
                    if line.strip():
                        events.append(
                            json.loads(line)
                        )

            result = {}

            stdout_lines = [
                line
                for line in proc.stdout.splitlines()
                if line.strip()
            ]

            if stdout_lines:
                result = json.loads(
                    stdout_lines[-1]
                )

            workspace_changed = any(
                workspace.rglob("*")
            )

            observed_effects = (
                self.effects_from_events(
                    events,
                    workspace_changed=workspace_changed,
                )
            )

            runtime = self.guard.evaluate_action(
                ActionSpec(
                    name=action,
                    effects=observed_effects,
                ),
                observation,
            )

            committed = False

            if runtime.allowed:
                for source in workspace.rglob("*"):
                    if not source.is_file():
                        continue

                    relative = source.relative_to(
                        workspace
                    )

                    target = (
                        self.commit_root
                        / relative
                    )

                    target.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    shutil.copy2(
                        source,
                        target,
                    )

                committed = True

            return SubprocessTransaction(
                action=action,
                returncode=proc.returncode,
                completed=bool(
                    result.get(
                        "completed",
                        False,
                    )
                ),
                error=result.get("error"),
                observed_effects=observed_effects,
                audit_events=tuple(events),
                committed=committed,
                allowed=runtime.allowed,
                halted=runtime.halted,
                reason=runtime.reason,
            )
