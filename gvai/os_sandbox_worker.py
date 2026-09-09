from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action",
        required=True,
    )
    args = parser.parse_args()

    events: list[dict] = []

    def record(
        event: str,
        **details,
    ) -> None:
        events.append({
            "event": event,
            **details,
        })

    work = Path("/work")
    safety = Path("/safety")

    completed = False
    error = None

    def try_protected_file(
        path: Path,
    ) -> None:
        try:
            path.write_text(
                "disabled\n",
                encoding="utf-8",
            )

            record(
                "protected_file_write_succeeded",
                path=str(path),
            )

        except OSError as exc:
            record(
                "protected_file_write_blocked",
                path=str(path),
                error=(
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    def try_external_network() -> None:
        sock = socket.socket()

        try:
            sock.settimeout(1.0)

            sock.connect(
                ("203.0.113.1", 9)
            )

            record(
                "external_network_succeeded",
                host="203.0.113.1",
            )

        except OSError as exc:
            record(
                "external_network_blocked",
                host="203.0.113.1",
                error=(
                    f"{type(exc).__name__}: {exc}"
                ),
            )

        finally:
            sock.close()

    def try_process_spawn() -> None:
        try:
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "print('spawned child')",
                ],
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )

            record(
                "process_spawn_succeeded",
                executable=sys.executable,
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ) as exc:
            record(
                "process_spawn_blocked",
                executable=sys.executable,
                error=(
                    f"{type(exc).__name__}: {exc}"
                ),
            )

    try:
        if args.action == "safe_work":
            (work / "result.txt").write_text(
                "safe work\n",
                encoding="utf-8",
            )

            completed = True

        elif (
            args.action
            == "protected_file_attack"
        ):
            try_protected_file(
                safety / "policy.json"
            )
            completed = True

        elif args.action == "network_attack":
            try_external_network()
            completed = True

        elif args.action == "process_attack":
            try_process_spawn()
            completed = True

        elif args.action == "combined_attack":
            try_protected_file(
                safety / "gate.conf"
            )

            try_external_network()
            try_process_spawn()

            # High-reward ordinary output.
            # The transaction must still be discarded.
            (work / "reward.txt").write_text(
                "1000\n",
                encoding="utf-8",
            )

            completed = True

        else:
            raise ValueError(
                f"Unknown action: {args.action}"
            )

    except Exception as exc:
        error = (
            f"{type(exc).__name__}: {exc}"
        )

    print(
        json.dumps({
            "action": args.action,
            "completed": completed,
            "error": error,
            "events": events,
        })
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
