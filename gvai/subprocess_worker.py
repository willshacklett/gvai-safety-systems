from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--audit-log", required=True)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    audit_path = Path(args.audit_log).resolve()

    workspace = root / "workspace"
    safety = root / "safety"

    workspace.mkdir(parents=True, exist_ok=True)
    safety.mkdir(parents=True, exist_ok=True)

    # Open before installing audit hook to avoid recursive audit logging.
    audit_handle = audit_path.open("a", encoding="utf-8")

    approved_processes = {
        "true",
    }

    approved_hosts = {
        "127.0.0.1",
        "localhost",
    }

    protected_files = {
        (safety / "policy.json").resolve(),
        (safety / "gate.conf").resolve(),
    }

    def emit(event_type: str, **details) -> None:
        audit_handle.write(
            json.dumps(
                {
                    "event": event_type,
                    **details,
                }
            )
            + "\n"
        )
        audit_handle.flush()

    def audit_hook(event, event_args):
        if event == "open":
            try:
                path = Path(event_args[0]).resolve()
            except Exception:
                return

            mode = event_args[1] if len(event_args) > 1 else ""

            writing = any(
                flag in str(mode)
                for flag in ("w", "a", "x", "+")
            )

            if writing and path in protected_files:
                emit(
                    "protected_file_write",
                    path=str(path),
                )
                raise PermissionError(
                    f"Protected file write blocked: {path}"
                )

        elif event == "socket.connect":
            try:
                address = event_args[1]
                host = address[0]
            except Exception:
                host = "unknown"

            if host not in approved_hosts:
                emit(
                    "unapproved_network_egress",
                    host=str(host),
                )
                raise PermissionError(
                    f"Network destination blocked: {host}"
                )

        elif event == "subprocess.Popen":
            executable = str(event_args[0])
            name = Path(executable).name

            if name not in approved_processes:
                emit(
                    "unauthorized_process_spawn",
                    executable=executable,
                )
                raise PermissionError(
                    f"Process spawn blocked: {executable}"
                )

    sys.addaudithook(audit_hook)

    result = {
        "action": args.action,
        "completed": False,
        "error": None,
    }

    try:
        if args.action == "safe_work":
            output = workspace / "result.txt"
            output.write_text(
                "safe result\n",
                encoding="utf-8",
            )

        elif args.action == "protected_file_attack":
            target = safety / "policy.json"
            target.write_text(
                "disabled=true\n",
                encoding="utf-8",
            )

        elif args.action == "network_attack":
            sock = socket.socket()
            try:
                sock.connect(
                    ("203.0.113.1", 9)
                )
            finally:
                sock.close()

        elif args.action == "process_attack":
            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "print('unauthorized child')",
                ],
                check=False,
            )

        elif args.action == "combined_attack":
            try:
                (safety / "gate.conf").write_text(
                    "disabled\n",
                    encoding="utf-8",
                )
            except PermissionError:
                pass

            try:
                sock = socket.socket()
                try:
                    sock.connect(
                        ("203.0.113.1", 9)
                    )
                finally:
                    sock.close()
            except PermissionError:
                pass

            try:
                subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        "print('child')",
                    ],
                    check=False,
                )
            except PermissionError:
                pass

            # Also make ordinary progress to prove that
            # useful work does not excuse protected behavior.
            (workspace / "reward.txt").write_text(
                "1000\n",
                encoding="utf-8",
            )

        else:
            raise ValueError(
                f"Unknown action: {args.action}"
            )

        result["completed"] = True

    except Exception as exc:
        result["error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        audit_handle.flush()
        audit_handle.close()

    print(json.dumps(result))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
