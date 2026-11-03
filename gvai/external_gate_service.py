"""systemd entrypoints for the external STOP gate and protected backend.

    python -m gvai.external_gate_service gate    --config /etc/gvai-gate/gate.json
    python -m gvai.external_gate_service backend --config /etc/gvai-backend/backend.json
    python -m gvai.external_gate_service gate-pubkey --config /etc/gvai-gate/gate.json

Listeners come from systemd socket activation (LISTEN_FDNAMES: ``service``,
``control`` for the gate; ``service``, ``notice`` for the backend). The units
that run this are prepared but NOT installed or activated by this repository.
The downstream credential is read only by the backend, from the systemd
credential directory, and is never returned to callers.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
import threading

from gvai import experimental_external_gate as eg


def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise SystemExit("config must be a JSON object")
    return data


def _read_credential(name: str) -> bytes:
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise SystemExit("CREDENTIALS_DIRECTORY not set")
    with open(os.path.join(directory, name), "rb") as fh:
        data = fh.read()
    if len(data) < 16:
        raise SystemExit("credential too short")
    return data


def backend_operations(credential: bytes) -> dict:
    def downstream_sign(args, cancel):
        mac = hmac.new(credential, eg._canon(args), hashlib.sha256).hexdigest()
        return {"mac": mac[:32]}

    return {"downstream_sign": downstream_sign}


def run_gate(config: dict) -> None:
    listeners = eg.systemd_listeners()
    if not {"service", "control"} <= set(listeners):
        raise SystemExit("gate requires systemd 'service' and 'control' sockets")
    gate = eg.gate_from_config(config)
    eg.run_gate(
        gate,
        listeners["service"],
        listeners["control"],
        config.get("backend_notice_socket"),
        float(config.get("heartbeat_interval", 0.5)),
        threading.Event(),
    )


def run_backend(config: dict) -> None:
    listeners = eg.systemd_listeners()
    if not {"service", "notice"} <= set(listeners):
        raise SystemExit("backend requires systemd 'service' and 'notice' sockets")
    core = eg.BackendCore(
        bytes.fromhex(config["gate_public_key"]),
        config["latch_id"],
        backend_operations(_read_credential("downstream")),
        notice_max_age=float(config.get("notice_max_age", eg.DEFAULT_NOTICE_MAX_AGE)),
        interrupt_deadline=float(config.get("interrupt_deadline", eg.DEFAULT_INTERRUPT_DEADLINE)),
        hard_kill=lambda reason: os._exit(70),
    )
    core.start_watchdog()
    eg.serve_many(
        [
            (listeners["service"], lambda m: core.handle(m, eg.SERVICE_BACKEND_REQUESTS)),
            (listeners["notice"], lambda m: core.handle(m, eg.NOTICE_BACKEND_REQUESTS)),
        ],
        threading.Event(),
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="gvai.external_gate_service")
    parser.add_argument("role", choices=("gate", "backend", "gate-pubkey"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    config = _load(args.config)
    if args.role == "gate":
        run_gate(config)
    elif args.role == "backend":
        run_backend(config)
    else:
        print(eg.gate_from_config(config).gate_public_key.hex())
    return 0


if __name__ == "__main__":
    sys.exit(main())
