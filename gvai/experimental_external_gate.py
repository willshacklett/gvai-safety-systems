"""Experimental external STOP gate + protected backend (simulation / host-ready).

Three roles, separated by *process* boundaries:

* Gate (supervisor): owns the STOP latch, the trusted anchor/store files, and
  the gate signing key. Issues short-lived, single-use, operation-bound permit
  tokens only while armed, and pushes signed head notices to the backend.
* Backend: the protected resource. Executes an operation only with a valid
  gate token, cancels in-flight operations when the gate stops or goes silent,
  and supports an independently authenticated STOP-only veto. Startup remains
  recovery-inhibited; there is no production rearm interface.
* Commercial service: holds NO signing keys and NO anchor access. It can only
  ask the gate for permits and present them to the backend.

Process separation inside tests is SIMULATED (same UID). Only a deployment that
runs the roles under distinct OS identities, verified by the host acceptance
probes, provides OS-enforced isolation. See docs/external_stop_gate_v1.md and
docs/stop_gate_host_readiness_v1.md.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import socket
import stat
import threading
import time
from dataclasses import dataclass, field
from multiprocessing.connection import Connection
from typing import Callable, Mapping, Optional

from gvai.experimental_stop_latch import (
    GENESIS_HEAD,
    AnchorHead,
    StopLatch,
    StopLatchKeyring,
)
from gvai import experimental_stop_latch as sl
from gvai.gate_transaction import GateTransaction

SEPARATION_MODEL = "simulated_process_separation_same_uid"
OS_ENFORCED_ISOLATION_IMPLEMENTED = False

_PERMIT_DOMAIN = b"GVAI-GATE-PERMIT-V1\n"
_NOTICE_DOMAIN = b"GVAI-GATE-NOTICE-V1\n"
MAX_MESSAGE_BYTES = 65536
DEFAULT_TOKEN_TTL = 5.0
DEFAULT_NOTICE_MAX_AGE = 3.0
DEFAULT_INTERRUPT_DEADLINE = 1.0

# Request types each listener may carry (least privilege per socket).
SERVICE_GATE_REQUESTS = frozenset({"authorize", "status"})
CONTROL_GATE_REQUESTS = frozenset({"command", "status", "reconcile"})
SERVICE_BACKEND_REQUESTS = frozenset({"execute", "audit"})
NOTICE_BACKEND_REQUESTS = frozenset({"notice"})
STOP_BACKEND_REQUESTS = frozenset({"stop_veto"})


def _canon(obj: Mapping[str, object]) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def args_digest(args: Mapping[str, object]) -> str:
    return hashlib.sha256(_canon(args)).hexdigest()


# ---------------------------------------------------------------- file state


class FileTrustedAnchor:
    """Gate-owned monotonic anchor file. Independence comes only from OS ownership."""

    def __init__(self, path: str) -> None:
        self._path = path

    def _read_locked(self) -> AnchorHead:
        try:
            with open(self._path, "r", encoding="ascii") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return GENESIS_HEAD
        seq, digest = data["sequence"], data["digest"]
        if type(seq) is not int or seq < 0 or type(digest) is not str:
            raise ValueError("anchor_corrupt")
        return AnchorHead(seq, digest)

    def read(self) -> AnchorHead:
        return self._with_lock(self._read_locked)

    def compare_and_advance(self, expected: AnchorHead, new: AnchorHead) -> bool:
        def op() -> bool:
            cur = self._read_locked()
            if cur != expected or new.sequence <= cur.sequence:
                return False
            tmp = self._path + ".tmp"
            with open(tmp, "w", encoding="ascii") as fh:
                json.dump({"sequence": new.sequence, "digest": new.digest}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
            return True

        return self._with_lock(op)

    def _with_lock(self, fn):
        with open(self._path + ".lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                return fn()
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


class FileCommandStore:
    def __init__(self, path: str) -> None:
        self._path = path

    def load(self) -> Optional[Mapping[str, object]]:
        try:
            with open(self._path, "r", encoding="ascii") as fh:
                return json.load(fh)
        except FileNotFoundError:
            return None

    def save(self, envelope: Mapping[str, object]) -> None:
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="ascii") as fh:
            json.dump(dict(envelope), fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path)


# -------------------------------------------------------------- gate signing


def _load_gate_seed(path: str) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError("unsafe_gate_seed")
        seed = os.read(fd, 33)
        named = os.stat(path, follow_symlinks=False)
        if len(seed) != 32 or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("gate_key_corrupt")
        return seed
    finally:
        os.close(fd)


def _public_bytes(priv) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# ----------------------------------------------------------------- gate core


class GateCore:
    """Gate logic (no I/O). Holds the only gate signing key."""

    def __init__(
        self,
        state_dir: str,
        latch_id: str,
        stop_keys: Mapping[str, bytes],
        arm_keys: Mapping[str, bytes],
        allowed_operations: frozenset,
        token_ttl: float = DEFAULT_TOKEN_TTL,
        forbidden_public_keys=(),
        clock: Callable[[], float] = time.time,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        seed = _load_gate_seed(os.path.join(state_dir, "gate_key.seed"))
        self._priv = Ed25519PrivateKey.from_private_bytes(seed)
        self.gate_public_key = _public_bytes(self._priv)
        self.gate_key_id = "gate-" + hashlib.sha256(self.gate_public_key).hexdigest()[:16]
        keyring = StopLatchKeyring(
            stop_keys,
            arm_keys,
            list(forbidden_public_keys) + [self.gate_public_key],
        )
        self.latch_id = latch_id
        self._transaction = GateTransaction(state_dir, latch_id, keyring)
        self._latch = StopLatch(
            latch_id,
            keyring,
            FileTrustedAnchor(os.path.join(state_dir, "anchor.json")),
            FileCommandStore(os.path.join(state_dir, "store.json")),
            transaction=self._transaction,
        )
        self._ops = frozenset(allowed_operations)
        self._ttl = token_ttl
        self._clock = clock
        self._boot_id = secrets.token_hex(8)
        self._counter = 0
        self._lock = threading.Lock()

    def close(self) -> None:
        if self._transaction is not None:
            self._transaction.close()

    def notice(self) -> dict:
        with self._lock:
            self._counter += 1
            counter = self._counter
        decision = self._latch.permit()
        head = self._latch.head
        body = {
            "type": "notice",
            "latch_id": self.latch_id,
            "key_id": self.gate_key_id,
            "boot_id": self._boot_id,
            "counter": counter,
            "status": decision.status,
            "allowed": decision.allowed,
            "sequence": head.sequence,
            "digest": head.digest,
        }
        body["signature"] = self._priv.sign(_NOTICE_DOMAIN + _canon(body)).hex()
        return body

    def handle_command(self, envelope: object) -> dict:
        result = self._latch.apply(envelope)
        return {
            "ok": result.accepted or result.reason == "already_applied",
            "status": result.status,
            "reason": result.reason,
        }

    def reconcile(self, envelope: object) -> dict:
        """Read-only STOP reconciliation. ``ok`` is true only for EXACT_APPLIED;
        ``answered`` says whether the query could be evaluated at all.

        It never asserts that the backend halted: that needs independent evidence.
        """
        r = self._latch.reconcile(envelope)
        return {
            "ok": r.answered and r.verdict == "EXACT_APPLIED",
            "answered": r.answered,
            "verdict": r.verdict,
            "status": r.status,
            "reason": r.reason,
            "head_sequence": r.head_sequence,
            "head_digest": r.head_digest,
            "submitted_digest": r.submitted_digest,
            "stop_recorded": r.verdict == "EXACT_APPLIED",
            "backend_halt": "UNVERIFIED",
        }

    def authorize(self, operation: object, digest: object) -> dict:
        if (
            type(operation) is not str
            or operation not in self._ops
            or type(digest) is not str
            or len(digest) != 64
        ):
            return {"ok": False, "reason": "operation_not_authorized"}
        decision = self._latch.permit()
        if not decision.allowed:
            return {"ok": False, "reason": decision.reason}
        head = self._latch.head
        now = self._clock()
        body = {
            "latch_id": self.latch_id,
            "key_id": self.gate_key_id,
            "operation": operation,
            "args_digest": digest,
            "sequence": head.sequence,
            "digest": head.digest,
            "nonce": secrets.token_hex(16),
            "issued_at": now,
            "expires_at": now + self._ttl,
        }
        body["signature"] = self._priv.sign(_PERMIT_DOMAIN + _canon(body)).hex()
        return {"ok": True, "token": body}

    def handle(self, message: object, allowed: Optional[frozenset] = None) -> dict:
        """Dispatch one request. Never raises; unknown or unpermitted input is denied."""
        try:
            if not isinstance(message, dict):
                return {"ok": False, "reason": "malformed_request"}
            kind = message.get("type")
            if allowed is not None and kind not in allowed:
                return {"ok": False, "reason": "request_not_permitted"}
            if kind == "command":
                out = self.handle_command(message.get("envelope"))
                if out["ok"]:
                    out["notice"] = self.notice()
                return out
            if kind == "reconcile":
                return self.reconcile(message.get("envelope"))
            if kind == "authorize":
                return self.authorize(message.get("operation"), message.get("args_digest"))
            if kind == "status":
                d = self._latch.permit()
                return {"ok": True, "status": d.status, "reason": d.reason}
            return {"ok": False, "reason": "unknown_request"}
        except Exception:
            return {"ok": False, "reason": "internal_error"}


# -------------------------------------------------------------- backend core


@dataclass
class _ActiveOp:
    sequence: int
    cancel: threading.Event = field(default_factory=threading.Event)
    cancelled_at: Optional[float] = None


class BackendCore:
    """Protected resource logic. Holds gate and configured STOP PUBLIC keys only.

    Starts recovery-inhibited, with no production rearm interface. Independently
    configured STOP keys can install a sticky veto without gate or storage I/O.
    Operations are ``fn(args, cancel_event)``. They should poll ``cancel_event``;
    on STOP, gate silence, or epoch change the event is set. An operation that
    ignores it past ``interrupt_deadline`` is abandoned and ``hard_kill`` is
    invoked (the service entrypoint makes that terminate the backend process).
    """

    def __init__(
        self,
        gate_public_key: bytes,
        latch_id: str,
        operations: Mapping[str, Callable[[Mapping[str, object], threading.Event], object]],
        notice_max_age: float = DEFAULT_NOTICE_MAX_AGE,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        interrupt_deadline: float = DEFAULT_INTERRUPT_DEADLINE,
        hard_kill: Optional[Callable[[str], None]] = None,
        *,
        stop_keys: Optional[Mapping[str, bytes]] = None,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        self._pub = Ed25519PublicKey.from_public_bytes(gate_public_key)
        self._stop_keys: dict[str, Ed25519PublicKey] = {}
        seen = {bytes(gate_public_key)}
        for key_id, raw in (stop_keys or {}).items():
            if type(key_id) is not str or not sl._IDENTIFIER.fullmatch(key_id):
                raise sl.StopLatchConfigError("invalid_key_id")
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
                raise sl.StopLatchConfigError("invalid_public_key")
            raw = bytes(raw)
            if raw in seen:
                raise sl.StopLatchConfigError("public_key_reused_from_other_purpose")
            seen.add(raw)
            self._stop_keys[key_id] = Ed25519PublicKey.from_public_bytes(raw)
        self._key_id = "gate-" + hashlib.sha256(gate_public_key).hexdigest()[:16]
        self._latch_id = latch_id
        self._ops = dict(operations)
        self._max_age = notice_max_age
        self._clock = clock
        self._mono = monotonic
        self._deadline = interrupt_deadline
        self._hard_kill = hard_kill or (lambda reason: None)
        self.hard_kills: list = []
        self._lock = threading.Lock()
        self._seq = -1
        self._allowed = False
        self._stop_veto = False
        self._recovery_inhibited = True
        self._notice_at: Optional[float] = None
        self._boot_id: Optional[str] = None
        self._counter = -1
        self._old_boots: set = set()
        self._nonces: dict = {}
        self._active: list = []
        # Permits minted before this backend started are refused: the nonce
        # memory is volatile, so a restart must not reopen used permits.
        self._started_at = clock()
        self._watchdog_stop = threading.Event()
        self.executed: list = []

    def submit_stop_veto(self, envelope: object) -> dict:
        """Authenticate denial only; never consult the gate or persistence."""
        try:
            command = sl.parse_command(envelope)
        except ValueError as exc:
            return {"ok": False, "reason": str(exc)}
        if command.latch_id != self._latch_id:
            return {"ok": False, "reason": "wrong_latch"}
        if command.command_type != sl.COMMAND_STOP:
            return {"ok": False, "reason": "not_a_stop_command"}
        key = self._stop_keys.get(command.key_id)
        if key is None:
            return {"ok": False, "reason": "authentication_failed"}
        from cryptography.exceptions import InvalidSignature

        try:
            key.verify(command.signature, command.signing_bytes())
        except InvalidSignature:
            return {"ok": False, "reason": "authentication_failed"}
        with self._lock:
            self._stop_veto = True
            self._allowed = False
            self._cancel_active_locked()
        return {
            "ok": True, "outcome": "VETO_DENIAL_CONFIRMED",
            "execution_denied": True, "durable_stop_recording": "UNKNOWN",
            "backend_termination": "UNVERIFIED",
        }

    def _verify(self, domain: bytes, body: Mapping[str, object]) -> bool:
        sig = body.get("signature")
        if type(sig) is not str or len(sig) != 128:
            return False
        try:
            raw = bytes.fromhex(sig)
            unsigned = {k: v for k, v in body.items() if k != "signature"}
            self._pub.verify(raw, domain + _canon(unsigned))
        except Exception:
            return False
        return body.get("key_id") == self._key_id and body.get("latch_id") == self._latch_id

    def _cancel_active_locked(self, keep_sequence: Optional[int] = None) -> None:
        now = self._mono()
        for op in self._active:
            if keep_sequence is not None and op.sequence == keep_sequence:
                continue
            if not op.cancel.is_set():
                op.cancelled_at = now
                op.cancel.set()

    def start_watchdog(self, interval: float = 0.05) -> None:
        """Cancel in-flight work if gate notices stop arriving."""

        def loop() -> None:
            while not self._watchdog_stop.wait(interval):
                with self._lock:
                    stale = (
                        self._notice_at is None
                        or self._mono() - self._notice_at > self._max_age
                    )
                    if stale:
                        self._cancel_active_locked()

        threading.Thread(target=loop, daemon=True).start()

    def stop_watchdog(self) -> None:
        self._watchdog_stop.set()

    def apply_notice(self, notice: object) -> dict:
        try:
            if not isinstance(notice, dict) or not self._verify(_NOTICE_DOMAIN, notice):
                return {"ok": False, "reason": "notice_authentication_failed"}
            seq, ctr, boot = notice["sequence"], notice["counter"], notice["boot_id"]
            if (
                type(seq) is not int
                or type(ctr) is not int
                or type(boot) is not str
                or type(notice["allowed"]) is not bool
            ):
                return {"ok": False, "reason": "notice_malformed"}
            with self._lock:
                if boot in self._old_boots:
                    return {"ok": False, "reason": "notice_replayed"}
                if boot == self._boot_id:
                    if ctr <= self._counter:
                        return {"ok": False, "reason": "notice_replayed"}
                elif self._boot_id is not None:
                    self._old_boots.add(self._boot_id)
                if seq < self._seq:
                    return {"ok": False, "reason": "notice_rollback"}
                self._boot_id, self._counter = boot, ctr
                self._seq = seq
                self._allowed = (
                    not self._stop_veto and not self._recovery_inhibited
                    and notice["allowed"] and notice["status"] == "armed"
                )
                self._notice_at = self._mono()
                if self._allowed:
                    self._cancel_active_locked(keep_sequence=seq)
                else:
                    self._cancel_active_locked()
            return {"ok": True}
        except Exception:
            return {"ok": False, "reason": "internal_error"}

    def execute(self, operation: object, args: object, token: object) -> dict:
        """Deny unless a fresh, valid, unused gate token matches this call."""
        try:
            if (
                not isinstance(token, dict)
                or not isinstance(args, dict)
                or type(operation) is not str
            ):
                return {"ok": False, "reason": "malformed_request"}
            if operation not in self._ops:
                return {"ok": False, "reason": "unknown_operation"}
            if not self._verify(_PERMIT_DOMAIN, token):
                return {"ok": False, "reason": "token_authentication_failed"}
            if token.get("operation") != operation or token.get("args_digest") != args_digest(args):
                return {"ok": False, "reason": "token_mismatch"}
            seq, exp, nonce = token.get("sequence"), token.get("expires_at"), token.get("nonce")
            issued = token.get("issued_at")
            if (
                type(seq) is not int
                or type(nonce) is not str
                or type(exp) not in (int, float)
                or type(issued) not in (int, float)
            ):
                return {"ok": False, "reason": "token_malformed"}
            with self._lock:
                if self._stop_veto:
                    return {"ok": False, "reason": "stop_veto"}
                if self._recovery_inhibited:
                    return {"ok": False, "reason": "recovery_inhibited"}
                now = self._clock()
                if self._notice_at is None:
                    return {"ok": False, "reason": "no_gate_notice"}
                if self._mono() - self._notice_at > self._max_age:
                    return {"ok": False, "reason": "gate_notice_stale"}
                if not self._allowed:
                    return {"ok": False, "reason": "gate_not_armed"}
                if seq != self._seq:
                    return {"ok": False, "reason": "token_epoch_mismatch"}
                if issued < self._started_at:
                    return {"ok": False, "reason": "token_predates_backend_start"}
                if exp < now:
                    return {"ok": False, "reason": "token_expired"}
                self._nonces = {n: e for n, e in self._nonces.items() if e >= now}
                if nonce in self._nonces:
                    return {"ok": False, "reason": "token_replayed"}
                self._nonces[nonce] = exp
                active = _ActiveOp(sequence=seq)
                self._active.append(active)
            return self._run(operation, args, active)
        except Exception:
            return {"ok": False, "reason": "internal_error"}

    def _run(self, operation: str, args: dict, active: _ActiveOp) -> dict:
        box: dict = {}
        done = threading.Event()

        def work() -> None:
            try:
                if not active.cancel.is_set():
                    box["result"] = self._ops[operation](dict(args), active.cancel)
            except Exception:
                box["error"] = True
            finally:
                done.set()

        threading.Thread(target=work, daemon=True).start()
        try:
            while not done.wait(0.005):
                with self._lock:
                    started = active.cancelled_at
                if started is not None and self._mono() - started > self._deadline:
                    self.hard_kills.append(operation)
                    self._hard_kill("uncooperative_operation")
                    return {"ok": False, "reason": "interrupted_uncooperative"}
            with self._lock:
                if active.cancel.is_set() or self._stop_veto or self._recovery_inhibited:
                    return {"ok": False, "reason": "interrupted_by_stop"}
                if "error" in box:
                    return {"ok": False, "reason": "operation_failed"}
                self.executed.append((operation, dict(args)))
            return {"ok": True, "result": box["result"]}
        finally:
            with self._lock:
                if active in self._active:
                    self._active.remove(active)

    def handle(self, message: object, allowed: Optional[frozenset] = None) -> dict:
        if not isinstance(message, dict):
            return {"ok": False, "reason": "malformed_request"}
        kind = message.get("type")
        if allowed is not None and kind not in allowed:
            return {"ok": False, "reason": "request_not_permitted"}
        if kind == "notice":
            return self.apply_notice(message)
        if kind == "stop_veto":
            return self.submit_stop_veto(message.get("envelope"))
        if kind == "execute":
            return self.execute(message.get("operation"), message.get("args"), message.get("token"))
        if kind == "audit":
            with self._lock:
                return {"ok": True, "executed": [[o, a] for o, a in self.executed]}
        return {"ok": False, "reason": "unknown_request"}


# ------------------------------------------------------- process / transport


class FdListener:
    """Accept loop over an inherited (systemd socket-activation) listening fd."""

    def __init__(self, fd: int) -> None:
        self._sock = socket.socket(fileno=fd)

    def accept(self) -> Connection:
        peer, _ = self._sock.accept()
        return Connection(peer.detach())


def systemd_listeners() -> dict:
    """Named listening fds passed by systemd (LISTEN_FDS/LISTEN_FDNAMES)."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()):
        return {}
    count = int(os.environ.get("LISTEN_FDS", "0"))
    names = os.environ.get("LISTEN_FDNAMES", "").split(":")
    out = {}
    for i in range(count):
        name = names[i] if i < len(names) and names[i] else f"fd{i}"
        out[name] = FdListener(3 + i)
    for var in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(var, None)
    return out


def path_listener(path: str):
    from multiprocessing.connection import Listener

    listener = Listener(path, family="AF_UNIX")
    os.chmod(path, 0o600)
    return listener


def _serve(listener, handler, stop_event) -> None:
    def conn_loop(conn):
        try:
            while not stop_event.is_set():
                if not conn.poll(0.2):
                    continue
                raw = conn.recv_bytes(MAX_MESSAGE_BYTES)
                try:
                    reply = handler(json.loads(raw.decode("utf-8")))
                except Exception:
                    reply = {"ok": False, "reason": "malformed_request"}
                conn.send_bytes(json.dumps(reply).encode("utf-8"))
        except (EOFError, OSError):
            pass
        finally:
            conn.close()

    while not stop_event.is_set():
        try:
            conn = listener.accept()
        except Exception:
            break
        threading.Thread(target=conn_loop, args=(conn,), daemon=True).start()


def serve_many(listeners_and_handlers, stop_event) -> None:
    """Serve several listeners; return when the stop event is set."""
    for listener, handler in listeners_and_handlers:
        threading.Thread(
            target=_serve, args=(listener, handler, stop_event), daemon=True
        ).start()
    stop_event.wait()


def make_control_handler(gate: GateCore, push: Callable[..., bool]):
    """Control-socket handler. ``backend_notice`` reports only the backend's reply to the
    notice; it is not evidence that execution halted."""

    def control_handler(message):
        reply = gate.handle(message, CONTROL_GATE_REQUESTS)
        if reply.get("ok") and "notice" in reply:
            acked = push(reply["notice"])
            reply["backend_notice"] = "acknowledged" if acked is True else "unconfirmed"
        return reply

    return control_handler


def run_gate(gate: GateCore, service_listener, control_listener, backend_notice_path,
             heartbeat_interval: float, stop: threading.Event) -> None:
    def push(notice=None) -> bool:
        if not backend_notice_path:
            return False
        try:
            conn = BackendClient(backend_notice_path, timeout=1.0)
            reply = conn.send_notice(notice or gate.notice())
            conn.close()
            return reply.get("ok") is True
        except Exception:
            return False

    def heartbeat():
        while not stop.is_set():
            push()
            stop.wait(heartbeat_interval)

    threading.Thread(target=heartbeat, daemon=True).start()

    def service_handler(message):
        return gate.handle(message, SERVICE_GATE_REQUESTS)

    control_handler = make_control_handler(gate, push)

    serve_many([(service_listener, service_handler), (control_listener, control_handler)], stop)


def gate_from_config(config: Mapping[str, object]) -> GateCore:
    return GateCore(
        config["state_dir"],
        config["latch_id"],
        {k: bytes.fromhex(v) for k, v in config["stop_keys"].items()},
        {k: bytes.fromhex(v) for k, v in config["arm_keys"].items()},
        frozenset(config["operations"]),
        token_ttl=config.get("token_ttl", DEFAULT_TOKEN_TTL),
        forbidden_public_keys=[bytes.fromhex(v) for v in config.get("forbidden", [])],
    )


def gate_process_main(config: dict, ready_conn) -> None:
    gate = gate_from_config(config)
    service = path_listener(config["socket"])
    control = path_listener(config["control_socket"])
    ready_conn.send_bytes(json.dumps({"gate_public_key": gate.gate_public_key.hex()}).encode())
    run_gate(gate, service, control, config.get("backend_notice_socket"),
             config.get("heartbeat_interval", 0.2), threading.Event())


def simulation_operations() -> dict:
    """Test-only operations; the cooperative and stubborn ones model long work."""

    def slow(args, cancel):
        end = time.monotonic() + float(args.get("seconds", 5))
        while time.monotonic() < end:
            if cancel.wait(0.005):
                return {"cancelled": True}
        return {"done": True}

    def stubborn(args, cancel):
        time.sleep(float(args.get("seconds", 3)))
        return {"done": True}

    return {
        "echo": lambda a, c: dict(a),
        "charge": lambda a, c: {"charged": a.get("amount", 0)},
        "slow": slow,
        "stubborn": stubborn,
    }


def backend_process_main(config: dict, ready_conn) -> None:
    core = BackendCore(
        bytes.fromhex(config["gate_public_key"]),
        config["latch_id"],
        simulation_operations(),
        notice_max_age=config.get("notice_max_age", DEFAULT_NOTICE_MAX_AGE),
        interrupt_deadline=config.get("interrupt_deadline", DEFAULT_INTERRUPT_DEADLINE),
        hard_kill=lambda reason: os._exit(70),
        stop_keys={k: bytes.fromhex(v) for k, v in config.get("stop_keys", {}).items()},
    )
    core.start_watchdog()
    service = path_listener(config["socket"])
    notice = path_listener(config["notice_socket"])
    listeners = [
        (service, lambda m: core.handle(m, SERVICE_BACKEND_REQUESTS)),
        (notice, lambda m: core.handle(m, NOTICE_BACKEND_REQUESTS)),
    ]
    if config.get("stop_socket"):
        listeners.append((
            path_listener(config["stop_socket"]),
            lambda m: core.handle(m, STOP_BACKEND_REQUESTS),
        ))
    ready_conn.send_bytes(b"{}")
    serve_many(listeners, threading.Event())


class _Client:
    """Lazy, reconnecting client. Every failure mode is a DENY, never an exception."""

    def __init__(self, path: str, timeout: float = 2.0) -> None:
        self._path = path
        self._timeout = timeout
        self._conn = None

    def _connect(self):
        from multiprocessing.connection import Client

        if self._conn is None:
            self._conn = Client(self._path, family="AF_UNIX")
        return self._conn

    def request(self, message: Mapping[str, object]) -> dict:
        try:
            conn = self._connect()
            conn.send_bytes(json.dumps(message).encode("utf-8"))
            if not conn.poll(self._timeout):
                self.close()  # a late reply would desynchronise the stream
                return {"ok": False, "reason": "communication_failure"}
            reply = json.loads(conn.recv_bytes(MAX_MESSAGE_BYTES).decode("utf-8"))
            return reply if isinstance(reply, dict) else {"ok": False, "reason": "bad_reply"}
        except Exception:
            self.close()
            return {"ok": False, "reason": "communication_failure"}

    def close(self) -> None:
        conn, self._conn = self._conn, None
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


class GateClient(_Client):
    def authorize(self, operation: str, args: Mapping[str, object]) -> dict:
        return self.request(
            {"type": "authorize", "operation": operation, "args_digest": args_digest(args)}
        )

    def submit_command(self, envelope: Mapping[str, object]) -> dict:
        return self.request({"type": "command", "envelope": dict(envelope)})

    def status(self) -> dict:
        return self.request({"type": "status"})

    def reconcile_stop(self, envelope: Mapping[str, object]) -> dict:
        """Authenticated read-only query. A transport failure yields UNKNOWN."""
        reply = self.request({"type": "reconcile", "envelope": dict(envelope)})
        if "verdict" in reply:
            return reply
        verdict = "UNKNOWN" if reply.get("reason") == "communication_failure" else "REJECTED"
        return {"ok": False, "verdict": verdict, "reason": reply.get("reason", "denied"),
                "stop_recorded": False, "backend_halt": "UNVERIFIED"}

    def submit_stop(self, envelope: Mapping[str, object]) -> dict:
        """Submit a signed STOP and classify the reply.

        ``outcome`` is UNKNOWN on any transport failure, never an acknowledgement.
        ``durable`` means the gate's anchor and store hold exactly this command.
        ``backend_halt`` is always UNVERIFIED here: halting needs independent evidence.
        """
        if not isinstance(envelope, Mapping) or envelope.get("command_type") != "stop":
            return {"outcome": "REJECTED", "durable": False, "reason": "not_a_stop_command",
                    "backend_notice": "unknown", "backend_halt": "UNVERIFIED"}
        r = self.submit_command(envelope)
        reason = r.get("reason")
        out = {"outcome": "REJECTED", "durable": False, "reason": reason,
               "backend_notice": r.get("backend_notice", "unknown"),
               "backend_halt": "UNVERIFIED"}
        if reason == "communication_failure":
            out.update(outcome="UNKNOWN", backend_notice="unknown")
        elif r.get("ok") is True and reason == "accepted":
            out.update(outcome="STOP_RECORDED", durable=True)
        elif r.get("ok") is True and reason == "already_applied":
            out.update(outcome="ALREADY_APPLIED", durable=True)
        elif reason in ("anchor_advance_failed", "store_write_failed", "persistence_unknown"):
            out.update(outcome="UNKNOWN")
        return out


class BackendClient(_Client):
    def execute(self, operation: str, args: Mapping[str, object], token) -> dict:
        return self.request(
            {"type": "execute", "operation": operation, "args": dict(args), "token": token}
        )

    def send_notice(self, notice: Mapping[str, object]) -> dict:
        return self.request(notice)

    def audit(self) -> dict:
        return self.request({"type": "audit"})


class BackendStopClient(_Client):
    """Local STOP-only ingress; lost replies never imply non-application."""

    def submit_stop_veto(self, envelope: Mapping[str, object]) -> dict:
        reply = self.request({"type": "stop_veto", "envelope": dict(envelope)})
        confirmed = {
            "ok": True, "outcome": "VETO_DENIAL_CONFIRMED",
            "execution_denied": True, "durable_stop_recording": "UNKNOWN",
            "backend_termination": "UNVERIFIED",
        }
        if reply == confirmed and reply.get("ok") is True and reply.get("execution_denied") is True:
            return reply
        reason = reply.get("reason")
        if reply.get("ok") is False and type(reason) is str and reason in {
            "malformed_envelope", "unsupported_version", "invalid_sequence",
            "invalid_identifier", "invalid_signature_encoding",
            "unknown_command_type", "wrong_latch", "not_a_stop_command",
            "authentication_failed", "request_not_permitted",
        }:
            return {
                "ok": False, "outcome": "REJECTED", "reason": reason,
                "execution_denied": "UNKNOWN", "durable_stop_recording": "UNKNOWN",
                "backend_termination": "UNVERIFIED",
            }
        return {
            "ok": False, "outcome": "UNKNOWN", "execution_denied": "UNKNOWN",
            "durable_stop_recording": "UNKNOWN", "backend_termination": "UNVERIFIED",
        }


class GatedService:
    """What the commercial service uses. It holds no keys and no anchor access.

    A service that skips this class gains nothing: the backend independently
    denies any operation lacking a valid gate token.
    """

    def __init__(self, gate: GateClient, backend: BackendClient, timeout: float = 15.0) -> None:
        self._gate, self._backend = gate, backend
        self._backend._timeout = timeout

    def call(self, operation: str, args: Mapping[str, object]) -> dict:
        permit = self._gate.authorize(operation, args)
        if not permit.get("ok"):
            return {"ok": False, "reason": permit.get("reason", "denied")}
        return self._backend.execute(operation, args, permit["token"])
