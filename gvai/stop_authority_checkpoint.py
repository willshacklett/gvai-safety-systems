"""Disconnected authenticated checkpoint protocol; server storage is simulated."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gvai import stop_generation_authority as sa
from gvai.experimental_stop_latch import StopLatchKeyring
from gvai.stop_authority_filesystem import decode_snapshot, encode_snapshot

REQUEST_DOMAIN = b"GVAI-STOP-CHECKPOINT-REQUEST-V1\n"
RESPONSE_DOMAIN = b"GVAI-STOP-CHECKPOINT-RESPONSE-V1\n"
MAX_WIRE_BYTES = 1024 * 1024
MAX_REQUESTS = 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SIG = re.compile(r"[0-9a-f]{128}\Z")
_VERDICTS = {"VERIFIED", "CONFLICT", "UNAVAILABLE", "UNKNOWN"}


def _canonical(body: object) -> bytes:
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def _decode(raw: object) -> dict:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_WIRE_BYTES:
        raise ValueError("invalid_checkpoint_message_size")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_checkpoint_field")
            result[key] = value
        return result

    def reject(value):
        raise ValueError("invalid_checkpoint_constant")

    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("malformed_checkpoint_message") from exc
    if type(body) is not dict or raw != _canonical(body):
        raise ValueError("noncanonical_checkpoint_message")
    return body


def _identity(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


@dataclass(frozen=True)
class Checkpoint:
    authority_id: str
    latch_id: str
    checkpoint_id: str
    trust_domain: str
    stop_epoch: int
    revision: int
    head_digest: str
    writer_id: str | None
    writer_fence: int

    def __post_init__(self):
        if not all(_identity(value) for value in (
            self.authority_id, self.latch_id, self.checkpoint_id, self.trust_domain,
        )):
            raise ValueError("invalid_checkpoint_identity")
        if not all(type(value) is int and 0 <= value <= sa.MAX_INTEGER for value in (
            self.stop_epoch, self.revision, self.writer_fence,
        )):
            raise ValueError("invalid_checkpoint_counter")
        if type(self.head_digest) is not str or _HASH.fullmatch(self.head_digest) is None:
            raise ValueError("invalid_checkpoint_digest")
        if self.revision == 0:
            if (self.stop_epoch, self.writer_fence, self.writer_id, self.head_digest) != (
                0, 0, None, sa.GENESIS_DIGEST,
            ):
                raise ValueError("invalid_checkpoint_genesis")
        elif not _identity(self.writer_id) or not 1 <= self.writer_fence <= self.revision:
            raise ValueError("invalid_checkpoint_writer")
        if self.stop_epoch > self.revision:
            raise ValueError("invalid_checkpoint_epoch")


def checkpoint_for(
    snapshot: sa.AuthoritySnapshot, checkpoint_id: str, trust_domain: str,
) -> Checkpoint:
    return Checkpoint(
        snapshot.authority_id, snapshot.latch_id, checkpoint_id, trust_domain,
        snapshot.stop_epoch, snapshot.revision, snapshot.head_digest,
        snapshot.writer_id, snapshot.writer_fence,
    )


def _parse_checkpoint(value: object) -> Checkpoint:
    if type(value) is not dict or set(value) != set(Checkpoint.__dataclass_fields__):
        raise ValueError("invalid_checkpoint_fields")
    return Checkpoint(**value)


@dataclass(frozen=True)
class CheckpointOutcome:
    verdict: str
    reason: str
    checkpoint: Checkpoint | None = None


class CheckpointTransport(Protocol):
    """Future authenticated endpoint; no networking implemented here."""

    def exchange(self, request: bytes) -> bytes: ...


def _signed(body: dict, domain: bytes, signer: Callable[[bytes], bytes]) -> bytes:
    signature = signer(domain + _canonical(body))
    if type(signature) is not bytes or len(signature) != 64:
        raise ValueError("invalid_checkpoint_signer")
    raw = _canonical(dict(body, signature=signature.hex()))
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError("checkpoint_message_oversized")
    return raw


def _verify(body: dict, domain: bytes, key: Ed25519PublicKey) -> dict:
    signature = body.get("signature")
    if type(signature) is not str or _SIG.fullmatch(signature) is None:
        raise ValueError("invalid_checkpoint_signature")
    unsigned = {name: value for name, value in body.items() if name != "signature"}
    key.verify(bytes.fromhex(signature), domain + _canonical(unsigned))
    return unsigned


class CheckpointClient:
    """Supervisor-owned signer/transport, never selected by a workload request."""

    def __init__(
        self, *, authority_id: str, latch_id: str, checkpoint_id: str,
        trust_domain: str, client_id: str, writer_id: str, server_id: str,
        server_public_key: bytes, signer: Callable[[bytes], bytes],
        transport: CheckpointTransport, stop_keys: StopLatchKeyring,
    ):
        if not all(_identity(value) for value in (
            authority_id, latch_id, checkpoint_id, trust_domain,
            client_id, writer_id, server_id,
        )):
            raise ValueError("invalid_checkpoint_configuration")
        self._scope = dict(
            authority_id=authority_id, latch_id=latch_id,
            checkpoint_id=checkpoint_id, trust_domain=trust_domain,
        )
        self._client_id, self._writer_id, self._server_id = client_id, writer_id, server_id
        self._server_key = Ed25519PublicKey.from_public_bytes(server_public_key)
        self._signer, self._transport, self._stop_keys = signer, transport, stop_keys

    def verify(self, snapshot: sa.AuthoritySnapshot) -> CheckpointOutcome:
        return self._request("verify", snapshot, None)

    def advance(
        self, snapshot: sa.AuthoritySnapshot, *, expected: Checkpoint,
    ) -> CheckpointOutcome:
        return self._request("advance", snapshot, expected)

    def _request(self, action, snapshot, expected):
        sa.validate_authority_snapshot(
            snapshot, self._scope["authority_id"], self._scope["latch_id"], self._stop_keys,
        )
        target = checkpoint_for(snapshot, self._scope["checkpoint_id"], self._scope["trust_domain"])
        if expected is not None:
            if type(expected) is not Checkpoint:
                raise ValueError("invalid_expected_checkpoint")
            if any(getattr(expected, name) != value for name, value in self._scope.items()):
                raise ValueError("expected_checkpoint_scope_mismatch")
        body = dict(
            self._scope, version=1, action=action, client_id=self._client_id,
            writer_id=self._writer_id, writer_fence=snapshot.writer_fence,
            nonce=secrets.token_hex(32),
            expected=asdict(expected) if expected is not None else None,
            snapshot=json.loads(encode_snapshot(snapshot)),
        )
        request = _signed(body, REQUEST_DOMAIN, self._signer)
        request_digest = hashlib.sha256(request).hexdigest()
        try:
            raw = self._transport.exchange(request)
        except TimeoutError:
            return CheckpointOutcome("UNKNOWN", "checkpoint_reply_lost")
        except OSError:
            return CheckpointOutcome("UNAVAILABLE", "checkpoint_transport_unavailable")
        except Exception:
            return CheckpointOutcome("UNKNOWN", "checkpoint_exchange_unverifiable")
        try:
            response = _verify(_decode(raw), RESPONSE_DOMAIN, self._server_key)
            if set(response) != {
                *self._scope, "version", "server_id", "request_digest", "nonce",
                "verdict", "reason", "checkpoint",
            }:
                raise ValueError("invalid_response_fields")
            if (
                type(response["version"]) is not int or response["version"] != 1
                or response["server_id"] != self._server_id
                or response["request_digest"] != request_digest
                or response["nonce"] != body["nonce"]
                or any(response[name] != value for name, value in self._scope.items())
                or response["verdict"] not in _VERDICTS
                or not _identity(response["reason"])
            ):
                raise ValueError("checkpoint_response_binding_failed")
            head = _parse_checkpoint(response["checkpoint"]) if response["checkpoint"] is not None else None
            if head is not None and any(getattr(head, name) != value for name, value in self._scope.items()):
                raise ValueError("checkpoint_head_scope_mismatch")
            if response["verdict"] == "VERIFIED" and head != target:
                raise ValueError("checkpoint_verified_head_mismatch")
            return CheckpointOutcome(response["verdict"], response["reason"], head)
        except (ValueError, TypeError, InvalidSignature):
            return CheckpointOutcome("UNKNOWN", "checkpoint_response_unverifiable")


class SimulatedCheckpointServer:
    """Volatile fake remote authority; no independent deployment or durability.

    Genesis provisioning and writer-key policy are trusted administrative acts.
    Pinned writer credentials may perform validated C1 fence rotations.
    Nonce history is bounded; exhaustion denies, never silently evicts.
    """

    def __init__(
        self, *, initial: Checkpoint, server_id: str,
        clients: Mapping[str, tuple[str, bytes]], signer: Callable[[bytes], bytes],
        stop_keys: StopLatchKeyring,
    ):
        if type(initial) is not Checkpoint or initial.revision != 0 or not _identity(server_id):
            raise ValueError("explicit_genesis_required")
        self._scope = {name: getattr(initial, name) for name in (
            "authority_id", "latch_id", "checkpoint_id", "trust_domain",
        )}
        self._head: Checkpoint | None = initial
        self._server_id, self._signer, self._keys = server_id, signer, stop_keys
        self._clients = {}
        seen_keys: set[bytes] = set()
        for client_id, (writer_id, key) in clients.items():
            if not _identity(client_id) or not _identity(writer_id):
                raise ValueError("invalid_client_binding")
            if type(key) is not bytes or len(key) != 32 or key in seen_keys:
                raise ValueError("invalid_or_reused_client_key")
            seen_keys.add(key)
            self._clients[client_id] = (writer_id, Ed25519PublicKey.from_public_bytes(key))
        self._nonces: set[tuple[str, str]] = set()
        self._lock = Lock()

    def exchange(self, raw: bytes) -> bytes:
        body = _decode(raw)
        entry = self._clients.get(body.get("client_id"))
        if entry is None:
            raise ValueError("untrusted_checkpoint_client")
        body = _verify(body, REQUEST_DOMAIN, entry[1])
        if (
            set(body) != {*self._scope, "version", "action", "client_id", "writer_id",
                          "writer_fence", "nonce", "expected", "snapshot"}
            or type(body["version"]) is not int or body["version"] != 1
            or body["action"] not in ("verify", "advance")
            or body["writer_id"] != entry[0]
            or any(body[name] != value for name, value in self._scope.items())
            or type(body["nonce"]) is not str or _HASH.fullmatch(body["nonce"]) is None
        ):
            raise ValueError("invalid_checkpoint_request")
        snapshot = decode_snapshot(_canonical(body["snapshot"]))
        sa.validate_authority_snapshot(
            snapshot, self._scope["authority_id"], self._scope["latch_id"], self._keys,
        )
        if type(body["writer_fence"]) is not int or body["writer_fence"] != snapshot.writer_fence:
            raise ValueError("invalid_request_fence")
        expected = _parse_checkpoint(body["expected"]) if body["expected"] is not None else None
        if (body["action"] == "verify") != (expected is None):
            raise ValueError("invalid_expected_checkpoint")
        with self._lock:
            target = checkpoint_for(snapshot, self._scope["checkpoint_id"], self._scope["trust_domain"])
            nonce = (body["client_id"], body["nonce"])
            if nonce in self._nonces:
                verdict, reason = "CONFLICT", "request_replayed"
            elif len(self._nonces) >= MAX_REQUESTS:
                verdict, reason = "UNAVAILABLE", "request_history_exhausted"
            else:
                self._nonces.add(nonce)
                verdict, reason = self._decide(body["action"], snapshot, target, expected, entry[0])
            response = dict(
                self._scope, version=1, server_id=self._server_id,
                request_digest=hashlib.sha256(raw).hexdigest(), nonce=body["nonce"],
                verdict=verdict, reason=reason,
                checkpoint=(
                    asdict(self._head)
                    if type(self._head) is Checkpoint and reason != "checkpoint_state_invalid"
                    else None
                ),
            )
            return _signed(response, RESPONSE_DOMAIN, self._signer)

    def _decide(self, action, snapshot, target, expected, writer):
        current = self._head
        if current is None:
            return "UNAVAILABLE", "checkpoint_missing"
        if type(current) is not Checkpoint:
            return "UNKNOWN", "checkpoint_state_invalid"
        try:
            Checkpoint(**asdict(current))
        except (ValueError, TypeError):
            return "UNKNOWN", "checkpoint_state_invalid"
        if any(getattr(current, name) != value for name, value in self._scope.items()):
            return "UNKNOWN", "checkpoint_state_invalid"
        if action == "verify":
            return ("VERIFIED", "checkpoint_matches") if current == target else (
                "CONFLICT", "checkpoint_head_conflict",
            )
        if snapshot.writer_id != writer:
            return "CONFLICT", "checkpoint_writer_conflict"
        if target.writer_fence < current.writer_fence:
            return "CONFLICT", "checkpoint_stale_fence"
        if target.writer_fence == current.writer_fence and target.writer_id != current.writer_id:
            return "CONFLICT", "checkpoint_writer_conflict"
        if expected is None or expected.revision > target.revision:
            return "CONFLICT", "checkpoint_expected_conflict"
        prefix = sa.AuthoritySnapshot(
            snapshot.authority_id, snapshot.latch_id, snapshot.events[:expected.revision],
        )
        if checkpoint_for(prefix, target.checkpoint_id, target.trust_domain) != expected:
            return "CONFLICT", "checkpoint_expected_conflict"
        if current == target:
            return "VERIFIED", "checkpoint_already_advanced"
        if current != expected:
            return "CONFLICT", "checkpoint_conditional_conflict"
        if target.revision <= current.revision or target.stop_epoch < current.stop_epoch:
            return "CONFLICT", "checkpoint_stale_head"
        self._head = target
        return "VERIFIED", "checkpoint_advanced"
