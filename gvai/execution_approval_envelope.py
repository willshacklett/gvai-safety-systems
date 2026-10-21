"""Offline wire-format conformance only; no signature verification or admission."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import uuid


DOMAIN_PREFIX = b"GVAI-EXECUTION-APPROVAL-V1\n"
MAX_ENVELOPE_BYTES = 65536
MAX_DEPTH = 8
_MAX_INTEGER = 2**63 - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")


class EnvelopeRejected(ValueError):
    """A wire-format or offline context constraint was not satisfied."""


def _reject() -> None:
    raise EnvelopeRejected("Execution approval envelope rejected.")


def _object(value: object, fields: set[str]) -> None:
    if type(value) is not dict or set(value) != fields:
        _reject()


def _match(value: object, pattern: re.Pattern) -> None:
    if type(value) is not str or pattern.fullmatch(value) is None:
        _reject()


def _integer(value: object) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_INTEGER:
        _reject()


def _uuid(value: object) -> None:
    if type(value) is not str or str(uuid.UUID(value)) != value:
        _reject()
    parsed = uuid.UUID(value)
    if parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        _reject()


def _strings(value: object, limit: int, *, nonempty: bool = True) -> None:
    if type(value) is not list or not (int(nonempty) <= len(value) <= limit):
        _reject()
    for item in value:
        _match(item, _ID)
    if value != sorted(set(value)):
        _reject()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _no_number(value):
    _reject()


def _bounded_depth(text: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                _reject()
        elif char in "]}":
            depth -= 1
            if depth < 0:
                _reject()
    if depth or quoted:
        _reject()


def _action(value: object) -> None:
    _object(
        value, {"tool_id", "executable_sha256", "arguments", "inputs",
                "resources", "outputs", "limits"},
    )
    _match(value["tool_id"], _ID)
    _match(value["executable_sha256"], _DIGEST)
    arguments = value["arguments"]
    if type(arguments) is not list or len(arguments) > 128:
        _reject()
    for argument in arguments:
        if (
            type(argument) is not str or len(argument) > 1024
            or any(ord(char) < 32 or ord(char) > 126 for char in argument)
        ):
            _reject()
    for field in ("inputs", "resources", "outputs"):
        entries = value[field]
        if type(entries) is not list or len(entries) > 128:
            _reject()
        ids = []
        for entry in entries:
            _object(entry, {"id", "sha256"})
            _match(entry["id"], _ID)
            _match(entry["sha256"], _DIGEST)
            ids.append(entry["id"])
        if ids != sorted(set(ids)):
            _reject()
    limits = value["limits"]
    _object(limits, {"duration_seconds", "memory_bytes", "output_bytes"})
    for limit in limits.values():
        _integer(limit)
        if limit == 0:
            _reject()
    if limits["duration_seconds"] > 60:
        _reject()


def _bounded_context(value: object) -> None:
    remaining = MAX_ENVELOPE_BYTES

    def visit(item: object, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0:
            _reject()
        if type(item) is str:
            remaining -= len(item)
            if remaining < 0 or not item.isascii():
                _reject()
        elif type(item) is int:
            _integer(item)
        elif type(item) is bool or item is None:
            return
        elif type(item) in (dict, list):
            if depth >= MAX_DEPTH or len(item) > remaining:
                _reject()
            if type(item) is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        _reject()
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        else:
            _reject()

    visit(value, 0)


def _validate(value: object, now: object) -> None:
    _integer(now)
    _object(
        value,
        {"version", "purpose", "approval_id", "challenge", "issuer_id",
         "approver_id", "scope", "audience", "workload", "action", "action_sha256",
         "effects", "policy", "observation", "human_decision_id", "control",
         "issued_at", "not_before", "expires_at", "auth"},
    )
    if type(value["version"]) is not int or value["version"] != 1:
        _reject()
    if value["purpose"] != "execute-once":
        _reject()
    _uuid(value["approval_id"])
    _match(value["challenge"], _DIGEST)
    for field in ("issuer_id", "approver_id", "human_decision_id"):
        _match(value[field], _ID)
    _strings(value["scope"], 16)
    _strings(value["effects"], 128, nonempty=False)
    audience = value["audience"]
    _object(audience, {"supervisor_id", "environment_id", "tenant_id", "boot_id"})
    for field in ("supervisor_id", "environment_id", "tenant_id"):
        _match(audience[field], _ID)
    _uuid(audience["boot_id"])
    workload = value["workload"]
    _object(workload, {"instance_id", "bundle_sha256", "revision"})
    _match(workload["instance_id"], _ID)
    _match(workload["bundle_sha256"], _DIGEST)
    _match(workload["revision"], _REVISION)
    _action(value["action"])
    _match(value["action_sha256"], _DIGEST)
    if hashlib.sha256(_canonical(value["action"])).hexdigest() != value["action_sha256"]:
        _reject()
    policy = value["policy"]
    _object(policy, {"sha256", "epoch"})
    _match(policy["sha256"], _DIGEST)
    _integer(policy["epoch"])
    control = value["control"]
    _object(control, {"epoch", "revocation_generation", "shutdown_generation"})
    for generation in control.values():
        _integer(generation)
    observation = value["observation"]
    _object(observation, {"id", "source_id", "sha256", "sequence", "observed_at",
                          "expires_at", "status", "halted"})
    for field in ("id", "source_id"):
        _match(observation[field], _ID)
    _match(observation["sha256"], _DIGEST)
    _integer(observation["sequence"])
    if observation["status"] != "stable" or observation["halted"] is not False:
        _reject()
    for field in ("observed_at", "expires_at"):
        _integer(observation[field])
    if not (
        observation["observed_at"] <= now < observation["expires_at"]
        and 0 < observation["expires_at"] - observation["observed_at"] <= 60
    ):
        _reject()
    for field in ("issued_at", "not_before", "expires_at"):
        _integer(value[field])
    if not (
        value["issued_at"] <= value["not_before"] <= now < value["expires_at"]
        and 0 < value["expires_at"] - value["issued_at"] <= 60
        and value["action"]["limits"]["duration_seconds"] <= value["expires_at"] - now
    ):
        _reject()
    auth = value["auth"]
    _object(auth, {"algorithm", "key_id", "signature"})
    if auth["algorithm"] != "Ed25519":
        _reject()
    _match(auth["key_id"], _ID)
    _match(auth["signature"], _SIGNATURE)


@dataclass(frozen=True)
class UnauthenticatedEnvelope:
    """Immutable canonical bytes only, never a capability or verified approval."""

    canonical_envelope: bytes
    canonical_payload: bytes

    @property
    def signing_bytes(self) -> bytes:
        return DOMAIN_PREFIX + self.canonical_payload

    @property
    def allowed(self) -> bool:
        return False

    @property
    def authenticated(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def parse_execution_approval(
    raw: object, *, now: object, expected_payload: object,
) -> UnauthenticatedEnvelope:
    """Reject malformed/mismatched claims against an explicit offline snapshot.

    ``expected_payload`` must exactly equal the entire unsigned payload. It is
    caller-provided test context, NOT an authenticated or live supervisor state.
    Matching it and formatting a signature confer no execution authority.
    """
    try:
        if type(raw) not in (bytes, str):
            _reject()
        if len(raw) > MAX_ENVELOPE_BYTES:
            _reject()
        text = raw.decode("ascii") if type(raw) is bytes else raw
        encoded = text.encode("ascii")
        if len(encoded) > MAX_ENVELOPE_BYTES:
            _reject()
        _bounded_depth(text)
        value = json.loads(
            text, object_pairs_hook=_pairs, parse_float=_no_number,
            parse_constant=_no_number,
        )
        _validate(value, now)
        unsigned = {**value, "auth": {
            "algorithm": value["auth"]["algorithm"], "key_id": value["auth"]["key_id"],
        }}
        # Expected context must be equally strict, not a truthy subset or callback.
        if type(expected_payload) is not dict:
            _reject()
        _bounded_context(expected_payload)
        expected_bytes = _canonical(expected_payload)
        if len(expected_bytes) > MAX_ENVELOPE_BYTES:
            _reject()
        expected = json.loads(
            expected_bytes, object_pairs_hook=_pairs, parse_float=_no_number,
            parse_constant=_no_number,
        )
        _object(expected["auth"], {"algorithm", "key_id"})
        complete_expected = {**expected, "auth": {
            **expected["auth"], "signature": value["auth"]["signature"],
        }}
        _validate(complete_expected, now)
        payload = _canonical(unsigned)
        if payload != expected_bytes:
            _reject()
        return UnauthenticatedEnvelope(_canonical(value), payload)
    except EnvelopeRejected:
        raise
    except Exception:
        raise EnvelopeRejected("Execution approval envelope rejected.") from None
