from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Callable, Literal, Mapping, Protocol


COMMAND_VERSION = 1
COMMAND_TYPE_SHUTDOWN = "shutdown"
COMMAND_ALGORITHM = "HMAC-SHA256"
DEFAULT_CLOCK_SKEW_SECONDS = 5
DEFAULT_MAX_LIFETIME_SECONDS = 300
MIN_HMAC_KEY_BYTES = 32

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{64}\Z")
_COMMAND_FIELDS = frozenset(
    {
        "version",
        "command_id",
        "command_type",
        "target_id",
        "issuer_id",
        "issued_at",
        "expires_at",
        "auth",
    }
)
_AUTH_FIELDS = frozenset({"algorithm", "key_id", "signature"})


class ExternalCommandRejected(ValueError):
    """A control command could not be safely authorized."""


@dataclass(frozen=True)
class CommandAuthentication:
    algorithm: str
    key_id: str
    signature: str


@dataclass(frozen=True)
class ExternalControlCommand:
    version: int
    command_id: str
    command_type: str
    target_id: str
    issuer_id: str
    issued_at: int
    expires_at: int
    auth: CommandAuthentication

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, object]
    ) -> ExternalControlCommand:
        if not isinstance(value, Mapping) or set(value) != _COMMAND_FIELDS:
            raise ExternalCommandRejected("Malformed command envelope.")

        auth = value.get("auth")
        if not isinstance(auth, Mapping) or set(auth) != _AUTH_FIELDS:
            raise ExternalCommandRejected("Malformed authentication evidence.")

        command = cls(
            version=value["version"],
            command_id=value["command_id"],
            command_type=value["command_type"],
            target_id=value["target_id"],
            issuer_id=value["issuer_id"],
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
            auth=CommandAuthentication(
                algorithm=auth["algorithm"],
                key_id=auth["key_id"],
                signature=auth["signature"],
            ),
        )
        command.validate()
        return command


    @classmethod
    def from_json(cls, value: str | bytes) -> ExternalControlCommand:
        if isinstance(value, bytes):
            try:
                value = value.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise ExternalCommandRejected("Malformed command JSON.") from None
        if not isinstance(value, str):
            raise ExternalCommandRejected("Malformed command JSON.")

        def unique_object(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ExternalCommandRejected("Duplicate command JSON field.")
                result[key] = item
            return result

        def reject_constant(_value):
            raise ExternalCommandRejected("Invalid command JSON number.")

        try:
            decoded = json.loads(
                value,
                object_pairs_hook=unique_object,
                parse_constant=reject_constant,
            )
        except ExternalCommandRejected:
            raise
        except (TypeError, ValueError):
            raise ExternalCommandRejected("Malformed command JSON.") from None
        return cls.from_mapping(decoded)

    def to_mapping(self) -> dict[str, object]:
        return {
            "version": self.version,
            "command_id": self.command_id,
            "command_type": self.command_type,
            "target_id": self.target_id,
            "issuer_id": self.issuer_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "auth": {
                "algorithm": self.auth.algorithm,
                "key_id": self.auth.key_id,
                "signature": self.auth.signature,
            },
        }

    def validate(self, *, require_signature: bool = True) -> None:
        if type(self.version) is not int or self.version != COMMAND_VERSION:
            raise ExternalCommandRejected("Unsupported command version.")
        if not isinstance(self.command_id, str):
            raise ExternalCommandRejected("Malformed command identifier.")
        try:
            if str(uuid.UUID(self.command_id)) != self.command_id:
                raise ValueError
        except (ValueError, AttributeError):
            raise ExternalCommandRejected("Malformed command identifier.") from None

        if self.command_type != COMMAND_TYPE_SHUTDOWN:
            raise ExternalCommandRejected("Unsupported command type.")
        _validate_identifier(self.target_id, "target")
        _validate_identifier(self.issuer_id, "issuer")
        _validate_identifier(self.auth.key_id, "key")
        if type(self.issued_at) is not int or type(self.expires_at) is not int:
            raise ExternalCommandRejected("Command times must be integer Unix seconds.")
        if self.auth.algorithm != COMMAND_ALGORITHM:
            raise ExternalCommandRejected("Unsupported authentication algorithm.")
        if require_signature and (
            not isinstance(self.auth.signature, str)
            or not _SIGNATURE.fullmatch(self.auth.signature)
        ):
            raise ExternalCommandRejected("Malformed authentication evidence.")

    def canonical_bytes(self) -> bytes:
        """Return the v1 signing bytes; signature is intentionally excluded."""
        self.validate(require_signature=False)
        payload = {
            "auth": {
                "algorithm": self.auth.algorithm,
                "key_id": self.auth.key_id,
            },
            "command_id": self.command_id,
            "command_type": self.command_type,
            "expires_at": self.expires_at,
            "issued_at": self.issued_at,
            "issuer_id": self.issuer_id,
            "target_id": self.target_id,
            "version": self.version,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")


def _validate_identifier(value: object, kind: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ExternalCommandRejected(f"Malformed {kind} identifier.")


def sign_control_command(
    command: ExternalControlCommand, key: bytes
) -> ExternalControlCommand:
    """Sign a command with externally held key material; no key is persisted."""
    if not isinstance(key, bytes) or len(key) < MIN_HMAC_KEY_BYTES:
        raise ValueError("HMAC-SHA256 keys must contain at least 32 bytes.")
    signature = hmac.new(key, command.canonical_bytes(), hashlib.sha256).hexdigest()
    return replace(command, auth=replace(command.auth, signature=signature))


class CommandAuthenticator(Protocol):
    def verify(
        self,
        *,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        message: bytes,
        signature: str,
    ) -> bool: ...


class HMACSHA256Authenticator:
    """Verifier over caller-supplied keys; key provisioning is out of scope."""

    def __init__(self, keys: Mapping[tuple[str, str], bytes]) -> None:
        self._keys = dict(keys)
        for issuer_key, key in self._keys.items():
            if (
                not isinstance(issuer_key, tuple)
                or len(issuer_key) != 2
                or not isinstance(key, bytes)
                or len(key) < MIN_HMAC_KEY_BYTES
            ):
                raise ValueError("Invalid issuer/key configuration.")
            _validate_identifier(issuer_key[0], "issuer")
            _validate_identifier(issuer_key[1], "key")

    def verify(
        self,
        *,
        issuer_id: str,
        key_id: str,
        algorithm: str,
        message: bytes,
        signature: str,
    ) -> bool:
        if algorithm != COMMAND_ALGORITHM or not _SIGNATURE.fullmatch(signature):
            return False
        key = self._keys.get((issuer_id, key_id))
        if not isinstance(key, bytes) or len(key) < MIN_HMAC_KEY_BYTES:
            return False
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)


StateResult = Literal["accepted", "replayed", "revoked"]


class ExternalControlState(Protocol):
    """State backend contract; consumption and revocation must be linearizable."""

    def consume_if_active(
        self,
        *,
        issuer_id: str,
        command_id: str,
        now: int,
        retain_until: int,
    ) -> StateResult: ...

    def revoke_issuer(self, issuer_id: str) -> None: ...

    def revoke_command(self, issuer_id: str, command_id: str) -> None: ...


class InMemoryExternalControlState:
    """Thread-safe reference state for tests or one process; not distributed."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[tuple[str, str], int] = {}
        self._revoked_issuers: set[str] = set()
        self._revoked_commands: set[tuple[str, str]] = set()

    def consume_if_active(
        self,
        *,
        issuer_id: str,
        command_id: str,
        now: int,
        retain_until: int,
    ) -> StateResult:
        key = (issuer_id, command_id)
        with self._lock:
            self._consumed = {
                consumed_key: expiry
                for consumed_key, expiry in self._consumed.items()
                if expiry >= now
            }
            if issuer_id in self._revoked_issuers or key in self._revoked_commands:
                return "revoked"
            if key in self._consumed:
                return "replayed"
            self._consumed[key] = retain_until
            return "accepted"

    def revoke_issuer(self, issuer_id: str) -> None:
        with self._lock:
            self._revoked_issuers.add(issuer_id)

    def revoke_command(self, issuer_id: str, command_id: str) -> None:
        with self._lock:
            self._revoked_commands.add((issuer_id, command_id))


class ExternalControlCommandVerifier:
    def __init__(
        self,
        authenticator: CommandAuthenticator,
        state: ExternalControlState,
        *,
        clock: Callable[[], int] | None = None,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
        max_lifetime_seconds: int = DEFAULT_MAX_LIFETIME_SECONDS,
    ) -> None:
        if type(clock_skew_seconds) is not int or clock_skew_seconds < 0:
            raise ValueError("Clock skew must be a non-negative integer.")
        if type(max_lifetime_seconds) is not int or max_lifetime_seconds <= 0:
            raise ValueError("Maximum command lifetime must be a positive integer.")
        self.authenticator = authenticator
        self.state = state
        self.clock = clock or (lambda: int(time.time()))
        self.clock_skew_seconds = clock_skew_seconds
        self.max_lifetime_seconds = max_lifetime_seconds

    def authorize(
        self,
        envelope: Mapping[str, object] | ExternalControlCommand | str | bytes,
        *,
        expected_target_id: str,
    ) -> ExternalControlCommand:
        try:
            command = (
                envelope
                if isinstance(envelope, ExternalControlCommand)
                else ExternalControlCommand.from_json(envelope)
                if isinstance(envelope, (str, bytes))
                else ExternalControlCommand.from_mapping(envelope)
            )
            command.validate()
            _validate_identifier(expected_target_id, "expected target")
            if command.target_id != expected_target_id:
                raise ExternalCommandRejected("Command target does not match.")
            if command.expires_at <= command.issued_at:
                raise ExternalCommandRejected("Invalid command validity interval.")
            if command.expires_at - command.issued_at > self.max_lifetime_seconds:
                raise ExternalCommandRejected("Command lifetime exceeds policy.")
            now = self.clock()
            if type(now) is not int:
                raise ExternalCommandRejected("Trusted clock is unavailable.")
            if command.issued_at > now + self.clock_skew_seconds:
                raise ExternalCommandRejected("Command is issued in the future.")
            if command.expires_at < now - self.clock_skew_seconds:
                raise ExternalCommandRejected("Command has expired.")
            if not self.authenticator.verify(
                issuer_id=command.issuer_id,
                key_id=command.auth.key_id,
                algorithm=command.auth.algorithm,
                message=command.canonical_bytes(),
                signature=command.auth.signature,
            ):
                raise ExternalCommandRejected("Command authentication failed.")
        except ExternalCommandRejected:
            raise
        except Exception:
            raise ExternalCommandRejected("Command verification failed closed.") from None

        try:
            state_result = self.state.consume_if_active(
                issuer_id=command.issuer_id,
                command_id=command.command_id,
                now=now,
                retain_until=command.expires_at + self.clock_skew_seconds,
            )
        except Exception:
            raise ExternalCommandRejected("Trusted control state is unavailable.") from None

        if state_result == "replayed":
            raise ExternalCommandRejected("Command has already been consumed.")
        if state_result == "revoked":
            raise ExternalCommandRejected("Command or issuer has been revoked.")
        if state_result != "accepted":
            raise ExternalCommandRejected("Trusted control state returned an invalid result.")
        return command