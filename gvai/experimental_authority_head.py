from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    GENESIS_HASH,
    MAX_EVALUATION_UNITS,
)


CHECKPOINT_VERSION = 1
CHECKPOINT_PURPOSE = "independent_authority_head"
CHECKPOINT_ALGORITHM = "Ed25519"
CHECKPOINT_DOMAIN = b"gvai-independent-authority-head-checkpoint-v1\x00"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class AuthorityHeadState:
    """An unsigned database observation or independently held high-water record."""

    authority: AuthorityIdentity
    sequence: int
    event_hash: str

    def __post_init__(self) -> None:
        if type(self.authority) is not AuthorityIdentity:
            raise ValueError("A complete authority identity is required.")
        if type(self.sequence) is not int or not 0 <= self.sequence <= MAX_EVALUATION_UNITS:
            raise ValueError("Invalid authority-head sequence.")
        if type(self.event_hash) is not str or _DIGEST.fullmatch(self.event_hash) is None:
            raise ValueError("Invalid canonical event-head hash.")
        if self.sequence == 0 and self.event_hash != GENESIS_HASH:
            raise ValueError("Sequence zero requires the V1 genesis hash.")


@dataclass(frozen=True)
class AuthorityHeadCheckpoint:
    """Separate experimental encoding; never a V1 receipt envelope."""

    head: AuthorityHeadState
    signing_key_id: str
    signature: bytes
    version: int = CHECKPOINT_VERSION
    purpose: str = CHECKPOINT_PURPOSE
    signature_algorithm: str = CHECKPOINT_ALGORITHM

    def __post_init__(self) -> None:
        if type(self.head) is not AuthorityHeadState:
            raise ValueError("An authority-head state is required.")
        if type(self.signing_key_id) is not str or _IDENTIFIER.fullmatch(self.signing_key_id) is None:
            raise ValueError("Invalid checkpoint signing key ID.")
        if type(self.signature) is not bytes or len(self.signature) != 64:
            raise ValueError("An Ed25519 signature must be exactly 64 bytes.")
        if type(self.version) is not int or self.version != CHECKPOINT_VERSION:
            raise ValueError("Unsupported checkpoint version.")
        if type(self.purpose) is not str or self.purpose != CHECKPOINT_PURPOSE:
            raise ValueError("Invalid checkpoint purpose.")
        if type(self.signature_algorithm) is not str or self.signature_algorithm != CHECKPOINT_ALGORITHM:
            raise ValueError("Unsupported checkpoint signature algorithm.")

    def canonical_bytes(self) -> bytes:
        record = {
            "authority_epoch": self.head.authority.epoch,
            "authority_id": self.head.authority.authority_id,
            "contract_version": self.version,
            "event_head_hash": self.head.event_hash,
            "purpose": self.purpose,
            "sequence": self.head.sequence,
            "signature_algorithm": self.signature_algorithm,
            "signing_key_id": self.signing_key_id,
            "trust_domain": self.head.authority.trust_domain,
        }
        return CHECKPOINT_DOMAIN + json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")


class IndependentHighWaterProvider(Protocol):
    """Trusted state outside PostgreSQL; no implicit initialization or reset.

    Atomically compare with an already provisioned record for this exact
    authority/epoch/domain. Reject lower sequences and equal-sequence hash
    conflicts. On success, durably store any advancement before returning the
    accepted state. Missing state returns None; outages/errors must not succeed.
    Operations must be linearizable across callers and enforce the timeout.
    This interface does not prove that an implementation meets these guarantees.
    Only authenticated checkpoints may enter this operation.
    """

    def check_and_advance(
        self, checkpoint: AuthorityHeadCheckpoint, *, timeout_seconds: float
    ) -> AuthorityHeadState | None: ...


@dataclass(frozen=True)
class AuthorityHeadVerification:
    signature_authentic: bool = False
    database_consistent: bool = False
    high_water_confirmed: bool = False

    @property
    def accepted(self) -> bool:
        return self.signature_authentic and self.database_consistent and self.high_water_confirmed


class ExperimentalAuthorityHeadVerifier:
    """Pinned checkpoint verification, conditional on independent provider trust.

    High-water confirmation detects rollback below independently known history,
    not unseen newer events, wall-clock recency, or durable protection by itself.
    No signer, database reader, provider implementation, or registration is supplied.
    """

    __slots__ = ("_authority", "_public_keys", "_revoked_ids", "_provider", "_timeout")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Checkpoint trust configuration is immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Checkpoint trust configuration is immutable.")

    def __init__(
        self,
        *,
        authority: AuthorityIdentity,
        checkpoint_public_keys: Mapping[str, bytes],
        independent_high_water: IndependentHighWaterProvider | None,
        other_purpose_key_ids: frozenset[str],
        other_purpose_public_keys: frozenset[bytes],
        revoked_key_ids: frozenset[str] = frozenset(),
        timeout_seconds: float = 2.0,
    ) -> None:
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if not isinstance(checkpoint_public_keys, Mapping) or not 1 <= len(checkpoint_public_keys) <= 16:
            raise ValueError("A bounded non-empty checkpoint key set is required.")
        for key_ids in (other_purpose_key_ids, revoked_key_ids):
            if type(key_ids) not in (set, frozenset) or any(
                type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None
                for key_id in key_ids
            ):
                raise ValueError("Invalid excluded or revoked key IDs.")
        if type(other_purpose_public_keys) not in (set, frozenset) or any(
            type(key) is not bytes or len(key) != 32 for key in other_purpose_public_keys
        ):
            raise ValueError("Invalid other-purpose public keys.")
        pinned_keys = {}
        for key_id, key_bytes in checkpoint_public_keys.items():
            if type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None:
                raise ValueError("Invalid checkpoint key ID.")
            if type(key_bytes) is not bytes or len(key_bytes) != 32:
                raise ValueError("Invalid pinned checkpoint public key.")
            if key_id in other_purpose_key_ids or key_bytes in other_purpose_public_keys:
                raise ValueError("Checkpoint keys must not be reused for other purposes.")
            pinned_keys[key_id] = Ed25519PublicKey.from_public_bytes(key_bytes)
        if independent_high_water is not None and not callable(
            getattr(independent_high_water, "check_and_advance", None)
        ):
            raise ValueError("An independent high-water provider is required.")
        if (
            type(timeout_seconds) not in (int, float)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 30
        ):
            raise ValueError("Checkpoint timeout must be bounded and positive.")
        self._authority = authority
        self._public_keys = MappingProxyType(pinned_keys)
        self._revoked_ids = frozenset(revoked_key_ids)
        self._provider = independent_high_water
        self._timeout = float(timeout_seconds)

    def verify_signature(self, checkpoint: object) -> bool:
        """Authenticity only: a valid old signature does not establish freshness."""
        if type(checkpoint) is not AuthorityHeadCheckpoint:
            return False
        try:
            checkpoint.__post_init__()
            checkpoint.head.__post_init__()
            checkpoint.head.authority.__post_init__()
            if checkpoint.head.authority != self._authority:
                return False
            if checkpoint.signing_key_id in self._revoked_ids:
                return False
            public_key = self._public_keys.get(checkpoint.signing_key_id)
            if public_key is None:
                return False
            public_key.verify(checkpoint.signature, checkpoint.canonical_bytes())
            return True
        except Exception:
            return False

    def verify_checkpoint(
        self, checkpoint: object, database_head: object
    ) -> AuthorityHeadVerification:
        if (
            type(checkpoint) is not AuthorityHeadCheckpoint
            or type(checkpoint.head) is not AuthorityHeadState
            or type(checkpoint.head.authority) is not AuthorityIdentity
        ):
            return AuthorityHeadVerification()
        try:
            checkpoint = replace(
                checkpoint,
                head=replace(checkpoint.head, authority=replace(checkpoint.head.authority)),
            )
        except (AttributeError, TypeError, ValueError):
            return AuthorityHeadVerification()
        if not self.verify_signature(checkpoint):
            return AuthorityHeadVerification()
        if type(database_head) is not AuthorityHeadState:
            return AuthorityHeadVerification(signature_authentic=True)
        try:
            database_head.__post_init__()
            database_head.authority.__post_init__()
            if database_head != checkpoint.head:
                return AuthorityHeadVerification(signature_authentic=True)
        except Exception:
            return AuthorityHeadVerification(signature_authentic=True)
        consistent = AuthorityHeadVerification(True, True, False)
        if self._provider is None:
            return consistent
        try:
            provider_checkpoint = replace(
                checkpoint,
                head=replace(checkpoint.head, authority=replace(checkpoint.head.authority)),
            )
            confirmed = self._provider.check_and_advance(
                provider_checkpoint, timeout_seconds=self._timeout
            )
            if provider_checkpoint != checkpoint:
                return consistent
            if type(confirmed) is not AuthorityHeadState:
                return consistent
            confirmed.__post_init__()
            confirmed.authority.__post_init__()
            if confirmed != checkpoint.head:
                return consistent
        except Exception:
            return consistent
        return AuthorityHeadVerification(True, True, True)
