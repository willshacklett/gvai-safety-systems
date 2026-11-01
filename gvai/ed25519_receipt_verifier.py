from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gvai.commercial_reservation_authority import AuthorityIdentity


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ED25519_PUBLIC_KEY_LENGTH = 32
_ED25519_SIGNATURE_LENGTH = 64


class Ed25519ReceiptVerifier:
    """Verify receipt signatures against explicitly pinned Ed25519 public keys.

    Use through ``verify_authenticated_receipt`` to enforce the receipt's
    expected context. A valid signature authenticates evidence; it does not
    authorize execution or replay.
    """

    __slots__ = ("_authority", "_trusted_public_keys", "_revoked_key_ids")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Verifier trust configuration is immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Verifier trust configuration is immutable.")

    def __init__(
        self,
        *,
        authority: AuthorityIdentity,
        trusted_public_keys: Mapping[str, bytes],
        revoked_key_ids: frozenset[str] = frozenset(),
    ) -> None:
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if not isinstance(trusted_public_keys, Mapping) or not trusted_public_keys:
            raise ValueError("A non-empty pinned public-key set is required.")

        pinned_keys = {}
        for key_id, public_key_bytes in trusted_public_keys.items():
            if type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None:
                raise ValueError("Invalid trusted signing key ID.")
            if (
                type(public_key_bytes) is not bytes
                or len(public_key_bytes) != _ED25519_PUBLIC_KEY_LENGTH
            ):
                raise ValueError("Invalid pinned Ed25519 public key.")
            pinned_keys[key_id] = Ed25519PublicKey.from_public_bytes(public_key_bytes)

        if not isinstance(revoked_key_ids, (set, frozenset)):
            raise ValueError("Revoked signing key IDs must be a set.")
        revoked = frozenset(revoked_key_ids)
        for key_id in revoked:
            if type(key_id) is not str or _IDENTIFIER.fullmatch(key_id) is None:
                raise ValueError("Invalid revoked signing key ID.")

        self._authority = authority
        self._trusted_public_keys = MappingProxyType(pinned_keys)
        self._revoked_key_ids = revoked

    def verify_receipt(
        self,
        canonical_envelope: bytes,
        signature: bytes,
        signing_key_id: str,
        expected_authority: AuthorityIdentity,
    ) -> bool:
        if (
            type(canonical_envelope) is not bytes
            or not canonical_envelope
            or type(signature) is not bytes
            or len(signature) != _ED25519_SIGNATURE_LENGTH
            or type(signing_key_id) is not str
            or _IDENTIFIER.fullmatch(signing_key_id) is None
            or type(expected_authority) is not AuthorityIdentity
            or expected_authority != self._authority
            or signing_key_id in self._revoked_key_ids
        ):
            return False

        public_key = self._trusted_public_keys.get(signing_key_id)
        if public_key is None:
            return False
        try:
            public_key.verify(signature, canonical_envelope)
            return True
        except Exception:
            return False
