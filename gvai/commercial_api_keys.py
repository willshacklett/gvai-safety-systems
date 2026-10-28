from __future__ import annotations

import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Callable, Protocol

from gvai.commercial_identity import (
    CommercialCapability,
    VerifiedCustomerIdentity,
    _valid_customer_tenant,
    _valid_identifier,
)


API_KEY_PREFIX = "gvai_customer_v1_"
_KEY_ID = re.compile(r"[0-9a-f]{32}\Z")
_CREDENTIAL = re.compile(re.escape(API_KEY_PREFIX) + r"([0-9a-f]{32})_([0-9a-f]{64})\Z")
_DOMAIN = b"gvai-customer-api-key-v1\x00"


class ApiKeyOperationError(ValueError):
    """A trusted key-management operation failed without exposing its inputs."""


@dataclass(frozen=True)
class ApiKeyRecord:
    key_id: str
    principal_id: str
    tenant_id: str
    capabilities: frozenset[CommercialCapability]
    created_at: int
    expires_at: int
    verifier: bytes = field(repr=False)
    revoked: bool = False


class IssuedApiKey:
    """Ephemeral handoff; only take_secret() presents the secret, once."""

    __slots__ = ("key_id", "_secret", "_lock")

    def __init__(self, key_id: str, secret: str) -> None:
        self.key_id = key_id
        self._secret = secret
        self._lock = threading.Lock()

    def take_secret(self) -> str | None:
        with self._lock:
            secret = self._secret
            self._secret = None
            return secret


class ApiKeyStore(Protocol):
    """Trusted store: unique IDs, current reads, atomic insert and revocation."""

    def insert_if_absent(self, record: ApiKeyRecord) -> bool: ...

    def lookup(self, key_id: str) -> ApiKeyRecord | None: ...

    def revoke(self, key_id: str) -> bool: ...


class InMemoryApiKeyStore:
    """Nonproduction, single-process reference store; no durable revocation."""

    def __init__(self) -> None:
        self._records: dict[str, ApiKeyRecord] = {}
        self._lock = threading.Lock()

    def insert_if_absent(self, record: ApiKeyRecord) -> bool:
        with self._lock:
            if record.key_id in self._records:
                return False
            self._records[record.key_id] = record
            return True

    def lookup(self, key_id: str) -> ApiKeyRecord | None:
        with self._lock:
            return self._records.get(key_id)

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            record = self._records.get(key_id)
            if record is None:
                return False
            self._records[key_id] = replace(record, revoked=True)
            return True


class CustomerApiKeys:
    """Offline lifecycle and CustomerIdentityVerifier adapter, not authorization.

    Construct and call management methods only from trusted server code.
    The verifier secret must be independently provisioned, never a STOP key.
    """

    def __init__(
        self,
        store: ApiKeyStore,
        *,
        verifier_secret: bytes | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._verifier_secret = (
            verifier_secret
            if type(verifier_secret) is bytes and len(verifier_secret) >= 32
            else None
        )
        self._clock = clock

    def issue(
        self,
        *,
        principal_id: str,
        tenant_id: str,
        capabilities: frozenset[CommercialCapability],
        expires_at: int,
    ) -> IssuedApiKey:
        """Trusted assignment only; never bind these arguments to request claims."""
        try:
            now = self._now()
            if (
                self._verifier_secret is None
                or not _valid_identifier(principal_id)
                or not _valid_customer_tenant(tenant_id)
                or type(capabilities) is not frozenset
                or any(type(grant) is not CommercialCapability for grant in capabilities)
                or type(expires_at) is not int
                or expires_at <= now
            ):
                raise ValueError
            for _attempt in range(3):
                key_id = secrets.token_hex(16)
                credential = API_KEY_PREFIX + key_id + "_" + secrets.token_hex(32)
                if _CREDENTIAL.fullmatch(credential) is None:
                    raise ValueError
                record = ApiKeyRecord(
                    key_id, principal_id, tenant_id, capabilities,
                    int(now), expires_at, self._digest(credential),
                )
                if self._store.insert_if_absent(record) is True:
                    return IssuedApiKey(key_id, credential)
        except Exception:
            pass
        raise ApiKeyOperationError("API key issuance failed.")

    def verify(self, credential: object) -> VerifiedCustomerIdentity | None:
        """Re-read current state every time; all errors deny without diagnostics."""
        try:
            if self._verifier_secret is None or type(credential) is not str:
                return None
            if len(credential) != len(API_KEY_PREFIX) + 97:
                return None
            parsed = _CREDENTIAL.fullmatch(credential)
            if parsed is None:
                return None
            record = self._store.lookup(parsed[1])
            if not self._valid_record(record, parsed[1]):
                return None
            if not hmac.compare_digest(self._digest(credential), record.verifier):
                return None
            now = self._now()
            if record.revoked or not record.created_at <= now < record.expires_at:
                return None
            return VerifiedCustomerIdentity(
                record.principal_id, record.tenant_id,
                record.capabilities, record.expires_at,
            )
        except Exception:
            return None

    def revoke(self, key_id: object) -> bool:
        """Trusted management only; repeated revocation succeeds for known IDs."""
        try:
            if type(key_id) is not str or _KEY_ID.fullmatch(key_id) is None:
                return False
            return self._store.revoke(key_id) is True
        except Exception:
            return False

    def _digest(self, credential: str) -> bytes:
        return hmac.new(
            self._verifier_secret, _DOMAIN + credential.encode("ascii"), hashlib.sha256
        ).digest()

    def _now(self) -> float:
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError
        return now

    @staticmethod
    def _valid_record(record: object, key_id: str) -> bool:
        return (
            type(record) is ApiKeyRecord
            and record.key_id == key_id
            and _valid_identifier(record.principal_id)
            and _valid_customer_tenant(record.tenant_id)
            and type(record.capabilities) is frozenset
            and all(type(grant) is CommercialCapability for grant in record.capabilities)
            and type(record.created_at) is int
            and type(record.expires_at) is int
            and 0 <= record.created_at < record.expires_at
            and type(record.revoked) is bool
            and type(record.verifier) is bytes
            and len(record.verifier) == 32
        )
