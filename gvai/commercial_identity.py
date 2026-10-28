from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol

from gvai.identity import INTERNAL_TENANT_ID


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class CommercialCapability(str, Enum):
    EVALUATE = "evaluation:run"
    READ_USAGE = "usage:read"


class CommercialResourceKind(str, Enum):
    EVALUATION = "evaluation"
    USAGE = "usage"


@dataclass(frozen=True)
class VerifiedCustomerIdentity:
    """Trusted verifier output, never a request schema or credential itself."""

    principal_id: str
    tenant_id: str
    capabilities: frozenset[CommercialCapability]
    expires_at: int
    revoked: bool = False


class CustomerIdentityVerifier(Protocol):
    """Independently verify credentials and current revocation on every call."""

    def verify(self, credential: str) -> VerifiedCustomerIdentity | None: ...


@dataclass(frozen=True)
class CommercialResourceOwnership:
    """Current server-owned metadata, resolved by resource ID only."""

    resource_id: str
    tenant_id: str
    kind: CommercialResourceKind


class CommercialOwnershipStore(Protocol):
    def lookup(self, resource_id: str) -> CommercialResourceOwnership | None: ...


class CommercialAuthorizationReason(str, Enum):
    AUTHORIZED = "authorized"
    MISSING_IDENTITY = "missing_identity"
    INVALID_IDENTITY = "invalid_identity"
    VERIFICATION_FAILED = "verification_failed"
    REVOKED_IDENTITY = "revoked_identity"
    EXPIRED_IDENTITY = "expired_identity"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    CAPABILITY_NOT_GRANTED = "capability_not_granted"
    INVALID_RESOURCE = "invalid_resource"
    RESOURCE_NOT_FOUND = "resource_not_found"
    INVALID_OWNERSHIP = "invalid_ownership"
    OWNERSHIP_LOOKUP_FAILED = "ownership_lookup_failed"
    TENANT_MISMATCH = "tenant_mismatch"
    RESOURCE_KIND_MISMATCH = "resource_kind_mismatch"
    AUTHORIZATION_FAILED = "authorization_failed"


@dataclass(frozen=True)
class CommercialAuthorizationDecision:
    reason: CommercialAuthorizationReason

    @property
    def allowed(self) -> bool:
        return self.reason is CommercialAuthorizationReason.AUTHORIZED

    def __bool__(self) -> bool:
        return self.allowed


class CommercialAuthorizer:
    """Offline customer authorization only; never executes or controls work."""

    def __init__(
        self,
        verifier: CustomerIdentityVerifier,
        ownership: CommercialOwnershipStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._verifier = verifier
        self._ownership = ownership
        self._clock = clock

    def authorize(
        self,
        credential: object,
        capability: CommercialCapability,
        resource_id: str,
    ) -> CommercialAuthorizationDecision:
        try:
            reason = self._authorize(credential, capability, resource_id)
        except Exception:
            reason = CommercialAuthorizationReason.AUTHORIZATION_FAILED
        return CommercialAuthorizationDecision(reason)

    def _authorize(
        self,
        credential: object,
        capability: CommercialCapability,
        resource_id: str,
    ) -> CommercialAuthorizationReason:
        reasons = CommercialAuthorizationReason
        if credential is None:
            return reasons.MISSING_IDENTITY
        if type(credential) is not str or not 1 <= len(credential) <= 4096:
            return reasons.INVALID_IDENTITY
        if type(capability) is not CommercialCapability:
            return reasons.UNSUPPORTED_CAPABILITY
        if not _valid_identifier(resource_id):
            return reasons.INVALID_RESOURCE

        try:
            identity = self._verifier.verify(credential)
        except Exception:
            return reasons.VERIFICATION_FAILED
        if type(identity) is not VerifiedCustomerIdentity:
            return reasons.INVALID_IDENTITY
        if (
            not _valid_identifier(identity.principal_id)
            or not _valid_customer_tenant(identity.tenant_id)
            or type(identity.capabilities) is not frozenset
            or any(type(grant) is not CommercialCapability for grant in identity.capabilities)
            or type(identity.expires_at) is not int
            or identity.expires_at <= 0
            or type(identity.revoked) is not bool
        ):
            return reasons.INVALID_IDENTITY
        if identity.revoked:
            return reasons.REVOKED_IDENTITY
        if capability not in identity.capabilities:
            return reasons.CAPABILITY_NOT_GRANTED

        try:
            resource = self._ownership.lookup(resource_id)
        except Exception:
            return reasons.OWNERSHIP_LOOKUP_FAILED
        if resource is None:
            return reasons.RESOURCE_NOT_FOUND
        if (
            type(resource) is not CommercialResourceOwnership
            or not _valid_identifier(resource.resource_id)
            or resource.resource_id != resource_id
            or not _valid_customer_tenant(resource.tenant_id)
            or type(resource.kind) is not CommercialResourceKind
        ):
            return reasons.INVALID_OWNERSHIP
        if resource.tenant_id != identity.tenant_id:
            return reasons.TENANT_MISMATCH
        expected_kind = {
            CommercialCapability.EVALUATE: CommercialResourceKind.EVALUATION,
            CommercialCapability.READ_USAGE: CommercialResourceKind.USAGE,
        }[capability]
        if resource.kind is not expected_kind:
            return reasons.RESOURCE_KIND_MISMATCH

        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            return reasons.AUTHORIZATION_FAILED
        if now >= identity.expires_at:
            return reasons.EXPIRED_IDENTITY
        return reasons.AUTHORIZED


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_customer_tenant(value: object) -> bool:
    return _valid_identifier(value) and value != INTERNAL_TENANT_ID
