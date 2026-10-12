from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping, Protocol


INTERNAL_TENANT_ID = "gvai-internal"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CAPABILITY = re.compile(r"[a-z][a-z0-9_.:-]{0,127}\Z")
_CONTEXT_SEAL = object()


class IdentityScope(str, Enum):
    INTERNAL = "internal"
    CUSTOMER = "customer"


@dataclass(frozen=True)
class VerifiedIdentityClaims:
    """Claims returned only by an independently trusted verifier."""

    principal_id: str
    tenant_id: str
    scope: IdentityScope
    role: str
    capabilities: frozenset[str]


class IdentityVerifier(Protocol):
    """Adapter boundary for an external or local authentication authority."""

    def verify(self, evidence: object) -> VerifiedIdentityClaims | None: ...


@dataclass(frozen=True, init=False)
class IdentityContext:
    principal_id: str
    tenant_id: str
    scope: IdentityScope
    role: str
    capabilities: frozenset[str]
    _seal: object = field(repr=False, compare=False)

    def __init__(self, *_args, **_kwargs) -> None:
        raise TypeError(
            "IdentityContext must be issued by IdentityAuthority.authenticate()."
        )

    @classmethod
    def _issue(
        cls,
        claims: VerifiedIdentityClaims,
        seal: object,
    ) -> IdentityContext:
        if seal is not _CONTEXT_SEAL:
            raise TypeError("Identity contexts can only be issued by the authority.")
        context = object.__new__(cls)
        object.__setattr__(context, "principal_id", claims.principal_id)
        object.__setattr__(context, "tenant_id", claims.tenant_id)
        object.__setattr__(context, "scope", claims.scope)
        object.__setattr__(context, "role", claims.role)
        object.__setattr__(context, "capabilities", claims.capabilities)
        object.__setattr__(context, "_seal", seal)
        return context


@dataclass(frozen=True)
class IdentityPolicy:
    """Trusted role-to-capability grants. Missing entries grant nothing."""

    role_capabilities: Mapping[
        tuple[IdentityScope, str], frozenset[str]
    ]

    def __post_init__(self) -> None:
        if not isinstance(self.role_capabilities, Mapping):
            raise ValueError("Role grants must be a mapping.")

        normalized: dict[tuple[IdentityScope, str], frozenset[str]] = {}
        for key, capabilities in self.role_capabilities.items():
            if (
                not isinstance(key, tuple)
                or len(key) != 2
                or not isinstance(key[0], IdentityScope)
                or not _valid_identifier(key[1])
            ):
                raise ValueError("Role grant key is invalid.")
            if not isinstance(capabilities, (set, frozenset)):
                raise ValueError("Role capabilities must be a set.")
            frozen = frozenset(capabilities)
            if any(not _valid_capability(capability) for capability in frozen):
                raise ValueError("Role grant contains an invalid capability.")
            normalized[key] = frozen

        object.__setattr__(
            self,
            "role_capabilities",
            MappingProxyType(normalized),
        )

    @property
    def known_capabilities(self) -> frozenset[str]:
        return frozenset(
            capability
            for capabilities in self.role_capabilities.values()
            for capability in capabilities
        )


class IdentityAuthority:
    """Creates contexts only after the injected verifier accepts evidence."""

    def __init__(self, verifier: IdentityVerifier, policy: IdentityPolicy) -> None:
        self._verifier = verifier
        self._policy = policy

    def authenticate(self, evidence: object) -> IdentityContext | None:
        try:
            claims = self._verifier.verify(evidence)
        except Exception:
            return None

        if type(claims) is not VerifiedIdentityClaims:
            return None
        if (
            not _valid_identifier(claims.principal_id)
            or not _valid_identifier(claims.tenant_id)
            or not isinstance(claims.scope, IdentityScope)
            or not _valid_identifier(claims.role)
            or not isinstance(claims.capabilities, frozenset)
            or any(not _valid_capability(capability) for capability in claims.capabilities)
        ):
            return None

        if claims.scope is IdentityScope.INTERNAL:
            if claims.tenant_id != INTERNAL_TENANT_ID:
                return None
        elif claims.tenant_id == INTERNAL_TENANT_ID:
            return None

        grants = self._policy.role_capabilities.get((claims.scope, claims.role))
        if grants is None or not claims.capabilities.issubset(grants):
            return None

        return IdentityContext._issue(claims, _CONTEXT_SEAL)


@dataclass(frozen=True)
class TenantResource:
    scope: IdentityScope
    tenant_id: str
    resource_id: str


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str


class IdentityAuthorizer:
    """Default-deny checks for scoped resources and named tools."""

    def __init__(self, policy: IdentityPolicy) -> None:
        self._policy = policy

    def authorize_resource(
        self,
        identity: IdentityContext | None,
        resource: TenantResource,
        required_capability: str,
    ) -> AuthorizationDecision:
        identity_failure = self._identity_failure(identity)
        if identity_failure is not None:
            return identity_failure
        if not isinstance(resource, TenantResource):
            return AuthorizationDecision(False, "invalid_resource")
        if (
            not isinstance(resource.scope, IdentityScope)
            or not _valid_identifier(resource.tenant_id)
            or not _valid_identifier(resource.resource_id)
        ):
            return AuthorizationDecision(False, "invalid_resource")
        if resource.scope is not identity.scope:
            return AuthorizationDecision(False, "scope_mismatch")
        if resource.tenant_id != identity.tenant_id:
            return AuthorizationDecision(False, "tenant_mismatch")
        return self.authorize_capability(
            identity,
            required_capability,
            required_scope=resource.scope,
        )

    def authorize_tool(
        self,
        identity: IdentityContext | None,
        tool_name: str,
        *,
        scope: IdentityScope,
    ) -> AuthorizationDecision:
        identity_failure = self._identity_failure(identity)
        if identity_failure is not None:
            return identity_failure
        if not isinstance(scope, IdentityScope) or scope is not identity.scope:
            return AuthorizationDecision(False, "scope_mismatch")
        if not _valid_identifier(tool_name):
            return AuthorizationDecision(False, "unknown_tool")

        capability = f"tool:{tool_name}"
        if capability not in self._policy.known_capabilities:
            return AuthorizationDecision(False, "unknown_tool")
        return self.authorize_capability(
            identity,
            capability,
            required_scope=scope,
        )

    def authorize_capability(
        self,
        identity: IdentityContext | None,
        capability: str,
        *,
        required_scope: IdentityScope | None = None,
    ) -> AuthorizationDecision:
        identity_failure = self._identity_failure(identity)
        if identity_failure is not None:
            return identity_failure
        if not _valid_capability(capability):
            return AuthorizationDecision(False, "unknown_capability")
        if capability not in self._policy.known_capabilities:
            return AuthorizationDecision(False, "unknown_capability")
        if required_scope is not None:
            if not isinstance(required_scope, IdentityScope):
                return AuthorizationDecision(False, "scope_mismatch")
            if identity.scope is not required_scope:
                return AuthorizationDecision(False, "scope_mismatch")
        if capability not in identity.capabilities:
            return AuthorizationDecision(False, "capability_not_granted")
        return AuthorizationDecision(True, "authorized")

    @staticmethod
    def _identity_failure(
        identity: IdentityContext | None,
    ) -> AuthorizationDecision | None:
        if identity is None:
            return AuthorizationDecision(False, "missing_identity")
        if (
            type(identity) is not IdentityContext
            or getattr(identity, "_seal", None) is not _CONTEXT_SEAL
        ):
            return AuthorizationDecision(False, "unverified_identity")
        return None


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _valid_capability(value: object) -> bool:
    return isinstance(value, str) and _CAPABILITY.fullmatch(value) is not None
