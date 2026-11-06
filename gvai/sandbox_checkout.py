from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import asdict, dataclass, replace
from typing import Callable, Protocol
from urllib.parse import urlsplit

from gvai.commercial_identity import _valid_customer_tenant, _valid_identifier


_ATTEMPT = re.compile(r"[0-9a-f]{32}\Z")
_ACCOUNT = re.compile(r"acct_[A-Za-z0-9]{1,123}\Z")
_PRICE = re.compile(r"price_[A-Za-z0-9]{1,122}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PATH = re.compile(r"/[A-Za-z0-9/_.-]*\Z")


class CheckoutIntentDenied(ValueError):
    """Fixed reason only; never includes untrusted inputs or adapter diagnostics."""


@dataclass(frozen=True)
class AuthenticatedCheckoutContext:
    """Future identity-adapter output, NOT a client schema or authentication proof."""

    issuer: str
    principal_id: str
    tenant_id: str
    expires_at: int


@dataclass(frozen=True)
class CheckoutMembership:
    """Current server-owned membership and explicit checkout-management approval."""

    issuer: str
    principal_id: str
    tenant_id: str
    active: bool
    checkout_approved: bool


class CheckoutMembershipStore(Protocol):
    def lookup(
        self, issuer: str, principal_id: str, tenant_id: str,
    ) -> CheckoutMembership | None: ...


def _redirect_valid(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        return False
    if not value.isascii() or any(character.isspace() for character in value):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    labels = parts.netloc.split(".")
    return (
        parts.scheme == "https"
        and len(parts.netloc) <= 253
        and len(labels) >= 2
        and all(_HOST_LABEL.fullmatch(label) is not None for label in labels)
        and labels[-1].isalpha()
        and parts.netloc != "localhost"
        and not parts.netloc.endswith((".localhost", ".local"))
        and _PATH.fullmatch(parts.path) is not None
        and not any(segment in (".", "..") for segment in parts.path.split("/"))
        and value == "https://" + parts.netloc + parts.path
    )


@dataclass(frozen=True)
class SandboxCheckoutConfig:
    stripe_account_id: str
    environment: str
    price_id: str
    price_approved: bool
    success_url: str
    cancel_url: str

    def __post_init__(self) -> None:
        if (
            type(self.stripe_account_id) is not str
            or _ACCOUNT.fullmatch(self.stripe_account_id) is None
            or type(self.environment) is not str
            or self.environment != "sandbox"
            or type(self.price_id) is not str
            or _PRICE.fullmatch(self.price_id) is None
            or self.price_approved is not True
            or not _redirect_valid(self.success_url)
            or not _redirect_valid(self.cancel_url)
            or self.success_url == self.cancel_url
        ):
            raise CheckoutIntentDenied("invalid_server_configuration")


@dataclass(frozen=True)
class CheckoutAssociation:
    issuer: str
    principal_id: str
    tenant_id: str
    attempt_id: str


@dataclass(frozen=True)
class SandboxCheckoutIntent:
    """Internal immutable plan; never entitlement or a Stripe session."""

    version: int
    association: CheckoutAssociation
    stripe_account_id: str
    environment: str
    product: str
    mode: str
    price_id: str
    currency: str
    unit_amount: int
    recurring_interval: str
    recurring_interval_count: int
    quantity: int
    success_url: str
    cancel_url: str
    idempotency_key: str
    request_fingerprint: str


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")).hexdigest()


class SandboxCheckoutBuilder:
    """Trusted offline boundary; no authentication, persistence or Stripe execution."""

    def __init__(
        self,
        config: SandboxCheckoutConfig,
        memberships: CheckoutMembershipStore,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if type(config) is not SandboxCheckoutConfig:
            raise CheckoutIntentDenied("invalid_server_configuration")
        self._config = config
        self._memberships = memberships
        self._clock = clock

    def build(
        self,
        request: object,
        *,
        context: AuthenticatedCheckoutContext,
        attempt_id: str,
    ) -> SandboxCheckoutIntent:
        """V1 client allowlist is empty. Context and attempt ID are server inputs."""
        if type(request) is not dict or len(request) != 0:
            raise CheckoutIntentDenied("invalid_client_request")
        if (
            type(context) is not AuthenticatedCheckoutContext
            or not _valid_identifier(context.issuer)
            or not _valid_identifier(context.principal_id)
            or not _valid_customer_tenant(context.tenant_id)
            or type(context.expires_at) is not int
            or context.expires_at <= 0
        ):
            raise CheckoutIntentDenied("invalid_authenticated_context")
        if (
            type(attempt_id) is not str
            or _ATTEMPT.fullmatch(attempt_id) is None
            or attempt_id == "0" * 32
        ):
            raise CheckoutIntentDenied("invalid_attempt_identity")
        try:
            membership = self._memberships.lookup(
                context.issuer, context.principal_id, context.tenant_id,
            )
        except Exception:
            raise CheckoutIntentDenied("membership_unavailable") from None
        if (
            type(membership) is not CheckoutMembership
            or not _valid_identifier(membership.issuer)
            or not _valid_identifier(membership.principal_id)
            or not _valid_customer_tenant(membership.tenant_id)
            or (membership.issuer, membership.principal_id, membership.tenant_id)
            != (context.issuer, context.principal_id, context.tenant_id)
            or membership.active is not True
            or membership.checkout_approved is not True
        ):
            raise CheckoutIntentDenied("membership_denied")
        try:
            now = self._clock()
        except Exception:
            raise CheckoutIntentDenied("clock_unavailable") from None
        if (
            type(now) not in (int, float)
            or (type(now) is float and not math.isfinite(now))
            or now < 0
        ):
            raise CheckoutIntentDenied("invalid_clock")
        if now >= context.expires_at:
            raise CheckoutIntentDenied("expired_authenticated_context")

        config = self._config
        association = CheckoutAssociation(
            context.issuer, context.principal_id, context.tenant_id, attempt_id,
        )
        # Stable across parameter changes: future storage must reject fingerprint conflicts.
        key = "gvai-checkout-v1-" + _digest({
            "domain": "gvai-sandbox-checkout-attempt-v1",
            "account": config.stripe_account_id,
            "environment": config.environment,
            "attempt": attempt_id,
        })
        intent = SandboxCheckoutIntent(
            1, association, config.stripe_account_id, config.environment,
            "GVAI Advisory API", "subscription", config.price_id, "usd", 9900,
            "month", 1, 1, config.success_url, config.cancel_url, key, "",
        )
        return replace(
            intent, request_fingerprint=_digest({
                "domain": "gvai-sandbox-checkout-intent-v1",
                "intent": asdict(intent),
            }),
        )
