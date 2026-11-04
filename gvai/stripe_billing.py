"""Test-mode Stripe authority. Browser redirects and event payloads never grant access."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from gvai.commercial_http import _reject_json_constant, _unique_object
from gvai.commercial_identity import _valid_customer_tenant


LOG = logging.getLogger(__name__)
API_VERSION = "2024-06-20"
ALLOWANCE = 100_000
AMOUNT = 9900
MAX_PAYLOAD = 65_536
FRESH_SECONDS = 60
EVENT_TYPES = frozenset({
    "checkout.session.completed", "checkout.session.expired",
    "invoice.paid", "invoice.payment_failed", "invoice.payment_action_required",
    "invoice.voided", "invoice.marked_uncollectible",
    "customer.subscription.created", "customer.subscription.updated",
    "customer.subscription.deleted", "customer.deleted",
    "charge.refunded", "charge.dispute.created",
})
_ID = re.compile(r"[A-Za-z0-9_]{1,128}\Z")


class BillingUnavailable(RuntimeError):
    """Redacted failure requiring retry or operator reconciliation."""


def fail(event: str) -> BillingUnavailable:
    LOG.warning("stripe_billing: %s", event)
    return BillingUnavailable("Billing unavailable; reconcile before retry.")


def identifier(value: Any, prefix: str) -> str:
    if type(value) is not str or not value.startswith(prefix) or not _ID.fullmatch(value):
        raise fail("invalid_identifier")
    return value


def decode(raw: bytes) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PAYLOAD:
            raise ValueError
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
        if type(result) is not dict:
            raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise fail("invalid_json") from None


def verify_event(raw: bytes, signature: str, secret: str, *, now: int) -> dict[str, Any]:
    if (
        type(raw) is not bytes or not 0 < len(raw) <= MAX_PAYLOAD
        or type(signature) is not str or len(signature) > 2048
        or type(secret) is not str or not secret.startswith("whsec_") or len(secret) < 20
    ):
        raise fail("signature_rejected")
    parts = [part.partition("=") for part in signature.split(",")]
    timestamps = [value for key, separator, value in parts if key == "t" and separator]
    signatures = [value for key, separator, value in parts if key == "v1" and separator]
    if (
        len(timestamps) != 1 or not re.fullmatch(r"[0-9]{1,12}", timestamps[0])
        or not 1 <= len(signatures) <= 8
        or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in signatures)
        or abs(now - int(timestamps[0])) > 300
    ):
        raise fail("signature_rejected")
    expected = hmac.new(
        secret.encode("ascii"), timestamps[0].encode("ascii") + b"." + raw, hashlib.sha256,
    ).hexdigest()
    if not any(hmac.compare_digest(expected, item) for item in signatures):
        raise fail("signature_rejected")
    event = decode(raw)
    if (
        event.get("object") != "event" or event.get("livemode") is not False
        or event.get("api_version") != API_VERSION or event.get("account") is not None
        or type(event.get("type")) is not str or type(event.get("data")) is not dict
        or type(event["data"].get("object")) is not dict
    ):
        raise fail("event_contract_rejected")
    identifier(event.get("id"), "evt_")
    return event


def https_url(value: Any, *, host: str | None = None) -> str:
    if type(value) is not str or len(value) > 4096 or any(ord(c) <= 32 for c in value):
        raise fail("url_rejected")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
        or parsed.port not in (None, 443) or (host is not None and parsed.hostname != host)
    ):
        raise fail("url_rejected")
    return value


@dataclass(frozen=True, repr=False)
class BillingConfig:
    secret_key: str = field(repr=False)
    webhook_secret: str = field(repr=False)
    price_id: str
    success_url: str
    cancel_url: str
    return_url: str

    def __post_init__(self) -> None:
        if (
            type(self.secret_key) is not str or not self.secret_key.startswith("sk_test_")
            or len(self.secret_key) < 20 or not self.secret_key.isascii()
            or type(self.webhook_secret) is not str
            or not self.webhook_secret.startswith("whsec_")
            or len(self.webhook_secret) < 20 or not self.webhook_secret.isascii()
        ):
            raise fail("test_mode_configuration_required")
        identifier(self.price_id, "price_")
        for value in (self.success_url, self.cancel_url, self.return_url):
            https_url(value)


class StripeAPI(Protocol):
    def request(
        self, method: str, path: str, parameters: dict[str, str] | None = None,
        *, idempotency_key: str | None = None,
    ) -> dict[str, Any]: ...


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise fail("redirect_rejected")


class StripeREST:
    """Pinned origin/version, bounded reads, no redirects and no automatic retries."""

    def __init__(self, config: BillingConfig) -> None:
        self.config = config
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def request(
        self, method: str, path: str, parameters: dict[str, str] | None = None,
        *, idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if method not in {"GET", "POST"} or not re.fullmatch(r"/v1/[a-z_]+(?:/[A-Za-z0-9_]+)*", path):
            raise fail("request_contract_rejected")
        encoded = urlencode(parameters or {}).encode("ascii")
        url = "https://api.stripe.com" + path
        if method == "GET" and encoded:
            url += "?" + encoded.decode("ascii")
        headers = {
            "Authorization": "Bearer " + self.config.secret_key,
            "Stripe-Version": API_VERSION, "Content-Type": "application/x-www-form-urlencoded",
        }
        if idempotency_key is not None:
            identifier(idempotency_key, "gvai_")
            headers["Idempotency-Key"] = idempotency_key
        try:
            with self._opener.open(Request(
                url, data=encoded if method == "POST" else None, headers=headers, method=method,
            ), timeout=5) as response:
                if response.status != 200:
                    raise fail("stripe_response_rejected")
                return decode(response.read(MAX_PAYLOAD + 1))
        except (HTTPError, URLError, OSError, TimeoutError):
            raise fail("stripe_request_failed") from None


@dataclass(frozen=True)
class PaidState:
    subscription: str | None = None
    invoice: str | None = None
    start: int | None = None
    end: int | None = None
    eligible: bool = False
    access_until: int | None = None


def _test_object(value: dict[str, Any], object_type: str, expected_id: str) -> None:
    if value.get("object") != object_type or value.get("id") != expected_id or value.get("livemode") is not False:
        raise fail("stripe_object_rejected")


def _single_list(value: dict[str, Any]) -> list[dict[str, Any]]:
    if type(value) is not dict:
        raise fail("stripe_list_rejected")
    data = value.get("data")
    if value.get("has_more") is not False or type(data) is not list or len(data) > 1:
        raise fail("ambiguous_subscription_state")
    if any(type(item) is not dict for item in data):
        raise fail("stripe_list_rejected")
    return data


class SubscriptionAuthority:
    def __init__(self, api: StripeAPI, config: BillingConfig, *, clock: Callable[[], float] = time.time) -> None:
        self.api, self.config, self.clock = api, config, clock

    def customer(self, customer: str) -> None:
        customer = identifier(customer, "cus_")
        value = self.api.request("GET", "/v1/customers/" + customer)
        _test_object(value, "customer", customer)
        if value.get("deleted"):
            raise fail("customer_deleted")

    def current(self, customer: str, pinned_subscription: str | None) -> PaidState:
        self.customer(customer)
        subscriptions = _single_list(self.api.request(
            "GET", "/v1/subscriptions", {"customer": customer, "status": "all", "limit": "2"},
        ))
        if not subscriptions:
            return PaidState()
        subscription_id = identifier(subscriptions[0].get("id"), "sub_")
        if pinned_subscription is not None and subscription_id != pinned_subscription:
            raise fail("subscription_substitution_rejected")
        sub = self.api.request("GET", "/v1/subscriptions/" + subscription_id)
        _test_object(sub, "subscription", subscription_id)
        if sub.get("customer") != customer:
            raise fail("subscription_customer_mismatch")
        denied = PaidState(subscription=subscription_id)
        if (
            sub.get("status") != "active" or sub.get("collection_method") != "charge_automatically"
            or sub.get("pause_collection") is not None or sub.get("pending_update") is not None
            or sub.get("trial_start") is not None or sub.get("trial_end") is not None
        ):
            return denied
        items = _single_list(sub.get("items", {}))
        if len(items) != 1 or type(items[0].get("quantity")) is not int or items[0]["quantity"] != 1:
            return denied
        price = items[0].get("price")
        if type(price) is not dict or not self.valid_price(price):
            return denied
        start, end = sub.get("current_period_start"), sub.get("current_period_end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end:
            raise fail("period_rejected")
        invoice_id = identifier(sub.get("latest_invoice"), "in_")
        invoice = self.api.request("GET", "/v1/invoices/" + invoice_id)
        _test_object(invoice, "invoice", invoice_id)
        if invoice.get("customer") != customer or invoice.get("subscription") != subscription_id:
            raise fail("invoice_binding_rejected")
        if (
            invoice.get("status") != "paid" or invoice.get("paid") is not True
            or invoice.get("paid_out_of_band") is not False
            or invoice.get("currency") != "usd" or invoice.get("amount_remaining") != 0
            or any(type(invoice.get(key)) is not int or invoice[key] != AMOUNT
                   for key in ("amount_paid", "amount_due", "total"))
        ):
            return denied
        lines = _single_list(invoice.get("lines", {}))
        if (
            len(lines) != 1 or lines[0].get("type") != "subscription"
            or lines[0].get("subscription") != subscription_id
            or lines[0].get("proration") is not False
            or lines[0].get("period") != {"start": start, "end": end}
            or type(lines[0].get("price")) is not dict
            or lines[0]["price"].get("id") != self.config.price_id
        ):
            return denied
        intent_id = identifier(invoice.get("payment_intent"), "pi_")
        intent = self.api.request("GET", "/v1/payment_intents/" + intent_id)
        _test_object(intent, "payment_intent", intent_id)
        if (
            intent.get("status") != "succeeded" or intent.get("customer") != customer
            or intent.get("invoice") != invoice_id or intent.get("currency") != "usd"
            or intent.get("amount_received") != AMOUNT
        ):
            return denied
        charge_id = identifier(intent.get("latest_charge"), "ch_")
        charge = self.api.request("GET", "/v1/charges/" + charge_id)
        _test_object(charge, "charge", charge_id)
        if (
            charge.get("customer") != customer or charge.get("payment_intent") != intent_id
            or charge.get("paid") is not True or charge.get("status") != "succeeded"
            or charge.get("refunded") is not False or charge.get("disputed") is not False
            or charge.get("amount_refunded") != 0
        ):
            return denied
        access_until = end
        cancel_at = sub.get("cancel_at")
        if cancel_at is not None:
            if type(cancel_at) is not int:
                raise fail("cancellation_rejected")
            access_until = min(end, cancel_at)
        return PaidState(
            subscription_id, invoice_id, start, end,
            start <= self.clock() < access_until, access_until,
        )

    def valid_price(self, price: dict[str, Any]) -> bool:
        return (
            price.get("id") == self.config.price_id and price.get("livemode") is False
            and price.get("active") is True and price.get("type") == "recurring"
            and price.get("currency") == "usd" and type(price.get("unit_amount")) is int
            and price["unit_amount"] == AMOUNT
            and price.get("recurring") == {
                "aggregate_usage": None, "interval": "month", "interval_count": 1,
                "trial_period_days": None, "usage_type": "licensed",
            }
        )


class BillingStore(Protocol):
    def bind(self, tenant: str, customer: str) -> None: ...
    def customer(self, tenant: str) -> str: ...
    def reconcile(
        self, customer: str, load: Callable[[str | None], PaidState],
        *, event: tuple[str, str] | None = None,
    ) -> bool: ...
    def checkout(self, tenant: str, create: Callable[[str], dict[str, Any]]) -> str: ...


class BillingService:
    def __init__(self, authority: SubscriptionAuthority, store: BillingStore) -> None:
        self.authority, self.store = authority, store

    def bind(self, tenant: str, customer: str) -> None:
        if not _valid_customer_tenant(tenant):
            raise fail("tenant_rejected")
        self.authority.customer(customer)
        self.store.bind(tenant, customer)

    def checkout(self, tenant: str) -> str:
        def create(customer: str) -> dict[str, Any]:
            self.authority.customer(customer)
            existing = _single_list(self.authority.api.request(
                "GET", "/v1/subscriptions", {"customer": customer, "status": "all", "limit": "2"},
            ))
            if existing:
                raise fail("subscription_already_exists")
            price = self.authority.api.request("GET", "/v1/prices/" + self.authority.config.price_id)
            if not self.authority.valid_price(price):
                raise fail("price_rejected")
            return self.authority.api.request("POST", "/v1/checkout/sessions", {
                "mode": "subscription", "customer": customer,
                "line_items[0][price]": self.authority.config.price_id,
                "line_items[0][quantity]": "1",
                "success_url": self.authority.config.success_url,
                "cancel_url": self.authority.config.cancel_url,
                "payment_method_types[0]": "card", "allow_promotion_codes": "false",
            }, idempotency_key="gvai_checkout_" + customer)
        return self.store.checkout(tenant, create)

    def portal(self, tenant: str) -> str:
        customer = self.store.customer(tenant)
        self.authority.customer(customer)
        session = self.authority.api.request("POST", "/v1/billing_portal/sessions", {
            "customer": customer, "return_url": self.authority.config.return_url,
        })
        if session.get("object") != "billing_portal.session" or session.get("customer") != customer:
            raise fail("portal_binding_rejected")
        return https_url(session.get("url"), host="billing.stripe.com")

    def reconcile(self, tenant: str) -> bool:
        customer = self.store.customer(tenant)
        return self.store.reconcile(customer, lambda pinned: self.authority.current(customer, pinned))

    def webhook(self, raw: bytes, signature: str) -> None:
        event = verify_event(
            raw, signature, self.authority.config.webhook_secret, now=int(self.authority.clock()),
        )
        if event["type"] not in EVENT_TYPES:
            return
        value = event["data"]["object"]
        if event["type"] == "charge.dispute.created":
            charge = self.authority.api.request(
                "GET", "/v1/charges/" + identifier(value.get("charge"), "ch_"),
            )
            value = charge
        customer = identifier(
            value.get("id") if event["type"] == "customer.deleted" else value.get("customer"), "cus_",
        )
        self.store.reconcile(
            customer, lambda pinned: self.authority.current(customer, pinned),
            event=(event["id"], hashlib.sha256(raw).hexdigest()),
        )
