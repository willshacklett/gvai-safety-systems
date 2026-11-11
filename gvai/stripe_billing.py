"""Test-mode Stripe authority. Browser redirects and event payloads never grant access."""

from __future__ import annotations

from email.utils import parsedate_to_datetime
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


DENIAL_EVENTS = frozenset({
    "customer.subscription.deleted", "charge.dispute.created", "charge.refunded", "customer.deleted",
    "invoice.payment_failed", "invoice.voided", "invoice.marked_uncollectible",
})
TERMINAL_STATUSES = frozenset({"canceled", "incomplete_expired"})
_CODE = re.compile(r"[a-z0-9_]{1,64}\Z")


class BillingUnavailable(RuntimeError):
    """Redacted failure requiring retry or operator reconciliation.

    ``transient`` is True only for provider unavailability that proves nothing about the
    customer. Every other failure, including unknown ones, is treated as an integrity anomaly.
    """

    transient: bool
    code: str

    def __init__(self, message: str, *, transient: bool = False, code: str = "unspecified") -> None:
        super().__init__(message)
        self.transient = transient
        self.code = code if _CODE.fullmatch(code) else "unspecified"


def fail(event: str, *, transient: bool = False) -> BillingUnavailable:
    LOG.warning("stripe_billing: %s", event)
    return BillingUnavailable("Billing unavailable; reconcile before retry.", transient=transient, code=event)


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


def verify_event(raw: bytes, signature: str, secret: str, *, now: int, historical: bool = False) -> dict[str, Any]:
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
        or int(timestamps[0]) > now + 300
        or (not historical and abs(now - int(timestamps[0])) > 300)
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
        or type(event.get("created")) is not int or not 1 <= event["created"] <= now + 300
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
            type(self.secret_key) is not str or not self.secret_key.startswith(("sk_test_", "rk_test_"))
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


class StripeObject(dict):
    """A decoded Stripe response plus the authenticated Stripe-side time of that response."""

    stripe_date: int | None = None


def _response_date(value: str | None) -> int | None:
    if type(value) is not str or len(value) > 64:
        return None
    try:
        moment = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    return int(moment.timestamp()) if moment is not None and moment.tzinfo is not None else None


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
                    raise fail("stripe_response_rejected", transient=True)
                try:
                    value = StripeObject(decode(response.read(MAX_PAYLOAD + 1)))
                except BillingUnavailable:
                    raise fail("stripe_response_invalid", transient=True) from None
                value.stripe_date = _response_date(response.headers.get("Date"))
                return value
        except BillingUnavailable:
            raise
        except HTTPError as error:
            raise fail(
                "stripe_request_failed", transient=error.code in {401, 403, 408, 425, 429} or error.code >= 500,
            ) from None
        except (URLError, OSError, TimeoutError):
            raise fail("stripe_request_failed", transient=True) from None


@dataclass(frozen=True)
class PaidState:
    subscription: str | None = None
    invoice: str | None = None
    start: int | None = None
    end: int | None = None
    eligible: bool = False
    access_until: int | None = None
    observed_min: int | None = None
    observed_max: int | None = None
    terminal: bool = False


def _test_object(value: dict[str, Any], object_type: str, expected_id: str) -> None:
    if value.get("object") != object_type or value.get("id") != expected_id or value.get("livemode") is not False:
        raise fail("stripe_object_rejected")


def _single_list(value: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
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
        self._customer(self.api.request, customer)

    @staticmethod
    def _customer(get: Callable[..., Any], customer: str) -> None:
        customer = identifier(customer, "cus_")
        value = get("GET", "/v1/customers/" + customer)
        _test_object(value, "customer", customer)
        if value.get("deleted"):
            raise fail("customer_deleted")

    def current(
        self, customer: str, pinned_subscription: str | None, repin: bool = False,
    ) -> PaidState:
        """Read the customer's current Stripe state.

        Every response's Stripe ``Date`` is recorded. The reconciliation database accepts a
        positive snapshot only when the earliest of them is strictly after the newest verified
        webhook time it has seen, as an ordering check. A durable denial hold additionally requires explicit
        operator recovery with verified payment evidence.
        """
        dates: list[int | None] = []
        begin = getattr(self.api, "begin_fetch", None)
        if callable(begin):
            begin()

        def get(*args: Any, **kwargs: Any) -> Any:
            value = self.api.request(*args, **kwargs)
            dates.append(getattr(value, "stripe_date", None))
            return value

        def observed() -> dict[str, int | None]:
            if not dates or any(type(item) is not int for item in dates):
                return {"observed_min": None, "observed_max": None}
            return {"observed_min": min(dates), "observed_max": max(dates)}

        self._customer(get, customer)
        listed = get("GET", "/v1/subscriptions", {"customer": customer, "status": "all", "limit": "2"})
        if repin:
            if not isinstance(listed, dict) or listed.get("has_more") is not False or type(listed.get("data")) is not list \
                    or len(listed["data"]) > 2 or any(type(item) is not dict for item in listed["data"]):
                raise fail("ambiguous_subscription_state")
            subscriptions = [
                item for item in listed["data"]
                if pinned_subscription is None or item.get("id") != pinned_subscription
            ]
            if len(subscriptions) > 1:
                raise fail("ambiguous_subscription_state")
            if not subscriptions and pinned_subscription is not None:
                subscriptions = [item for item in listed["data"] if item.get("id") == pinned_subscription]
        else:
            subscriptions = _single_list(listed)
        if not subscriptions:
            return PaidState(**observed())
        subscription_id = identifier(subscriptions[0].get("id"), "sub_")
        if pinned_subscription is not None and subscription_id != pinned_subscription and not repin:
            raise fail("subscription_substitution_rejected")
        sub = get("GET", "/v1/subscriptions/" + subscription_id)
        _test_object(sub, "subscription", subscription_id)
        if sub.get("customer") != customer:
            raise fail("subscription_customer_mismatch")
        is_terminal = sub.get("status") in TERMINAL_STATUSES

        def deny() -> PaidState:
            return PaidState(subscription=subscription_id, terminal=is_terminal, **observed())

        if (
            sub.get("status") != "active" or sub.get("collection_method") != "charge_automatically"
            or sub.get("pause_collection") is not None or sub.get("pending_update") is not None
            or sub.get("trial_start") is not None or sub.get("trial_end") is not None
        ):
            return deny()
        items = _single_list(sub.get("items", {}))
        if len(items) != 1 or type(items[0].get("quantity")) is not int or items[0]["quantity"] != 1:
            return deny()
        price = items[0].get("price")
        if type(price) is not dict or not self.valid_price(price):
            return deny()
        start, end = sub.get("current_period_start"), sub.get("current_period_end")
        if type(start) is not int or type(end) is not int or not 0 <= start < end:
            raise fail("period_rejected")
        invoice_id = identifier(sub.get("latest_invoice"), "in_")
        invoice = get("GET", "/v1/invoices/" + invoice_id)
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
            return deny()
        lines = _single_list(invoice.get("lines", {}))
        if (
            len(lines) != 1 or lines[0].get("type") != "subscription"
            or lines[0].get("subscription") != subscription_id
            or lines[0].get("proration") is not False
            or lines[0].get("period") != {"start": start, "end": end}
            or type(lines[0].get("price")) is not dict
            or lines[0]["price"].get("id") != self.config.price_id
        ):
            return deny()
        intent_id = identifier(invoice.get("payment_intent"), "pi_")
        intent = get("GET", "/v1/payment_intents/" + intent_id)
        _test_object(intent, "payment_intent", intent_id)
        if (
            intent.get("status") != "succeeded" or intent.get("customer") != customer
            or intent.get("invoice") != invoice_id or intent.get("currency") != "usd"
            or intent.get("amount_received") != AMOUNT
        ):
            return deny()
        charge_id = identifier(intent.get("latest_charge"), "ch_")
        charge = get("GET", "/v1/charges/" + charge_id)
        _test_object(charge, "charge", charge_id)
        if (
            charge.get("customer") != customer or charge.get("payment_intent") != intent_id
            or charge.get("paid") is not True or charge.get("status") != "succeeded"
            or charge.get("refunded") is not False or charge.get("disputed") is not False
            or charge.get("amount_refunded") != 0
        ):
            return deny()
        access_until = end
        cancel_at = sub.get("cancel_at")
        if cancel_at is not None:
            if type(cancel_at) is not int:
                raise fail("cancellation_rejected")
            access_until = min(end, cancel_at)
        return PaidState(
            subscription_id, invoice_id, start, end,
            start <= self.clock() < access_until, access_until, **observed(),
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


def verified_recovery_event(raw: bytes, signature: str, config: BillingConfig, now: int) -> dict[str, Any]:
    """Only a signed TEST invoice payment can attest recovery; Dates cannot attest it."""
    event = verify_event(raw, signature, config.webhook_secret, now=now, historical=True)
    value = event["data"]["object"]
    if (event["type"] != "invoice.paid" or value.get("object") != "invoice"
            or value.get("livemode") is not False or value.get("status") != "paid"
            or value.get("paid") is not True or value.get("paid_out_of_band") is not False):
        raise fail("recovery_evidence_rejected")
    identifier(value.get("id"), "in_")
    identifier(value.get("customer"), "cus_")
    identifier(value.get("subscription"), "sub_")
    transitions = value.get("status_transitions")
    paid_at = transitions.get("paid_at") if type(transitions) is dict else None
    if type(paid_at) is not int or not 1 <= paid_at <= event["created"]:
        raise fail("recovery_payment_time_rejected")
    return event


class BillingStore(Protocol):
    def bind(self, tenant: str, customer: str) -> None: ...
    def customer(self, tenant: str) -> str: ...
    def reconcile(
        self, customer: str, load: Callable[[str | None, bool], PaidState],
        *, event: tuple[str, str, int, bool] | tuple[str, str, int, bool, str | None, str | None] | None = None,
    ) -> bool: ...
    def checkout(self, tenant: str, create: Callable[[str, int, bool], dict[str, Any]]) -> str: ...


class BillingService:
    def __init__(self, authority: SubscriptionAuthority, store: BillingStore) -> None:
        self.authority, self.store = authority, store

    def bind(self, tenant: str, customer: str) -> None:
        if not _valid_customer_tenant(tenant):
            raise fail("tenant_rejected")
        self.authority.customer(customer)
        self.store.bind(tenant, customer)

    def checkout(self, tenant: str) -> str:
        def create(customer: str, generation: int, repin: bool) -> dict[str, Any]:
            self.authority.customer(customer)
            listed = self.authority.api.request(
                "GET", "/v1/subscriptions", {"customer": customer, "status": "all", "limit": "2"},
            )
            if not isinstance(listed, dict) or listed.get("has_more") is not False \
                    or type(listed.get("data")) is not list or len(listed["data"]) > 2:
                raise fail("ambiguous_subscription_state")
            # Only a terminal subscription may already exist, and only when the database has
            # opened the resubscription (repin); anything else is rejected.
            if listed["data"] and (not repin or any(
                type(item) is not dict or item.get("status") not in TERMINAL_STATUSES
                for item in listed["data"]
            )):
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
            }, idempotency_key="gvai_checkout_" + customer + ("" if generation == 0 else "_g%d" % generation))
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
        return self.store.reconcile(
            customer, lambda pinned, repin: self.authority.current(customer, pinned, repin),
        )

    def webhook(self, raw: bytes, signature: str) -> None:
        event = verify_event(
            raw, signature, self.authority.config.webhook_secret, now=int(self.authority.clock()),
        )
        if event["type"] not in EVENT_TYPES:
            return
        value = event["data"]["object"]
        scope_sub = scope_invoice = None
        denial = event["type"] in DENIAL_EVENTS
        scoped = event["type"].startswith(("charge.", "invoice.")) and denial
        # A minimal customer-only notification can wake polling, but carries no
        # transaction identity and therefore cannot itself attest a denial.
        if scoped and set(value) == {"customer"}:
            denial = scoped = False
        if event["type"] == "charge.dispute.created":
            charge = self.authority.api.request(
                "GET", "/v1/charges/" + identifier(value.get("charge"), "ch_"),
            )
            _test_object(charge, "charge", identifier(value.get("charge"), "ch_"))
            value = charge
        if scoped:
            if event["type"].startswith("charge."):
                if value.get("object") != "charge" or value.get("livemode") is not False:
                    raise fail("denial_charge_rejected")
                intent_id = identifier(value.get("payment_intent"), "pi_")
                intent = self.authority.api.request("GET", "/v1/payment_intents/" + intent_id)
                _test_object(intent, "payment_intent", intent_id)
                scope_invoice = identifier(intent.get("invoice"), "in_")
                invoice = self.authority.api.request("GET", "/v1/invoices/" + scope_invoice)
                _test_object(invoice, "invoice", scope_invoice)
                if (intent.get("latest_charge") != value.get("id")
                        or intent.get("customer") != value.get("customer")
                        or invoice.get("customer") != value.get("customer")
                        or invoice.get("payment_intent") != intent_id):
                    raise fail("denial_binding_rejected")
                value = invoice
            else:
                if value.get("object") != "invoice" or value.get("livemode") is not False:
                    raise fail("denial_invoice_rejected")
                scope_invoice = identifier(value.get("id"), "in_")
            scope_sub = identifier(value.get("subscription"), "sub_")
        elif event["type"] == "customer.subscription.deleted":
            scope_sub = identifier(value.get("id"), "sub_")
            scoped = True
        customer = identifier(
            value.get("id") if event["type"] == "customer.deleted" else value.get("customer"), "cus_",
        )
        self.store.reconcile(
            customer, lambda pinned, repin: self.authority.current(customer, pinned, repin),
            event=(event["id"], hashlib.sha256(raw).hexdigest(), event["created"], denial)
                + ((scope_sub, scope_invoice) if scoped else ()),
        )
