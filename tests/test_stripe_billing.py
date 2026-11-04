"""Synthetic Stripe/transaction models. These do not execute PostgreSQL or Stripe."""

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import hmac
from http.client import HTTPConnection
import json
from pathlib import Path
import threading

import pytest

from gvai.billing_operator import _handoff, main
from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore, api_key_credential_material
from gvai.commercial_http import create_webhook_server
from gvai.commercial_identity import CommercialCapability
from gvai.commercial_reservation_authority import AuthorityIdentity, CanonicalReservationRequest
from gvai.commercial_service import CommercialEvaluationService
from gvai.commercial_usage import UsageReason
from gvai.postgresql_billing import PostgreSQLBillingStore, PostgreSQLPaidUsage
from gvai.stripe_billing import (
    ALLOWANCE, API_VERSION, BillingConfig, BillingService, BillingUnavailable,
    PaidState, StripeREST, SubscriptionAuthority, _NoRedirect, verify_event,
)


NOW = 1_800_000_000
SECRET = b"synthetic-key-verifier-secret-32-bytes"
SIGNING = "whsec_synthetic_signing_secret"
AUTHORITY = AuthorityIdentity("billing-test", 1, "disposable")
TELEMETRY = {
    "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
    "repeated_action_delta": 0, "recursion_depth": 0,
}


def config():
    return BillingConfig(
        "sk_test_synthetic_never_sent", SIGNING, "price_test",
        "https://example.test/success", "https://example.test/cancel",
        "https://example.test/billing",
    )


def timestamp(value):
    return datetime.fromtimestamp(value, timezone.utc)


def event(kind="invoice.paid", event_id="evt_test", customer="cus_a", **claims):
    raw = json.dumps({
        "object": "event", "id": event_id, "type": kind, "livemode": False,
        "api_version": API_VERSION, "data": {"object": {"customer": customer, **claims}},
    }).encode()
    signature = hmac.new(SIGNING.encode(), str(NOW).encode() + b"." + raw, hashlib.sha256).hexdigest()
    return raw, f"t={NOW},v1={signature}"


class Stripe:
    def __init__(self):
        self.calls = []
        self.objects = {}
        self.subscriptions = {}
        self.failure = False
        self.add("a")
        self.add("b")

    def add(self, label):
        customer, sub, invoice, intent, charge = (
            prefix + label for prefix in ("cus_", "sub_", "in_", "pi_", "ch_")
        )
        price = {
            "id": "price_test", "livemode": False, "active": True, "type": "recurring",
            "currency": "usd", "unit_amount": 9900,
            "recurring": {"aggregate_usage": None, "interval": "month", "interval_count": 1,
                          "trial_period_days": None, "usage_type": "licensed"},
        }
        self.objects["/v1/prices/price_test"] = price
        self.objects["/v1/customers/" + customer] = {
            "id": customer, "object": "customer", "livemode": False,
        }
        self.subscriptions[customer] = [{"id": sub}]
        self.objects["/v1/subscriptions/" + sub] = {
            "id": sub, "object": "subscription", "livemode": False, "customer": customer,
            "status": "active", "collection_method": "charge_automatically",
            "items": {"data": [{"quantity": 1, "price": price}], "has_more": False},
            "current_period_start": NOW - 100, "current_period_end": NOW + 1000,
            "latest_invoice": invoice,
        }
        self.objects["/v1/invoices/" + invoice] = {
            "id": invoice, "object": "invoice", "livemode": False, "customer": customer,
            "subscription": sub, "status": "paid", "paid": True, "paid_out_of_band": False,
            "currency": "usd", "amount_paid": 9900, "amount_due": 9900,
            "total": 9900, "amount_remaining": 0, "payment_intent": intent,
            "lines": {"has_more": False, "data": [{
                "type": "subscription", "subscription": sub, "proration": False,
                "period": {"start": NOW - 100, "end": NOW + 1000}, "price": price,
            }]},
        }
        self.objects["/v1/payment_intents/" + intent] = {
            "id": intent, "object": "payment_intent", "livemode": False,
            "customer": customer, "invoice": invoice, "status": "succeeded",
            "currency": "usd", "amount_received": 9900, "latest_charge": charge,
        }
        self.objects["/v1/charges/" + charge] = {
            "id": charge, "object": "charge", "livemode": False, "customer": customer,
            "payment_intent": intent, "paid": True, "status": "succeeded",
            "refunded": False, "disputed": False, "amount_refunded": 0,
        }

    def request(self, method, path, parameters=None, *, idempotency_key=None):
        self.calls.append((method, path, parameters, idempotency_key))
        if self.failure:
            raise BillingUnavailable("Synthetic outage.")
        if path == "/v1/subscriptions":
            return {"has_more": False, "data": copy.deepcopy(self.subscriptions[parameters["customer"]])}
        if path == "/v1/checkout/sessions":
            return {
                "id": "cs_test_checkout", "object": "checkout.session", "livemode": False,
                "customer": parameters["customer"], "mode": "subscription",
                "url": "https://checkout.stripe.com/c/pay/synthetic",
            }
        if path == "/v1/billing_portal/sessions":
            return {"object": "billing_portal.session", "customer": parameters["customer"],
                    "url": "https://billing.stripe.com/p/session/synthetic"}
        return copy.deepcopy(self.objects[path])


class Database:
    """Serialized transaction model; NOT proof of PostgreSQL locking or triggers."""

    def __init__(self):
        self.lock = threading.RLock()
        self.now = NOW
        self.customers = {}
        self.periods = {}
        self.events = {}
        self.attempts = {}
        self.keys = {}
        self.disabled = set()
        self.fail_commit = False

    def connect(self):
        return Connection(self)


class Connection:
    def __init__(self, database):
        self.db = database

    def __enter__(self):
        self.db.lock.acquire()
        self.before = copy.deepcopy((
            self.db.customers, self.db.periods, self.db.events, self.db.attempts,
        ))
        return self

    def __exit__(self, kind, value, trace):
        try:
            if kind is not None:
                self.db.customers, self.db.periods, self.db.events, self.db.attempts = self.before
            elif self.db.fail_commit:
                raise OSError("synthetic-secret-commit-acknowledgement-loss")
        finally:
            self.db.lock.release()

    def cursor(self):
        return Cursor(self.db)


class Cursor:
    def __init__(self, db):
        self.db = db
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def fetchone(self):
        return self.row

    def execute(self, sql, p=()):
        db = self.db
        self.row = None
        if sql.startswith("SAVEPOINT"):
            self.snapshot = copy.deepcopy((db.customers, db.periods))
        elif sql.startswith("ROLLBACK TO"):
            db.customers, db.periods = self.snapshot
        elif sql.startswith("SELECT tenant_ref FROM"):
            self.row = ({"tenant-a": 1, "tenant-b": 2}[p[0]],) if p[0] in {"tenant-a", "tenant-b"} else None
        elif sql.startswith("INSERT INTO gvai_authority.billing_customers"):
            tenant, customer = p
            if any(row["tenant"] != tenant and name == customer for name, row in db.customers.items()):
                raise ValueError("unique customer")
            if not any(row["tenant"] == tenant for row in db.customers.values()):
                db.customers[customer] = {
                    "tenant": tenant, "subscription": None, "revoked": False,
                    "eligible": False, "invoice": None, "verified": 0, "access": 0,
                    "checkout_started": None, "session": None, "url": None,
                }
        elif sql.startswith("SELECT customer_id FROM"):
            self.row = next(((name,) for name, row in db.customers.items() if row["tenant"] == p[0]), None)
        elif sql.startswith("SELECT b.customer_id"):
            tenant = {"tenant-a": 1, "tenant-b": 2}.get(p[0])
            self.row = next(((name,) for name, row in db.customers.items() if row["tenant"] == tenant), None)
        elif sql.startswith("SELECT b.tenant_ref"):
            row = db.customers.get(p[0])
            self.row = (row["tenant"], row["subscription"], row["revoked"]) if row else None
        elif sql.startswith("SELECT tenant_ref,payload_hash"):
            self.row = db.events.get(p[0])
        elif sql.startswith("SELECT extract"):
            self.row = (db.now,)
        elif sql.startswith("SELECT invoice_id FROM"):
            tenant, end, start, invoice = p
            self.row = next(((name,) for name, row in db.periods.items()
                             if row["tenant"] == tenant and row["start"] < end
                             and row["end"] > start and name != invoice), None)
        elif sql.startswith("INSERT INTO gvai_authority.billing_periods"):
            invoice, tenant, sub, start, end = p
            db.periods.setdefault(invoice, {
                "tenant": tenant, "sub": sub, "start": start, "end": end,
                "allowance": ALLOWANCE, "consumed": 0,
            })
        elif sql.startswith("SELECT tenant_ref,subscription_id"):
            row = db.periods.get(p[0])
            self.row = (row["tenant"], row["sub"], row["start"], row["end"], row["allowance"]) if row else None
        elif sql.startswith("UPDATE gvai_authority.billing_customers SET subscription"):
            sub, invoice, eligible, verified, access, tenant = p
            row = next(row for row in db.customers.values() if row["tenant"] == tenant)
            row.update(subscription=sub, invoice=invoice, eligible=eligible,
                       verified=verified.timestamp(), access=access.timestamp())
        elif sql.startswith("UPDATE gvai_authority.billing_customers SET eligible"):
            row = next(row for row in db.customers.values() if row["tenant"] == p[0])
            row.update(eligible=False, verified=0)
        elif sql.startswith("UPDATE gvai_authority.billing_customers SET revoked"):
            row = db.customers[p[0]]
            row.update(revoked=True, eligible=False)
            self.row = (row["tenant"],)
        elif sql.startswith("INSERT INTO gvai_authority.billing_events"):
            db.events[p[0]] = (p[1], p[2])
        elif "SET checkout_started_at=" in sql:
            row = db.customers[p[0]]
            if row["checkout_started"] is None:
                row["checkout_started"] = db.now
        elif sql.startswith("SELECT checkout_session_id"):
            row = db.customers[p[0]]
            self.row = (row["session"], row["url"], row["checkout_started"] > db.now - 23 * 3600)
        elif sql.startswith("UPDATE gvai_authority.billing_customers SET checkout_session_id"):
            db.customers[p[2]].update(session=p[0], url=p[1])
        elif sql.startswith("SELECT gvai_authority.reserve_paid_v1"):
            self.row = (self.reserve(p),)
        elif sql.startswith("SELECT gvai_authority.complete_paid_v1"):
            identity = self.authenticate(p[0], p[1], p[2])
            if identity is None:
                self.row = ("unauthorized",)
            else:
                key = (identity[0], hashlib.sha256(p[3].encode()).hexdigest())
                prior = db.attempts.get(key)
                target = "completed" if p[4] else "failed"
                if prior is None:
                    self.row = ("not_found",)
                elif prior["resource"] != p[2]:
                    self.row = ("not_found",)
                elif prior["state"] == target:
                    self.row = ("replay",)
                elif prior["state"] != "reserved":
                    self.row = ("conflict",)
                else:
                    prior["state"] = target
                    self.row = (target,)
        elif sql.startswith("SELECT * FROM gvai_authority.paid_usage"):
            identity = self.authenticate(*p)
            if identity is not None:
                _, invoice = identity
                states = [a["state"] for a in db.attempts.values() if a["invoice"] == invoice]
                self.row = (ALLOWANCE, db.periods[invoice]["consumed"],
                            states.count("reserved"), states.count("completed"), states.count("failed"))
        else:
            raise AssertionError("Unexpected SQL: " + sql)

    def authenticate(self, key, verifier, resource):
        db = self.db
        identity = db.keys.get(key)
        if identity is None or identity["verifier"] != verifier or identity["revoked"]:
            return None
        if identity["resource"] != resource or identity["expiry"] <= db.now:
            return None
        tenant = identity["tenant"]
        row = next((row for row in db.customers.values() if row["tenant"] == tenant), None)
        if (
            row is None or tenant in db.disabled or row["revoked"] or not row["eligible"]
            or row["verified"] <= db.now or row["access"] <= db.now or row["invoice"] is None
        ):
            return None
        return tenant, row["invoice"]

    def reserve(self, p):
        identity = self.authenticate(p[0], p[1], p[6])
        if identity is None or tuple(p[2:5]) != (AUTHORITY.authority_id, AUTHORITY.epoch, AUTHORITY.trust_domain):
            return "unauthorized"
        tenant, invoice = identity
        request = CanonicalReservationRequest(p[5], p[6], p[7])
        key = (tenant, hashlib.sha256(p[5].encode()).hexdigest())
        prior = self.db.attempts.get(key)
        if prior is not None:
            return "replay" if prior["digest"] == request.request_digest else "conflict"
        period = self.db.periods[invoice]
        if period["consumed"] >= ALLOWANCE:
            return "quota_exhausted"
        period["consumed"] += 1
        self.db.attempts[key] = {
            "invoice": invoice, "digest": request.request_digest,
            "resource": p[6], "state": "reserved",
        }
        return "reserved"


@pytest.fixture
def setup():
    stripe, db = Stripe(), Database()
    store = PostgreSQLBillingStore(db.connect)
    authority = SubscriptionAuthority(stripe, config(), clock=lambda: db.now)
    service = BillingService(authority, store)
    credentials = {}
    keys = CustomerApiKeys(InMemoryApiKeyStore(), verifier_secret=SECRET, clock=lambda: db.now)
    for label, tenant in (("a", 1), ("b", 2)):
        service.bind("tenant-" + label, "cus_" + label)
        issued = keys.issue(
            tenant_id="tenant-" + label, principal_id="principal-" + label,
            capabilities=frozenset(CommercialCapability), expires_at=NOW + 100000,
        )
        credential = issued.take_secret()
        key, verifier = api_key_credential_material(credential, SECRET)
        db.keys[key] = {
            "tenant": tenant, "resource": "project-" + label, "verifier": verifier,
            "revoked": False, "expiry": NOW + 100000,
        }
        credentials[label] = credential
    usage = PostgreSQLPaidUsage(db.connect, authority=AUTHORITY, credential_verifier_secret=SECRET)
    return stripe, db, service, store, usage, credentials


def paid(setup, kind="invoice.paid", identifier="evt_test"):
    setup[2].webhook(*event(kind, identifier))


def test_paid_invoice_and_active_subscription_enable_advisory_only(setup):
    stripe, db, service, store, usage, credentials = setup
    assert usage.reserve_evaluation(credentials["a"], "project-a", "before", b"x").reason is UsageReason.UNAUTHORIZED
    paid(setup)
    result = CommercialEvaluationService(usage).evaluate(credentials["a"], "project-a", "one", TELEMETRY, [])
    assert result.evaluation.advisory_only is True
    assert result.evaluation.enforcement_applied is False
    summary = usage.summary(credentials["a"], "project-a")
    assert (summary.allowance, summary.consumed, summary.completed) == (100000, 1, 1)
    assert db.customers["cus_a"]["subscription"] == "sub_a"
    assert db.periods["in_a"]["tenant"] == 1


@pytest.mark.parametrize("kind", ["checkout.session.completed", "invoice.paid", "customer.subscription.updated"])
def test_forged_payment_claim_does_not_grant(setup, kind):
    stripe, db, service, store, usage, credentials = setup
    stripe.objects["/v1/invoices/in_a"].update(paid=False, status="open")
    service.webhook(*event(kind, payment_status="paid", paid=True, tenant_id="tenant-b"))
    assert not db.customers["cus_a"]["eligible"]
    assert not db.periods


@pytest.mark.parametrize("change", [
    {"status": "past_due"}, {"status": "canceled"}, {"status": "trialing"},
    {"status": "unpaid"}, {"status": "incomplete_expired"},
    {"pause_collection": {"behavior": "void"}}, {"pending_update": {"changes": True}},
])
def test_subscription_non_active_or_uncertain_denies(setup, change):
    paid(setup)
    setup[0].objects["/v1/subscriptions/sub_a"].update(change)
    setup[2].webhook(*event("customer.subscription.updated", "evt_changed"))
    assert not setup[1].customers["cus_a"]["eligible"]


@pytest.mark.parametrize("path,change", [
    ("/v1/invoices/in_a", {"paid_out_of_band": True}),
    ("/v1/invoices/in_a", {"amount_paid": 0}),
    ("/v1/invoices/in_a", {"customer": "cus_b"}),
    ("/v1/invoices/in_a", {"subscription": "sub_b"}),
    ("/v1/payment_intents/pi_a", {"status": "processing"}),
    ("/v1/payment_intents/pi_a", {"invoice": "in_b"}),
    ("/v1/charges/ch_a", {"refunded": True}),
    ("/v1/charges/ch_a", {"disputed": True}),
])
def test_payment_binding_and_collection_rejections(setup, path, change):
    setup[0].objects[path].update(change)
    try:
        paid(setup)
    except BillingUnavailable:
        pass
    assert not setup[1].customers["cus_a"]["eligible"]


def test_duplicate_event_has_no_external_calls_or_counter_reset(setup):
    paid(setup)
    stripe, db, service, store, usage, credentials = setup
    assert usage.reserve_evaluation(credentials["a"], "project-a", "one", b"x").may_evaluate
    before = len(stripe.calls)
    paid(setup)
    assert len(stripe.calls) == before
    assert db.periods["in_a"]["consumed"] == 1
    assert len(db.events) == 1


def test_reordered_failure_then_old_paid_event_reads_current_state(setup):
    paid(setup)
    stripe, db, service, *_ = setup
    stripe.objects["/v1/subscriptions/sub_a"]["status"] = "past_due"
    paid(setup, "invoice.payment_failed", "evt_failed")
    paid(setup, "invoice.paid", "evt_old_paid")
    assert not db.customers["cus_a"]["eligible"]
    stripe.objects["/v1/subscriptions/sub_a"]["status"] = "active"
    paid(setup, "invoice.paid", "evt_recovered")
    paid(setup, "invoice.payment_failed", "evt_old_failure")
    assert db.customers["cus_a"]["eligible"]
    assert len(db.periods) == 1


def test_outage_suspends_without_acknowledging_event_then_retry_recovers(setup, caplog):
    paid(setup)
    setup[0].failure = True
    with pytest.raises(BillingUnavailable):
        paid(setup, identifier="evt_retry")
    assert not setup[1].customers["cus_a"]["eligible"]
    assert "evt_retry" not in setup[1].events
    setup[0].failure = False
    paid(setup, identifier="evt_retry")
    assert setup[1].customers["cus_a"]["eligible"]
    assert config().secret_key not in caplog.text


def test_cancellation_paid_through_and_freshness_expiry(setup):
    stripe, db, service, store, usage, credentials = setup
    stripe.objects["/v1/subscriptions/sub_a"].update(cancel_at_period_end=True, cancel_at=NOW + 1000)
    paid(setup)
    assert usage.reserve_evaluation(credentials["a"], "project-a", "one", b"x").may_evaluate
    db.now += 60
    assert usage.reserve_evaluation(credentials["a"], "project-a", "stale", b"x").reason is UsageReason.UNAUTHORIZED
    service.reconcile("tenant-a")
    assert usage.reserve_evaluation(credentials["a"], "project-a", "fresh", b"x").may_evaluate
    db.now = NOW + 1000
    service.reconcile("tenant-a")
    assert usage.reserve_evaluation(credentials["a"], "project-a", "expired", b"x").reason is UsageReason.UNAUTHORIZED


def test_operator_billing_revocation_is_sticky(setup):
    paid(setup)
    setup[3].revoke("tenant-a")
    paid(setup, identifier="evt_later")
    assert setup[1].customers["cus_a"]["revoked"]
    assert not setup[1].customers["cus_a"]["eligible"]


def test_key_revocation_and_tenant_isolation(setup):
    paid(setup)
    stripe, db, service, store, usage, credentials = setup
    assert usage.reserve_evaluation(credentials["b"], "project-a", "foreign", b"x").reason is UsageReason.UNAUTHORIZED
    assert usage.summary(credentials["a"], "project-b") is None
    key, _ = api_key_credential_material(credentials["a"], SECRET)
    db.keys[key]["revoked"] = True
    assert usage.reserve_evaluation(credentials["a"], "project-a", "revoked", b"x").reason is UsageReason.UNAUTHORIZED
    assert usage.complete(credentials["a"], "project-a", "revoked", succeeded=True).reason is UsageReason.UNAUTHORIZED
    assert usage.summary(credentials["a"], "project-a") is None
    with pytest.raises(BillingUnavailable):
        service.bind("tenant-b", "cus_a")


def test_subscription_substitution_and_event_collision_fail_closed(setup):
    paid(setup)
    with pytest.raises(BillingUnavailable):
        setup[2].webhook(*event("invoice.payment_failed", "evt_test"))
    setup[0].subscriptions["cus_a"] = [{"id": "sub_b"}]
    with pytest.raises(BillingUnavailable):
        paid(setup, identifier="evt_substitute")
    assert not setup[1].customers["cus_a"]["eligible"]


def test_final_unit_race_and_duplicate_race_transaction_model(setup):
    paid(setup)
    _, db, _, _, usage, credentials = setup
    db.periods["in_a"]["consumed"] = 99999
    with ThreadPoolExecutor(8) as executor:
        results = list(executor.map(
            lambda n: usage.reserve_evaluation(credentials["a"], "project-a", "race-" + str(n), b"x"),
            range(8),
        ))
    assert sum(result.may_evaluate for result in results) == 1
    assert db.periods["in_a"]["consumed"] == 100000
    assert sum(result.reason is UsageReason.QUOTA_EXHAUSTED for result in results) == 7


def test_duplicate_race_replay_conflict_and_no_refunds(setup):
    paid(setup)
    _, db, _, _, usage, credentials = setup
    with ThreadPoolExecutor(8) as executor:
        results = list(executor.map(
            lambda _: usage.reserve_evaluation(credentials["a"], "project-a", "same", b"x"), range(8),
        ))
    assert sum(result.may_evaluate for result in results) == 1
    assert sum(result.reason is UsageReason.REPLAY for result in results) == 7
    assert usage.reserve_evaluation(credentials["a"], "project-a", "same", b"changed").reason is UsageReason.CONFLICT
    assert usage.complete(credentials["a"], "project-a", "same", succeeded=False).reason is UsageReason.FAILED
    assert usage.complete(credentials["a"], "project-a", "same", succeeded=True).reason is UsageReason.CONFLICT
    assert db.periods["in_a"]["consumed"] == 1


def test_renewal_uses_new_period_without_resetting_history(setup):
    paid(setup)
    stripe, db, service, store, usage, credentials = setup
    assert usage.reserve_evaluation(credentials["a"], "project-a", "old", b"x").may_evaluate
    old_period = copy.deepcopy(db.periods["in_a"])
    db.now = NOW + 1000
    sub = stripe.objects["/v1/subscriptions/sub_a"]
    sub.update(current_period_start=NOW + 1000, current_period_end=NOW + 2000, latest_invoice="in_renewal")
    invoice = copy.deepcopy(stripe.objects["/v1/invoices/in_a"])
    invoice.update(id="in_renewal", payment_intent="pi_renewal")
    invoice["lines"]["data"][0]["period"] = {"start": NOW + 1000, "end": NOW + 2000}
    stripe.objects["/v1/invoices/in_renewal"] = invoice
    intent = copy.deepcopy(stripe.objects["/v1/payment_intents/pi_a"])
    intent.update(id="pi_renewal", invoice="in_renewal", latest_charge="ch_renewal")
    stripe.objects["/v1/payment_intents/pi_renewal"] = intent
    charge = copy.deepcopy(stripe.objects["/v1/charges/ch_a"])
    charge.update(id="ch_renewal", payment_intent="pi_renewal")
    stripe.objects["/v1/charges/ch_renewal"] = charge
    service.reconcile("tenant-a")
    assert db.periods["in_a"] == old_period
    assert usage.reserve_evaluation(credentials["a"], "project-a", "old", b"x").reason is UsageReason.REPLAY
    assert usage.reserve_evaluation(credentials["a"], "project-a", "new", b"x").may_evaluate
    assert db.periods["in_renewal"]["consumed"] == 1


def test_checkout_server_controlled_and_portal_mapping(setup):
    stripe, db, service, store, usage, credentials = setup
    stripe.subscriptions["cus_a"] = []
    assert service.checkout("tenant-a").startswith("https://checkout.stripe.com/")
    call = next(call for call in stripe.calls if call[1] == "/v1/checkout/sessions")
    assert call[2]["line_items[0][price]"] == "price_test"
    assert call[2]["customer"] == "cus_a" and call[2]["mode"] == "subscription"
    assert call[3] == "gvai_checkout_cus_a"
    assert not db.customers["cus_a"]["eligible"]
    assert service.checkout("tenant-a").startswith("https://checkout.stripe.com/")
    assert sum(call[1] == "/v1/checkout/sessions" for call in stripe.calls) == 1
    assert service.portal("tenant-b").startswith("https://billing.stripe.com/")
    assert stripe.calls[-1][2]["customer"] == "cus_b"
    with pytest.raises(BillingUnavailable):
        service.portal("tenant-missing")


def test_checkout_uncertain_retry_window_and_existing_subscription(setup):
    with pytest.raises(BillingUnavailable):
        setup[2].checkout("tenant-a")
    setup[0].subscriptions["cus_a"] = []
    setup[1].now += 23 * 3600
    with pytest.raises(BillingUnavailable):
        setup[2].checkout("tenant-a")
    assert not any(call[1] == "/v1/checkout/sessions" for call in setup[0].calls)


@pytest.mark.parametrize("mutate", [
    lambda raw, sig: (raw + b" ", sig),
    lambda raw, sig: (raw, sig.replace("v1=", "v0=")),
    lambda raw, sig: (raw, sig + ",t=" + str(NOW)),
    lambda raw, sig: (raw, sig.replace(str(NOW), str(NOW - 301))),
    lambda raw, sig: (raw, "t=0,v1=" + "0" * 64),
])
def test_signature_rejections_before_external_calls(setup, mutate):
    before = len(setup[0].calls)
    with pytest.raises(BillingUnavailable):
        setup[2].webhook(*mutate(*event()))
    assert len(setup[0].calls) == before
    assert not setup[1].events


@pytest.mark.parametrize("raw", [
    b'{"a":1,"a":2}', b'{"a":NaN}', b"[]" , b"x" * 65537, b"\xff",
])
def test_malformed_signed_events_rejected(raw):
    signature = hmac.new(SIGNING.encode(), str(NOW).encode() + b"." + raw, hashlib.sha256).hexdigest()
    with pytest.raises(BillingUnavailable):
        verify_event(raw, f"t={NOW},v1={signature}", SIGNING, now=NOW)


def test_live_mode_keys_and_objects_rejected(setup):
    with pytest.raises(BillingUnavailable):
        BillingConfig("sk_live_never_allowed", SIGNING, "price_test",
                      "https://example.test/ok", "https://example.test/no", "https://example.test/back")
    setup[0].objects["/v1/customers/cus_a"]["livemode"] = True
    with pytest.raises(BillingUnavailable):
        paid(setup)
    assert not setup[1].customers["cus_a"]["eligible"]
    assert config().secret_key not in repr(config())


def test_rest_transport_pins_origin_version_and_bounds_without_external_calls():
    client = StripeREST(config())

    class Response:
        status = 200
        raw = b'{"object":"customer","livemode":false}'

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, size):
            assert size == 65537
            return self.raw[:size]

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://api.stripe.com/v1/customers/cus_a"
            assert request.get_header("Stripe-version") == API_VERSION
            assert request.get_header("Authorization") == "Bearer " + config().secret_key
            assert timeout == 5
            return Response()

    client._opener = Opener()
    assert client.request("GET", "/v1/customers/cus_a")["livemode"] is False
    with pytest.raises(BillingUnavailable):
        client.request("GET", "//evil.test/v1/customers")
    Response.raw = b"x" * 65537
    with pytest.raises(BillingUnavailable):
        client.request("GET", "/v1/customers/cus_a")
    with pytest.raises(BillingUnavailable):
        _NoRedirect().redirect_request(None, None, None, None, None, None)


def test_unknown_signed_customer_and_multiple_subscriptions_never_create_entitlements(setup):
    with pytest.raises(BillingUnavailable):
        setup[2].webhook(*event(customer="cus_unknown"))
    setup[0].subscriptions["cus_a"] = [{"id": "sub_a"}, {"id": "sub_b"}]
    with pytest.raises(BillingUnavailable):
        paid(setup)
    assert not setup[1].periods


def test_invoice_replacement_cannot_refresh_an_existing_period_allowance(setup):
    paid(setup)
    stripe, db, service, store, usage, credentials = setup
    assert usage.reserve_evaluation(credentials["a"], "project-a", "one", b"x").may_evaluate
    state = PaidState("sub_a", "in_different", NOW - 100, NOW + 1000, True, NOW + 1000)
    with pytest.raises(BillingUnavailable):
        store.reconcile("cus_a", lambda _: state)
    assert db.periods["in_a"]["consumed"] == 1
    assert "in_different" not in db.periods
    assert not db.customers["cus_a"]["eligible"]


def test_expired_key_disabled_tenant_and_shortened_cancel_at_deny(setup):
    paid(setup)
    stripe, db, service, store, usage, credentials = setup
    stripe.objects["/v1/subscriptions/sub_a"]["cancel_at"] = NOW + 10
    service.reconcile("tenant-a")
    db.now += 10
    assert usage.reserve_evaluation(credentials["a"], "project-a", "cancelled", b"x").reason is UsageReason.UNAUTHORIZED
    db.now = NOW
    service.reconcile("tenant-a")
    db.disabled.add(1)
    assert usage.reserve_evaluation(credentials["a"], "project-a", "disabled", b"x").reason is UsageReason.UNAUTHORIZED
    db.disabled.clear()
    key, _ = api_key_credential_material(credentials["a"], SECRET)
    db.keys[key]["expiry"] = NOW
    assert usage.reserve_evaluation(credentials["a"], "project-a", "expired-key", b"x").reason is UsageReason.UNAUTHORIZED


def test_commit_acknowledgement_loss_withholds_evaluation(setup, caplog):
    paid(setup)
    setup[1].fail_commit = True
    result = CommercialEvaluationService(setup[4]).evaluate(setup[5]["a"], "project-a", "lost", TELEMETRY, [])
    assert result.evaluation is None and result.reason.value == "accounting_failure"
    setup[1].fail_commit = False
    assert setup[4].reserve_evaluation(
        setup[5]["a"], "project-a", "lost",
        json.dumps({"version": "gvai-evaluation-v1"}, sort_keys=True).encode(),
    ).reason in {UsageReason.CONFLICT, UsageReason.REPLAY}
    assert "synthetic-secret-commit" not in caplog.text


def test_bounded_webhook_http_and_no_management_routes(setup):
    server = create_webhook_server(setup[2].webhook)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    raw, signature = event()

    def send(path, body=raw, headers=None):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request("POST", path, body=body, headers=headers or {
                "Content-Type": "application/json", "Stripe-Signature": signature,
            })
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    try:
        assert server.server_address[0] == "127.0.0.1"
        for path in ("/v1/checkout", "/v1/portal", "/v1/evaluations", "/v1/stripe/webhook?tenant=a"):
            assert send(path)[0] == 404
        assert send("/v1/stripe/webhook", body=b"x" * 65537)[0] == 413
        assert send("/v1/stripe/webhook", headers={"Content-Type": "application/json"})[0] == 400
        assert send("/v1/stripe/webhook") == (200, b'{"received":true}')
        assert send("/v1/stripe/webhook", body=raw + b" ")[0] == 503
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_handoff_permissions_and_invalid_operator_config(tmp_path, caplog):
    output = tmp_path / "handoff.json"
    _handoff(str(output), "https://checkout.stripe.com/test")
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        _handoff(str(output), "https://checkout.stripe.com/test")
    config_path = tmp_path / "config.json"
    config_path.write_text('{"mode":"customer-claimed-paid","secret":"never-log-this"}')
    config_path.chmod(0o600)
    assert main(["--config", str(config_path), "portal", "--tenant", "tenant-a",
                 "--output", str(tmp_path / "not-created")]) == 1
    assert "never-log-this" not in caplog.text


def test_sql_paid_contract_is_separate_atomic_locked_and_fail_closed():
    sql = (Path(__file__).resolve().parents[1] / "migrations/postgresql/004_paid_advisory_v1.sql").read_text().lower()
    assert sql.startswith("begin;") and sql.rstrip().endswith("commit;")
    for text in (
        "check (allowance = 100000)", "primary key (tenant_ref,request_id_digest)",
        "foreign key (tenant_ref,invoice_id)", "for update of p",
        "verified_until<=clock_timestamp()", "access_until<=clock_timestamp()",
        "credential", "no_paid_pilot_bypass", "deferrable initially deferred",
        "security definer", "set search_path = pg_catalog, gvai_authority, pg_temp",
        "paid count mismatch", "revoked and not new.revoked",
    ):
        assert text in sql
    assert "update gvai_authority.advisory_pilots" not in sql
    assert "delete from" not in sql
    assert "grant " not in sql
