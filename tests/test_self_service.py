"""Self-service Stripe TEST-mode slice against a real, disposable PostgreSQL.

Opt in with GVAI_RUN_SELF_SERVICE_POSTGRES=1. Needs Docker and a cached postgres:16
image (never pulled). Stripe is a deterministic in-process fake; no network or real
Stripe object is used, so real Stripe behavior remains unverified by this file.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
from http.client import HTTPConnection
import json
import logging
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import threading
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_SELF_SERVICE_POSTGRES") != "1",
    reason="Opt in to the disposable-PostgreSQL self-service slice.",
)
ROOT = Path(__file__).resolve().parents[1]
WEBHOOK_SECRET = "whsec_" + "t" * 32
STRIPE_KEY = "sk_test_" + "k" * 32
VERIFIER_SECRET = bytes.fromhex("ab" * 32)
TELEMETRY = {
    "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
    "repeated_action_delta": 0, "recursion_depth": 0,
}
PRICE = {
    "id": "price_test_99", "object": "price", "livemode": False, "active": True,
    "type": "recurring", "currency": "usd", "unit_amount": 9900,
    "recurring": {
        "aggregate_usage": None, "interval": "month", "interval_count": 1,
        "trial_period_days": None, "usage_type": "licensed",
    },
}


class FakeStripe:
    """Minimal in-memory Stripe test-mode API; state is flipped by the tests."""

    def __init__(self):
        self.customers, self.state, self.calls = {}, {}, []
        self.sessions, self.idempotent = {}, {}
        self.start = int(time.time()) - 60
        self.end = self.start + 30 * 86400
        self.last_date = 0
        self.undated = False
        self.outage = None

    def begin_fetch(self):
        # Every logical fetch observes a strictly later Stripe-side second than the previous one.
        self.last_date = max(int(time.time()), self.last_date + 1)

    def set(self, customer, state):
        self.state[customer] = state

    def request(self, method, path, parameters=None, *, idempotency_key=None):
        from gvai.stripe_billing import BillingUnavailable, StripeObject
        if self.outage is not None and method == "GET":
            raise BillingUnavailable("Synthetic outage.", transient=self.outage == "transient")
        value = StripeObject(self._request(method, path, parameters, idempotency_key))
        value.stripe_date = None if self.undated else max(self.last_date, int(time.time()))
        return value

    def _request(self, method, path, parameters=None, idempotency_key=None):
        parameters = parameters or {}
        self.calls.append((method, path))
        parts = path.strip("/").split("/")[1:]
        if (method, parts) == ("POST", ["customers"]):
            if idempotency_key in self.idempotent:
                return self.idempotent[idempotency_key]
            customer = "cus_test_" + secrets.token_hex(6)
            self.customers[customer] = parameters
            self.idempotent[idempotency_key] = value = {
                "object": "customer", "id": customer, "livemode": False,
            }
            return value
        if method == "POST" and parts == ["checkout", "sessions"]:
            customer = parameters["customer"]
            assert parameters["line_items[0][price]"] == PRICE["id"]
            session = self.sessions.setdefault(customer, {
                "object": "checkout.session", "id": "cs_test_" + secrets.token_hex(6),
                "livemode": False, "customer": customer, "mode": "subscription",
            })
            session["url"] = "https://checkout.stripe.com/c/pay/" + session["id"]
            return session
        kind, identifier_ = parts[0], parts[1] if len(parts) > 1 else None
        n = (identifier_ or "").split("_")[-1]
        customer = "cus_test_" + n
        paid = self.state.get(customer) == "paid"
        if kind == "customers":
            return {"object": "customer", "id": identifier_, "livemode": False}
        if kind == "prices":
            return PRICE
        if kind == "subscriptions" and identifier_ is None:
            customer = parameters["customer"]
            n = customer.split("_")[-1]
            data = [] if self.state.get(customer) is None else [{"id": "sub_test_" + n}]
            return {"data": data, "has_more": False}
        if kind == "subscriptions":
            return {
                "object": "subscription", "id": identifier_, "livemode": False,
                "customer": customer, "status": "active" if paid else (
                    "canceled" if self.state.get(customer) == "canceled" else "past_due"),
                "collection_method": "charge_automatically", "pause_collection": None,
                "pending_update": None, "trial_start": None, "trial_end": None,
                "items": {"data": [{"quantity": 1, "price": PRICE}], "has_more": False},
                "current_period_start": self.start, "current_period_end": self.end,
                "latest_invoice": "in_test_" + n, "cancel_at": None,
            }
        sub = "sub_test_" + n
        if kind == "invoices":
            return {
                "object": "invoice", "id": identifier_, "livemode": False, "customer": customer,
                "subscription": sub, "status": "paid" if paid else "open", "paid": paid,
                "paid_out_of_band": False, "currency": "usd",
                "amount_remaining": 0 if paid else 9900, "amount_paid": 9900 if paid else 0,
                "amount_due": 9900, "total": 9900, "payment_intent": "pi_test_" + n,
                "lines": {"data": [{
                    "type": "subscription", "subscription": sub, "proration": False,
                    "period": {"start": self.start, "end": self.end}, "price": {"id": PRICE["id"]},
                }], "has_more": False},
            }
        if kind == "payment_intents":
            return {
                "object": "payment_intent", "id": identifier_, "livemode": False,
                "status": "succeeded" if paid else "requires_payment_method",
                "customer": customer, "invoice": "in_test_" + n, "currency": "usd",
                "amount_received": 9900 if paid else 0, "latest_charge": "ch_test_" + n,
            }
        if kind == "charges":
            return {
                "object": "charge", "id": identifier_, "livemode": False, "customer": customer,
                "payment_intent": "pi_test_" + n, "paid": paid, "status": "succeeded",
                "refunded": False, "disputed": False, "amount_refunded": 0,
            }
        raise AssertionError("unexpected Stripe request " + path)


@pytest.fixture(scope="module")
def stack():
    import psycopg
    from gvai.billing_operator import _billing_connect
    from gvai.commercial_http import create_webhook_server
    from gvai.commercial_reservation_authority import AuthorityIdentity
    from gvai.postgresql_billing import PAID_ENTRY_FUNCTIONS, PostgreSQLBillingStore, PostgreSQLPaidUsage
    from gvai.private_staging import PrivateStagingApplication, StagingConfig
    from gvai.self_service import PostgreSQLSelfServiceStore, SelfService, create_self_service_server
    from gvai.stripe_billing import BillingConfig, BillingService, SubscriptionAuthority

    # CI sets GVAI_REQUIRE_SELF_SERVICE_POSTGRES=1 so missing prerequisites fail instead of skipping.
    unavailable = pytest.fail if os.environ.get("GVAI_REQUIRE_SELF_SERVICE_POSTGRES") == "1" else pytest.skip
    if shutil.which("docker") is None:
        unavailable("Docker unavailable.")
    if subprocess.run(["docker", "image", "inspect", "postgres:16"], capture_output=True).returncode:
        unavailable("Cached postgres:16 unavailable; no image pull.")
    name = "gvai-self-service-" + secrets.token_hex(8)
    admin_password = secrets.token_hex(16)
    owner_password, runtime_password = secrets.token_hex(16), secrets.token_hex(16)

    def docker(*args, input=None):
        result = subprocess.run(
            ["docker", *args], input=input, text=True, capture_output=True, timeout=120,
            env={**os.environ, "POSTGRES_PASSWORD": admin_password},
        )
        assert result.returncode == 0, "docker failed: " + result.stderr[-800:]
        return result.stdout.strip()

    created = False
    servers = []
    app = None
    try:
        docker(
            "run", "--detach", "--pull=never", "--name", name, "--memory", "512m",
            "--pids-limit", "128", "--security-opt", "no-new-privileges:true",
            "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD",
            "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=256m", "postgres:16",
            "-c", "log_statement=none", "-c", "log_min_error_statement=panic",
        )
        created = True
        port = int(docker("port", name, "5432/tcp").splitlines()[0].rsplit(":", 1)[1])
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            probe = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"],
                                   capture_output=True)
            if probe.returncode == 0:
                time.sleep(1)
                break
            time.sleep(0.2)
        else:
            pytest.fail("PostgreSQL startup timed out.")
        docker(
            "exec", "-i", name, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-U", "postgres",
            input=f"CREATE ROLE ss_owner LOGIN PASSWORD '{owner_password}';"
                  f"CREATE ROLE ss_runtime LOGIN PASSWORD '{runtime_password}';"
                  "CREATE DATABASE gvai_advisory_test_ss OWNER ss_owner;"
                  "REVOKE ALL ON DATABASE gvai_advisory_test_ss FROM PUBLIC;"
                  "GRANT CONNECT ON DATABASE gvai_advisory_test_ss TO ss_owner,ss_runtime;",
        )

        def dsn(user, password):
            return f"host=127.0.0.1 port={port} dbname=gvai_advisory_test_ss user={user} password={password}"

        owner_dsn, runtime_dsn = dsn("ss_owner", owner_password), dsn("ss_runtime", runtime_password)

        def owner():
            return psycopg.connect(owner_dsn, connect_timeout=3)

        with psycopg.connect(owner_dsn, autocommit=True) as connection:
            for migration in (
                "001_reservation_authority_v1.sql", "002_restricted_reservation_routine_v1.sql",
                "003_advisory_pilots_v1.sql", "004_paid_advisory_v1.sql",
                "007_paid_checkout_state_v1.sql", "008_self_service_accounts_v1.sql",
                "009_subscription_reconciliation_v1.sql",
            ):
                connection.execute((ROOT / "migrations/postgresql" / migration).read_text())
            connection.execute(
                "GRANT USAGE ON SCHEMA gvai_authority TO ss_runtime;"
                "GRANT EXECUTE ON FUNCTION "
                "gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text),"
                "gvai_authority.complete_paid_v1(text,bytea,text,text,boolean),"
                "gvai_authority.paid_usage_v1(text,bytea,text) TO ss_runtime;"
                "INSERT INTO gvai_authority.authority_state(singleton_id,authority_id,epoch,trust_domain)"
                " VALUES(1,'self-service-test',1,'disposable');"
            )
        authority = AuthorityIdentity("self-service-test", 1, "disposable")
        fake = FakeStripe()
        config = BillingConfig(
            STRIPE_KEY, WEBHOOK_SECRET, PRICE["id"], "https://example.test/welcome",
            "https://example.test/cancel", "https://example.test/account",
        )
        billing = BillingService(
            SubscriptionAuthority(fake, config), PostgreSQLBillingStore(_billing_connect(owner_dsn)),
        )
        store = PostgreSQLSelfServiceStore(owner, verifier_secret=VERIFIER_SECRET)
        service = SelfService(store, billing, fake, signup_limit=1000)
        account_server = create_self_service_server(service)
        webhook_server = create_webhook_server(billing.webhook)
        app = PrivateStagingApplication(
            StagingConfig(runtime_dsn, VERIFIER_SECRET, authority, port=0, max_connections=4),
            usage_factory=PostgreSQLPaidUsage, entry_functions=PAID_ENTRY_FUNCTIONS,
        )
        for server in (account_server, webhook_server):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        app.start()
        yield type("Stack", (), dict(
            fake=fake, billing=billing, store=store, service=service, owner=staticmethod(owner),
            runtime_dsn=runtime_dsn, account=account_server.server_port,
            webhook=webhook_server.server_port, evaluation=app.server.server_port,
            psycopg=psycopg,
        ))
    finally:
        if app is not None:
            app.stop()
        for server in servers:
            server.shutdown()
            server.server_close()
        if created:
            subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True)


def call(port, method, path, token=None, body=None, headers=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    sent = dict(headers or {})
    if token is not None:
        sent["Authorization"] = "Bearer " + token
    payload = None
    if body is not None:
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()
        sent.setdefault("Content-Type", "application/json")
    try:
        connection.request(method, path, body=payload, headers=sent)
        response = connection.getresponse()
        raw = response.read()
        return response.status, (json.loads(raw) if raw else {}), response
    finally:
        connection.close()


def signup(stack):
    status, body, _ = call(stack.account, "POST", "/v1/signup")
    assert status == 201
    return body["account_token"], body["resource_id"], list(stack.fake.customers)[-1]


def deliver(stack, customer, event_type="invoice.paid", *, event_id=None, age=0, secret=WEBHOOK_SECRET,
            livemode=False):
    raw = json.dumps({
        "id": event_id or "evt_" + secrets.token_hex(8), "object": "event", "livemode": livemode,
        "api_version": "2024-06-20", "account": None, "type": event_type,
        "created": int(time.time()) - age, "data": {"object": {"customer": customer}},
    }).encode()
    stamp = str(int(time.time()) - age)
    signature = hmac.new(secret.encode(), stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    return call(
        stack.webhook, "POST", "/v1/stripe/webhook", body=raw,
        headers={"Stripe-Signature": f"t={stamp},v1={signature}"},
    )[0], raw


def entitled(stack, token):
    return call(stack.account, "GET", "/v1/account", token)[1]["entitled"]


def paid_account(stack):
    token, resource, customer = signup(stack)
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer, "checkout.session.completed")[0] == 200
    assert entitled(stack, token) is True
    return token, resource, customer


def evaluate(stack, key, resource, request_id="req-1"):
    status, body, _ = call(stack.evaluation, "POST", "/v1/evaluations", key, {
        "version": "v1", "request_id": request_id, "resource_id": resource,
        "telemetry": TELEMETRY, "reported_effects": [],
    })
    return status, body


def claim(stack, token):
    status, body, response = call(stack.account, "POST", "/v1/account/api-key", token)
    return status, body, response


def test_signup_to_first_advisory_call_without_leaking_secrets(stack, caplog):
    caplog.set_level(logging.DEBUG)
    token, resource, customer = signup(stack)
    assert re.fullmatch(r"gvai_acct_v1_[0-9a-f]{64}", token)
    assert call(stack.account, "GET", "/v1/account", token)[1] == {
        "resource_id": resource, "entitled": False, "entitlement_state": "payment_required",
        "api_key_claimed": False,
    }
    assert claim(stack, token)[0] == 402
    status, body, response = call(stack.account, "POST", "/v1/account/checkout", token)
    assert status == 200 and body["checkout_url"].startswith("https://checkout.stripe.com/")
    assert call(stack.account, "POST", "/v1/account/checkout", token)[1] == body
    assert response.getheader("Cache-Control") == "no-store"
    assert claim(stack, token)[0] == 402, "A redirect or session alone must not grant a key."
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer, "checkout.session.completed")[0] == 200
    status, issued, response = claim(stack, token)
    key = issued["api_key"]
    assert status == 201 and re.fullmatch(r"gvai_customer_v1_[0-9a-f]{32}_[0-9a-f]{64}", key)
    assert response.getheader("Cache-Control") == "no-store"
    assert issued["advisory_only"] is True and issued["enforcement_applied"] is False
    status, second, _ = claim(stack, token)
    assert status == 409 and key not in json.dumps(second)
    status, result = evaluate(stack, key, resource)
    assert status == 200
    assert result["evaluation"]["decision"] == "ALLOW"
    assert result["evaluation"]["advisory_only"] is True
    assert result["evaluation"]["enforcement_applied"] is False
    with stack.owner() as connection:
        stored = repr(connection.execute(
            "SELECT credential_verifier,key_id FROM gvai_authority.customer_credentials "
            "UNION ALL SELECT token_verifier,key_id FROM gvai_authority.customer_accounts"
        ).fetchall())
    secret_part = key.rsplit("_", 1)[1]
    assert secret_part not in stored and token[len("gvai_acct_v1_"):] not in stored
    assert key not in caplog.text and token not in caplog.text


def test_unauthenticated_and_malformed_requests_never_issue_or_leak(stack):
    port = stack.account
    for path in ("/v1/account/api-key", "/v1/account/checkout"):
        assert call(port, "POST", path)[0] == 401
        assert call(port, "POST", path, "gvai_acct_v1_" + "0" * 64)[0] == 401
        assert call(port, "POST", path, "not-a-token")[0] == 401
    token, _, customer = signup(stack)
    assert call(port, "POST", "/v1/account/api-key?token=" + token)[0] == 400
    assert call(port, "GET", "/v1/account?token=" + token)[0] == 400
    assert call(port, "POST", "/v1/account/api-key", token, b'{"x":1}')[0] == 400
    assert call(port, "GET", "/v1/api-key", token)[0] == 404


def test_webhook_signature_freshness_livemode_and_duplicate_delivery(stack):
    token, _, customer = signup(stack)
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer, secret="whsec_" + "x" * 32)[0] == 503
    assert deliver(stack, customer, age=3600)[0] == 503
    assert deliver(stack, customer, livemode=True)[0] == 503
    assert entitled(stack, token) is False
    before = len(stack.fake.calls)
    status, raw = deliver(stack, customer, event_id="evt_dup1")
    assert status == 200 and entitled(stack, token) is True
    mid = len(stack.fake.calls)
    assert mid > before
    stamp = str(int(time.time()))
    signature = hmac.new(WEBHOOK_SECRET.encode(), stamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    again = call(stack.webhook, "POST", "/v1/stripe/webhook", body=raw,
                 headers={"Stripe-Signature": f"t={stamp},v1={signature}"})[0]
    assert again == 200 and len(stack.fake.calls) == mid, "Replay must not re-run reconciliation."
    # The same event id with different content is a collision, never a second grant.
    assert deliver(stack, customer, "invoice.payment_failed", event_id="evt_dup1")[0] == 503
    with stack.owner() as connection:
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.billing_periods"
        ).fetchone()[0] >= 1
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.billing_events WHERE event_id='evt_dup1'"
        ).fetchone()[0] == 1


def test_out_of_order_events_follow_current_stripe_state_never_stale_payload(stack):
    token, resource, customer = signup(stack)
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer, "invoice.paid")[0] == 200
    assert entitled(stack, token) is True
    stack.fake.set(customer, "failed")
    assert deliver(stack, customer, "invoice.payment_failed")[0] == 200
    assert entitled(stack, token) is False
    # A delayed, older "paid" event arrives after the failure: current state still wins.
    assert deliver(stack, customer, "invoice.paid", age=200)[0] == 200
    assert entitled(stack, token) is False
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer, "invoice.paid")[0] == 200
    assert entitled(stack, token) is True
    with stack.owner() as connection:
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.billing_periods p JOIN gvai_authority.tenants t "
            "ON t.tenant_ref=p.tenant_ref JOIN gvai_authority.resource_ownerships o "
            "ON o.tenant_ref=t.tenant_ref WHERE o.resource_id=%s", (resource,),
        ).fetchone()[0] == 1, "Repeated paid events must reuse one period."


def test_unmapped_customer_event_is_not_acknowledged_and_grants_nothing(stack):
    assert deliver(stack, "cus_test_unknown")[0] == 503


def test_failed_payment_blocks_key_issuance_and_suspends_existing_key(stack):
    token, resource, customer = signup(stack)
    stack.fake.set(customer, "failed")
    assert deliver(stack, customer, "invoice.payment_failed")[0] == 200
    assert claim(stack, token)[0] == 402
    stack.fake.set(customer, "paid")
    assert deliver(stack, customer)[0] == 200
    key = claim(stack, token)[1]["api_key"]
    assert evaluate(stack, key, resource)[0] == 200
    stack.fake.set(customer, "failed")
    assert deliver(stack, customer, "invoice.payment_failed")[0] == 200
    assert evaluate(stack, key, resource, "req-2")[0] == 403


def test_revoked_key_is_denied_and_replay_is_not_a_second_evaluation(stack):
    from gvai.commercial_api_keys import CustomerApiKeys
    from gvai.postgresql_advisory import PostgreSQLCustomerStore

    token, resource, _ = paid_account(stack)
    key = claim(stack, token)[1]["api_key"]
    assert evaluate(stack, key, resource, "once")[0] == 200
    assert evaluate(stack, key, resource, "once")[1]["error"]["code"] == "replay"
    key_id = key.split("_")[3]
    assert CustomerApiKeys(
        PostgreSQLCustomerStore(stack.owner), verifier_secret=VERIFIER_SECRET,
    ).revoke(key_id)
    assert evaluate(stack, key, resource, "after-revoke")[0] == 403
    assert claim(stack, token)[0] == 409, "Revocation must not reopen the one-time claim."


def test_tenant_isolation_between_paid_accounts(stack):
    token_a, resource_a, customer_a = paid_account(stack)
    token_b, resource_b, customer_b = paid_account(stack)
    key_a, key_b = claim(stack, token_a)[1]["api_key"], claim(stack, token_b)[1]["api_key"]
    assert evaluate(stack, key_a, resource_b)[0] == 403
    assert evaluate(stack, key_b, resource_a)[0] == 403
    assert evaluate(stack, key_a, resource_a, "shared-id")[0] == 200
    assert evaluate(stack, key_b, resource_b, "shared-id")[0] == 200, "Request IDs are tenant scoped."
    assert call(stack.evaluation, "GET", "/v1/usage/" + resource_b, key_a)[0] == 403
    assert call(stack.account, "GET", "/v1/account", token_a)[1]["resource_id"] == resource_a
    assert call(stack.account, "POST", "/v1/account/checkout", token_a)[0] == 503, (
        "A paid customer must not be offered a second subscription."
    )
    token_c, _, customer_c = signup(stack)
    assert call(stack.account, "POST", "/v1/account/checkout", token_c)[0] == 200
    assert customer_c in stack.fake.sessions
    assert customer_a not in stack.fake.sessions and customer_b not in stack.fake.sessions


def test_one_time_claim_is_atomic_under_concurrency(stack):
    token, resource, _ = paid_account(stack)
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: claim(stack, token)[:2], range(8)))
    issued = [body for status, body in results if status == 201]
    assert len(issued) == 1
    assert sorted(status for status, _ in results).count(409) == 7
    with stack.owner() as connection:
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.customer_credentials c "
            "JOIN gvai_authority.resource_ownerships o ON o.tenant_ref=c.tenant_ref "
            "WHERE o.resource_id=%s", (resource,),
        ).fetchone()[0] == 1
    assert evaluate(stack, issued[0]["api_key"], resource)[0] == 200


def test_paid_quota_limit_is_enforced_at_100000(stack):
    token, resource, _ = paid_account(stack)
    key = claim(stack, token)[1]["api_key"]
    with stack.owner() as connection:
        invoice, tenant = connection.execute(
            "SELECT b.current_invoice,b.tenant_ref FROM gvai_authority.billing_customers b "
            "JOIN gvai_authority.resource_ownerships o ON o.tenant_ref=b.tenant_ref WHERE o.resource_id=%s",
            (resource,),
        ).fetchone()
        for statement in (
            "ALTER TABLE gvai_authority.billing_periods DISABLE TRIGGER billing_period_guard",
            "ALTER TABLE gvai_authority.billing_periods DISABLE TRIGGER paid_period_count",
            "ALTER TABLE gvai_authority.paid_attempts DISABLE TRIGGER paid_attempt_count",
        ):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO gvai_authority.paid_attempts SELECT %s,%s,"
            "encode(gvai_authority.digest(convert_to('seed-'||n,'UTF8'),'sha256'),'hex'),"
            "repeat('d',64),repeat('e',64),'completed' FROM generate_series(1,99999) n",
            (tenant, invoice),
        )
        connection.execute(
            "UPDATE gvai_authority.billing_periods SET consumed=99999 WHERE invoice_id=%s", (invoice,),
        )
        for statement in (
            "ALTER TABLE gvai_authority.billing_periods ENABLE TRIGGER billing_period_guard",
            "ALTER TABLE gvai_authority.billing_periods ENABLE TRIGGER paid_period_count",
            "ALTER TABLE gvai_authority.paid_attempts ENABLE TRIGGER paid_attempt_count",
        ):
            connection.execute(statement)
    assert evaluate(stack, key, resource, "last")[0] == 200
    status, body = evaluate(stack, key, resource, "over")
    assert status == 429 and body["error"]["code"] == "quota_denied"


def test_signup_is_rate_limited_and_account_table_is_owner_only(stack):
    from gvai.self_service import SelfService, SelfServiceError

    limited = SelfService(stack.store, stack.billing, stack.fake, signup_limit=2, signup_window=3600)
    limited.signup()
    limited.signup()
    with pytest.raises(SelfServiceError) as error:
        limited.signup()
    assert error.value.code == "rate_limited"
    with stack.psycopg.connect(stack.runtime_dsn) as runtime:
        with pytest.raises(stack.psycopg.errors.InsufficientPrivilege):
            runtime.execute("SELECT token_verifier FROM gvai_authority.customer_accounts")
    token, _, _ = paid_account(stack)
    claim(stack, token)
    with stack.owner() as connection:
        with pytest.raises(stack.psycopg.errors.RaiseException):
            connection.execute("UPDATE gvai_authority.customer_accounts SET key_id=NULL,key_claimed_at=NULL")


def test_account_cannot_be_linked_to_another_tenants_credential(stack):
    token_a, _, _ = paid_account(stack)
    claim(stack, token_a)
    _, _, _ = signup(stack)
    with stack.owner() as connection:
        key_id = connection.execute(
            "SELECT key_id FROM gvai_authority.customer_accounts WHERE key_id IS NOT NULL LIMIT 1"
        ).fetchone()[0]
        with pytest.raises(stack.psycopg.errors.RaiseException):
            connection.execute(
                "UPDATE gvai_authority.customer_accounts SET key_id=%s,key_claimed_at=now() "
                "WHERE key_id IS NULL AND account_ref=(SELECT max(account_ref) FROM gvai_authority.customer_accounts)",
                (key_id,),
            )


def tenant_of(stack, resource):
    with stack.owner() as connection:
        return connection.execute(
            "SELECT t.tenant_id FROM gvai_authority.tenants t JOIN gvai_authority.resource_ownerships o "
            "ON o.tenant_ref=t.tenant_ref WHERE o.resource_id=%s", (resource,),
        ).fetchone()[0]


def lapse_lease(stack, tenant):
    with stack.owner() as connection:
        connection.execute(
            "UPDATE gvai_authority.billing_customers SET verified_until=clock_timestamp()-interval '1 second' "
            "WHERE tenant_ref=(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)", (tenant,),
        )


def state_of(stack, token):
    return call(stack.account, "GET", "/v1/account", token)[1]


def test_paid_customer_keeps_access_across_lease_expiry_via_reconciliation(stack):
    token, resource, customer = paid_account(stack)
    key = claim(stack, token)[1]["api_key"]
    assert evaluate(stack, key, resource, "before")[0] == 200
    tenant = tenant_of(stack, resource)
    assert state_of(stack, token)["entitlement_state"] == "active"
    lapse_lease(stack, tenant)
    # A lapsed lease fails closed and is reported honestly; the customer's own claim changes nothing.
    assert evaluate(stack, key, resource, "lapsed")[0] == 403
    shown = state_of(stack, token)
    assert shown["entitlement_state"] == "verification_pending" and shown["entitled"] is False
    assert claim(stack, token)[0] in (402, 409)
    stack.billing.reconcile(tenant)
    assert evaluate(stack, key, resource, "after")[0] == 200
    after = state_of(stack, token)
    assert after["entitlement_state"] == "active" and set(after) == {
        "resource_id", "entitled", "entitlement_state", "api_key_claimed", "access_until",
    }
    with stack.owner() as connection:
        consumed = connection.execute(
            "SELECT p.consumed FROM gvai_authority.billing_periods p JOIN gvai_authority.tenants t "
            "ON t.tenant_ref=p.tenant_ref WHERE t.tenant_id=%s", (tenant,),
        ).fetchall()
    assert consumed == [(2,)], "Reconciliation must not reset or duplicate consumed attempts."


def test_lapsed_lease_is_never_extended_by_outage_and_cancellation_denies(stack):
    token, resource, customer = paid_account(stack)
    key = claim(stack, token)[1]["api_key"]
    tenant = tenant_of(stack, resource)
    lapse_lease(stack, tenant)
    stack.fake.outage = "transient"
    try:
        with pytest.raises(Exception):
            stack.billing.reconcile(tenant)
    finally:
        stack.fake.outage = None
    assert evaluate(stack, key, resource, "outage")[0] == 403
    assert state_of(stack, token)["entitlement_state"] == "verification_pending"
    stack.fake.set(customer, "canceled")
    stack.billing.reconcile(tenant)
    assert evaluate(stack, key, resource, "canceled")[0] == 403
    assert state_of(stack, token)["entitlement_state"] == "payment_required"
    # A later paid report for a terminal subscription must not reactivate it without resubscribe.
    stack.fake.set(customer, "paid")
    with pytest.raises(Exception):
        stack.billing.reconcile(tenant)
    assert evaluate(stack, key, resource, "reactivated")[0] == 403


def test_integrity_failure_suspends_and_revoked_key_stays_revoked_after_reconcile(stack):
    from gvai.commercial_api_keys import CustomerApiKeys
    from gvai.postgresql_advisory import PostgreSQLCustomerStore

    token, resource, customer = paid_account(stack)
    key = claim(stack, token)[1]["api_key"]
    tenant = tenant_of(stack, resource)
    assert CustomerApiKeys(
        PostgreSQLCustomerStore(stack.owner), verifier_secret=VERIFIER_SECRET,
    ).revoke(key.split("_")[3])
    lapse_lease(stack, tenant)
    stack.billing.reconcile(tenant)
    assert evaluate(stack, key, resource, "revoked")[0] == 403, "Reconciliation must not reactivate a revoked key."
    stack.fake.outage = "integrity"
    try:
        with pytest.raises(Exception):
            stack.billing.reconcile(tenant)
    finally:
        stack.fake.outage = None
    assert state_of(stack, token)["entitlement_state"] == "payment_required"
    assert stack.service.status(token)["entitled"] is False
