from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
from unittest.mock import Mock

import pytest

from gvai.identity import INTERNAL_TENANT_ID
from gvai.sandbox_checkout import (
    AuthenticatedCheckoutContext,
    CheckoutIntentDenied,
    CheckoutMembership,
    SandboxCheckoutBuilder,
    SandboxCheckoutConfig,
)


ATTEMPT = "1" * 32
CONTEXT = AuthenticatedCheckoutContext("identity-provider", "subject-a", "tenant-a", 200)
MEMBERSHIP = CheckoutMembership("identity-provider", "subject-a", "tenant-a", True, True)


def config(**changes):
    # Synthetic identifiers only; never discovered from environment or Stripe.
    values = dict(
        stripe_account_id="acct_SyntheticSandbox",
        environment="sandbox",
        price_id="price_SyntheticMonthly",
        price_approved=True,
        success_url="https://billing.example/checkout/success",
        cancel_url="https://billing.example/checkout/cancel",
    )
    return SandboxCheckoutConfig(**{**values, **changes})


def boundary(*, member=MEMBERSHIP, settings=None, now=100):
    store = Mock()
    store.lookup.return_value = member
    builder = SandboxCheckoutBuilder(
        config() if settings is None else settings, store, clock=lambda: now,
    )
    return builder, store


def build(builder, **changes):
    return builder.build({}, **{"context": CONTEXT, "attempt_id": ATTEMPT, **changes})


def test_exact_offer_and_association():
    builder, store = boundary()
    intent = build(builder)
    assert asdict(intent) == {
        "version": 1,
        "association": {
            "issuer": "identity-provider", "principal_id": "subject-a",
            "tenant_id": "tenant-a", "attempt_id": ATTEMPT,
        },
        "stripe_account_id": "acct_SyntheticSandbox",
        "environment": "sandbox",
        "product": "GVAI Advisory API",
        "mode": "subscription",
        "price_id": "price_SyntheticMonthly",
        "currency": "usd",
        "unit_amount": 9900,
        "recurring_interval": "month",
        "recurring_interval_count": 1,
        "quantity": 1,
        "success_url": "https://billing.example/checkout/success",
        "cancel_url": "https://billing.example/checkout/cancel",
        "idempotency_key": intent.idempotency_key,
        "request_fingerprint": intent.request_fingerprint,
    }
    assert len(intent.idempotency_key) == len("gvai-checkout-v1-") + 64
    expected = hashlib.sha256(json.dumps({
        "domain": "gvai-sandbox-checkout-intent-v1",
        "intent": {**asdict(intent), "request_fingerprint": ""},
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    assert intent.request_fingerprint == expected
    store.lookup.assert_called_once_with("identity-provider", "subject-a", "tenant-a")
    with pytest.raises(FrozenInstanceError):
        intent.quantity = 2
    with pytest.raises(FrozenInstanceError):
        intent.association.tenant_id = "tenant-b"


@pytest.mark.parametrize("field", [
    "tenant", "tenant_id", "principal_id", "issuer", "email", "customer",
    "customer_id", "subscription", "subscription_id", "account",
    "stripe_account_id", "price", "price_id", "amount", "unit_amount", "quantity",
    "currency", "metadata", "success_url", "cancel_url", "environment", "livemode",
    "attempt_id", "idempotency_key", "mode", "line_items", "unknown",
])
def test_client_allowlist_rejects_all_overrides_before_membership_lookup(field):
    builder, store = boundary()
    with pytest.raises(CheckoutIntentDenied, match="^invalid_client_request$"):
        builder.build({field: "untrusted"}, context=CONTEXT, attempt_id=ATTEMPT)
    store.lookup.assert_not_called()


@pytest.mark.parametrize("payload", [None, [], "", '{"price_id":"x"}', True, ((),)])
def test_client_request_requires_exact_dictionary(payload):
    builder, _ = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_client_request"):
        builder.build(payload, context=CONTEXT, attempt_id=ATTEMPT)


def test_dictionary_subclasses_cannot_hide_claims():
    class HiddenClaims(dict):
        def __len__(self):
            return 0

    builder, _ = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_client_request"):
        builder.build(HiddenClaims(price_id="other"), context=CONTEXT, attempt_id=ATTEMPT)


@pytest.mark.parametrize("field", ["issuer", "principal_id", "tenant_id"])
@pytest.mark.parametrize("value", [None, "", True, 1, "x" * 129, "../x", "a@b.example", "a\n", "\ud800", "caf\u00e9"])
def test_malformed_identity(field, value):
    builder, store = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_authenticated_context"):
        build(builder, context=replace(CONTEXT, **{field: value}))
    store.lookup.assert_not_called()


@pytest.mark.parametrize("context", [None, {}, MEMBERSHIP, replace(CONTEXT, tenant_id=INTERNAL_TENANT_ID)])
def test_untrusted_or_internal_context(context):
    builder, _ = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_authenticated_context"):
        build(builder, context=context)


@pytest.mark.parametrize("expiry", [None, True, False, -1, 0, 200.0, "200", float("nan")])
def test_invalid_context_expiry(expiry):
    builder, _ = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_authenticated_context"):
        build(builder, context=replace(CONTEXT, expires_at=expiry))


@pytest.mark.parametrize("now", [200, 201, 10**400])
def test_exclusive_expiry(now):
    builder, _ = boundary(now=now)
    with pytest.raises(CheckoutIntentDenied, match="expired_authenticated_context"):
        build(builder)


@pytest.mark.parametrize("now", [None, True, -1, float("nan"), float("inf"), -float("inf"), "100"])
def test_invalid_clock(now):
    builder, _ = boundary(now=now)
    with pytest.raises(CheckoutIntentDenied, match="invalid_clock"):
        build(builder)


@pytest.mark.parametrize("attempt", [
    None, True, 1, "", "0" * 32, "1" * 31, "1" * 33, "A" * 32,
    "../" + "1" * 29, "1" * 31 + "\n", "z" * 32, "\ud800" * 32,
])
def test_invalid_attempt_identity(attempt):
    builder, store = boundary()
    with pytest.raises(CheckoutIntentDenied, match="invalid_attempt_identity"):
        build(builder, attempt_id=attempt)
    store.lookup.assert_not_called()


@pytest.mark.parametrize("member", [
    None, {}, CONTEXT,
    replace(MEMBERSHIP, tenant_id="tenant-b"),
    replace(MEMBERSHIP, principal_id="subject-b"),
    replace(MEMBERSHIP, issuer="different-identity-provider"),
    replace(MEMBERSHIP, active=False),
    replace(MEMBERSHIP, active=1),
    replace(MEMBERSHIP, checkout_approved=False),
    replace(MEMBERSHIP, checkout_approved=1),
])
def test_missing_unauthorized_or_conflicting_membership(member):
    builder, _ = boundary(member=member)
    with pytest.raises(CheckoutIntentDenied, match="membership_denied"):
        build(builder)


def test_cross_tenant_context_substitution_denied():
    builder, _ = boundary()
    with pytest.raises(CheckoutIntentDenied, match="membership_denied"):
        build(builder, context=replace(CONTEXT, tenant_id="tenant-b"))


@pytest.mark.parametrize("field", ["issuer", "principal_id", "tenant_id"])
def test_membership_identity_fields_require_plain_valid_strings(field):
    class EqualToAnything:
        def __eq__(self, other):
            return True

    builder, _ = boundary(member=replace(MEMBERSHIP, **{field: EqualToAnything()}))
    with pytest.raises(CheckoutIntentDenied, match="membership_denied"):
        build(builder)


def test_membership_is_reread_on_replay_and_revocation_denies():
    builder, store = boundary()
    build(builder)
    store.lookup.return_value = replace(MEMBERSHIP, active=False)
    with pytest.raises(CheckoutIntentDenied, match="membership_denied"):
        build(builder)
    assert store.lookup.call_count == 2


@pytest.mark.parametrize("field", ["success_url", "cancel_url"])
@pytest.mark.parametrize("url", [
    None, "", True, "http://billing.example/ok", "//billing.example/ok",
    "https://billing.example", "https://billing.example/ok?tenant=other",
    "https://billing.example/ok?", "https://billing.example/ok#",
    "https://user:password@billing.example/ok", "https://billing.example:443/ok",
    "https://127.0.0.1/ok", "https://[::1]/ok", "https://localhost/ok",
    "https://x.localhost/ok", "https://x.local/ok",
    "https://billing.example/../ok", "https://billing.example/./ok",
    "https://billing.example/%2fother", "https://billing.example\\evil/ok",
    "https://billing.example/\n", "https://billing.example/\tpath",
    "https://billing.example/\u00e9", "https://billing.example/\ud800",
    "https://billing.example./ok", "https://-billing.example/ok",
    "HTTPS://billing.example/ok", "https://billing.example/" + "x" * 2048,
])
def test_invalid_redirects(field, url):
    with pytest.raises(CheckoutIntentDenied, match="invalid_server_configuration"):
        config(**{field: url})


@pytest.mark.parametrize("field,value", [
    ("stripe_account_id", None), ("stripe_account_id", "account-a"),
    ("stripe_account_id", "acct_"), ("stripe_account_id", "acct_a\n"),
    ("price_id", None), ("price_id", ""), ("price_id", "price_"),
    ("price_id", "prod_Synthetic"), ("price_id", "price_x\n"),
    ("price_id", "price_" + "x" * 123), ("price_approved", False),
    ("price_approved", 1), ("environment", "live"), ("environment", "test"),
    ("environment", None), ("environment", True),
])
def test_explicit_sandbox_server_approval_required(field, value):
    with pytest.raises(CheckoutIntentDenied, match="invalid_server_configuration"):
        config(**{field: value})


def test_redirect_outcomes_must_be_distinct():
    with pytest.raises(CheckoutIntentDenied, match="invalid_server_configuration"):
        config(cancel_url=config().success_url)


def test_config_has_no_environment_or_price_fallback(monkeypatch):
    monkeypatch.setenv("STRIPE_PRICE_ID", "price_Untrusted")
    monkeypatch.setenv("STRIPE_ENVIRONMENT", "live")
    monkeypatch.setenv("STRIPE_ACCOUNT_ID", "acct_Untrusted")
    builder, _ = boundary()
    assert build(builder).price_id == "price_SyntheticMonthly"
    with pytest.raises(TypeError):
        SandboxCheckoutConfig()
    with pytest.raises(CheckoutIntentDenied, match="invalid_server_configuration"):
        SandboxCheckoutBuilder({}, Mock())


def test_replay_is_deterministic_but_not_consumed_or_persisted():
    builder, store = boundary()
    first = build(builder)
    assert build(builder) == first
    # Pure concurrent repetition is intentionally NOT duplicate-session prevention.
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert list(pool.map(lambda _: build(builder), range(8))) == [first] * 8
    assert store.lookup.call_count == 10
    assert build(builder, context=replace(CONTEXT, expires_at=300)) == first
    next_attempt = build(builder, attempt_id="2" * 32)
    assert next_attempt.idempotency_key != first.idempotency_key
    assert next_attempt.request_fingerprint != first.request_fingerprint


@pytest.mark.parametrize("changes", [
    {"price_id": "price_AnotherApproved"},
    {"success_url": "https://billing.example/another"},
    {"cancel_url": "https://billing.example/another"},
])
def test_same_attempt_changed_parameters_require_future_conflict_rejection(changes):
    builder, _ = boundary()
    changed, _ = boundary(settings=config(**changes))
    first, other = build(builder), build(changed)
    assert first.idempotency_key == other.idempotency_key
    assert first.request_fingerprint != other.request_fingerprint


def test_attempt_reuse_across_valid_tenants_is_detectable_not_prevented_offline():
    builder, _ = boundary()
    other, _ = boundary(member=replace(MEMBERSHIP, tenant_id="tenant-b"))
    first = build(builder)
    second = build(other, context=replace(CONTEXT, tenant_id="tenant-b"))
    assert first.idempotency_key == second.idempotency_key
    assert first.request_fingerprint != second.request_fingerprint


def test_account_namespaces_attempt_key():
    builder, _ = boundary()
    other, _ = boundary(settings=config(stripe_account_id="acct_OtherSandbox"))
    assert build(builder).idempotency_key != build(other).idempotency_key


@pytest.mark.parametrize("dependency", ["membership", "clock"])
def test_adapter_errors_are_explicit_sanitized_denials(dependency):
    builder, store = boundary()
    secret = "sensitive adapter diagnostics"
    if dependency == "membership":
        store.lookup.side_effect = RuntimeError(secret)
    else:
        builder = SandboxCheckoutBuilder(config(), store, clock=Mock(side_effect=RuntimeError(secret)))
    with pytest.raises(CheckoutIntentDenied, match=f"^{dependency}_unavailable$") as caught:
        build(builder)
    assert secret not in str(caught.value)
    assert caught.value.__suppress_context__


def test_identity_expiry_is_checked_after_membership_lookup():
    store = Mock()
    now = [100]

    def lookup(*args):
        now[0] = 200
        return MEMBERSHIP

    store.lookup.side_effect = lookup
    builder = SandboxCheckoutBuilder(config(), store, clock=lambda: now[0])
    with pytest.raises(CheckoutIntentDenied, match="expired_authenticated_context"):
        build(builder)
