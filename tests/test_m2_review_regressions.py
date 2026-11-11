"""Independent review regressions; original security tests remain intact."""
from tests.test_stripe_billing import NOW, config, event
from gvai.stripe_billing import verified_recovery_event, verify_event, BillingUnavailable
import pytest


def test_owner_accepts_historical_signed_payment_but_live_ingress_does_not():
    raw, signature = event(at=NOW-4000, created=NOW-4001, object="invoice", id="in_a",
        livemode=False, subscription="sub_a", status="paid", paid=True,
        paid_out_of_band=False, status_transitions={"paid_at": NOW-4002})
    with pytest.raises(BillingUnavailable):
        verify_event(raw, signature, config().webhook_secret, now=NOW)
    assert verified_recovery_event(raw, signature, config(), NOW)["id"] == "evt_test"
    with pytest.raises(BillingUnavailable):
        verified_recovery_event(raw+b" ", signature, config(), NOW)


@pytest.mark.parametrize("kind", ["invoice.payment_failed", "charge.refunded", "charge.dispute.created"])
def test_transaction_denial_passes_verified_entitlement_scope(kind):
    from tests.test_stripe_billing import Stripe
    from gvai.stripe_billing import BillingService, SubscriptionAuthority
    api = Stripe()
    captured = []
    class Store:
        def reconcile(self, customer, load, *, event=None):
            captured.append((customer,event))
    service = BillingService(SubscriptionAuthority(api,config(),clock=lambda: NOW),Store())
    claims = dict(object="invoice",livemode=False,id="in_a",subscription="sub_a")
    if kind == "charge.refunded":
        claims = dict(api.objects["/v1/charges/ch_a"])
        claims.pop("customer")
    elif kind == "charge.dispute.created":
        claims = dict(object="dispute",livemode=False,id="dp_a",charge="ch_a")
    service.webhook(*event(kind,**claims))
    assert captured[0][0] == "cus_a"
    assert captured[0][1][3:] == (True,"sub_a","in_a")


def test_cross_customer_charge_chain_cannot_supply_denial_scope():
    from tests.test_stripe_billing import Stripe
    from gvai.stripe_billing import BillingService, SubscriptionAuthority
    api = Stripe()
    api.objects["/v1/payment_intents/pi_a"]["customer"] = "cus_b"
    class Store:
        def reconcile(self,*args,**kwargs):
            pytest.fail("Invalid binding reached database")
    service = BillingService(SubscriptionAuthority(api,config(),clock=lambda: NOW),Store())
    claims = dict(api.objects["/v1/charges/ch_a"])
    claims.pop("customer")
    with pytest.raises(BillingUnavailable):
        service.webhook(*event("charge.refunded",**claims))



def test_old_charge_attempt_cannot_deny_current_payment_for_same_invoice():
    from tests.test_stripe_billing import Stripe
    from gvai.stripe_billing import BillingService, SubscriptionAuthority
    api = Stripe()
    api.objects["/v1/payment_intents/pi_a"]["latest_charge"] = "ch_new"
    class Store:
        def reconcile(self,*args,**kwargs):
            pytest.fail("Old charge attempt cannot attest current denial")
    claims = dict(api.objects["/v1/charges/ch_a"])
    claims.pop("customer")
    service = BillingService(SubscriptionAuthority(api,config(),clock=lambda: NOW),Store())
    with pytest.raises(BillingUnavailable):
        service.webhook(*event("charge.refunded",**claims))
