"""Deterministic reconciler tests: bounds, capacity arithmetic, secrecy, configuration.

No network, Docker or PostgreSQL. SQL ordering semantics are proven by
tests/test_reconciler_postgresql.py; this file proves the Python-side bounds.
"""

import json
import logging
import os
import stat
import threading

import pytest

from gvai.billing_reconciler import (
    BoundedStripe, Reconciler, ReconcilerSettings, capacity_report, simulate_schedule,
)
from gvai.postgresql_billing import RECONCILER_ENTRY_FUNCTIONS
from gvai.stripe_billing import BillingConfig, BillingUnavailable, PaidState


class Recorder:
    def __init__(self):
        self.calls = []

    def request(self, method, path, parameters=None, *, idempotency_key=None):
        self.calls.append((method, path))
        return {"ok": True}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def bounded(**kwargs):
    clock = Clock()
    api = Recorder()
    return BoundedStripe(api, clock=clock, sleep=clock.sleep, **kwargs), api, clock


def test_bounded_stripe_is_get_only_and_never_sends_idempotency_keys():
    client, api, _ = bounded()
    assert client.request("GET", "/v1/customers/cus_a") == {"ok": True}
    for method in ("POST", "DELETE", "PUT"):
        with pytest.raises(BillingUnavailable):
            client.request(method, "/v1/customers")
    with pytest.raises(BillingUnavailable):
        client.request("GET", "/v1/customers/cus_a", idempotency_key="k")
    assert api.calls == [("GET", "/v1/customers/cus_a")]


def test_bounded_stripe_enforces_request_rate():
    client, api, clock = bounded(rate_per_second=5.0, burst=5)
    for _ in range(25):
        client.begin_fetch()
        client.request("GET", "/v1/customers/cus_a")
    # 25 requests with a burst of 5 at 5 rps cannot finish faster than 4 seconds.
    assert clock.now >= 3.9 and len(api.calls) == 25


def test_bounded_stripe_deadline_is_transient_and_stops_calls():
    client, api, clock = bounded(rate_per_second=1.0, burst=1, deadline_seconds=3.0)
    client.begin_fetch()
    client.request("GET", "/v1/customers/cus_a")
    with pytest.raises(BillingUnavailable) as caught:
        for _ in range(10):
            client.request("GET", "/v1/customers/cus_a")
    assert caught.value.transient is True
    assert len(api.calls) < 6


@pytest.mark.parametrize("kwargs", [
    {"rate_per_second": 0}, {"rate_per_second": 26}, {"burst": 0}, {"burst": 51},
    {"deadline_seconds": 0}, {"deadline_seconds": 26},
])
def test_bounded_stripe_rejects_unbounded_settings(kwargs):
    with pytest.raises(ValueError):
        BoundedStripe(Recorder(), **kwargs)


@pytest.mark.parametrize("kwargs", [
    {"workers": 0}, {"workers": 17}, {"claim_seconds": 9}, {"claim_seconds": 56}, {"idle_seconds": 0.01},
])
def test_reconciler_settings_are_bounded(kwargs):
    with pytest.raises(ValueError):
        ReconcilerSettings(**kwargs)


def test_capacity_report_documents_the_sustainable_tenant_limit():
    assert capacity_report(10, rate_per_second=10)["status"] == "ok"
    assert capacity_report(10, rate_per_second=10)["max_sustainable_tenants"] == 33
    assert capacity_report(10, rate_per_second=25)["max_sustainable_tenants"] == 83
    small = capacity_report(30, rate_per_second=10)
    assert small["lease_chain_safe"] is True
    for tenants in (100, 200, 1000):
        overloaded = capacity_report(tenants, rate_per_second=10)
        assert overloaded["status"] == "critical" and overloaded["lease_chain_safe"] is False
    assert capacity_report(1000, rate_per_second=25)["status"] == "critical"


def test_capacity_is_monotonic_in_tenants():
    margins = [capacity_report(n, rate_per_second=25)["worst_case_lease_margin_seconds"] for n in range(1, 400, 7)]
    assert margins == sorted(margins, reverse=True)


def test_schedule_is_starvation_free_and_lease_safe_within_capacity():
    result = simulate_schedule(50, throughput_per_second=10 / 6)
    assert result["min_served"] == result["max_served"]
    assert result["lapsed_lease_seconds"] == 0


def test_overload_degrades_uniformly_rather_than_starving_any_tenant():
    result = simulate_schedule(200, throughput_per_second=10 / 6)
    assert result["min_served"] >= 1 and result["max_served"] - result["min_served"] <= 1
    # Overload is reported as lapsed leases (fail closed), never as extended access.
    assert result["lapsed_lease_seconds"] > 0


def test_oldest_due_first_scales_with_throughput():
    assert simulate_schedule(200, throughput_per_second=25 / 6)["lapsed_lease_seconds"] == 0


class Store:
    def __init__(self, outcome="applied_eligible"):
        self.claims, self.outcome, self.completed = [], outcome, []

    def claim_due(self, limit, seconds):
        taken, self.claims = self.claims[:limit], self.claims[limit:]
        return taken

    def complete(self, claim, load):
        self.completed.append(claim)
        load(claim.subscription, claim.repin)
        return self.outcome

    def status(self):
        return {"tenants": 1}


class Authority:
    def __init__(self, error=None):
        self.error, self.seen = error, []

    def current(self, customer, pinned, repin):
        self.seen.append((customer, pinned, repin))
        if self.error:
            raise self.error
        return PaidState(None, None, None, None, False, None)


def claim(customer="cus_a"):
    from gvai.postgresql_billing import Claim
    return Claim(customer, None, False, 1, "active", 0.0)


def test_reconciler_processes_one_claim_per_step_with_its_pinned_subscription():
    store, authority = Store(), Authority()
    store.claims = [claim("cus_a"), claim("cus_b")]
    reconciler = Reconciler(store, authority, bounded()[0])
    assert reconciler.step() == 1 and reconciler.step() == 1 and reconciler.step() == 0
    assert [c[0] for c in authority.seen] == ["cus_a", "cus_b"]
    assert reconciler.counters == {"applied_eligible": 2}


def test_database_outage_during_complete_grants_nothing():
    class Down(Store):
        def complete(self, claim, load):
            raise BillingUnavailable("down", transient=True)

    reconciler = Reconciler(Down(), Authority(), bounded()[0])
    assert reconciler.process(claim()) == "database_unavailable"


def test_heartbeat_is_private_atomic_and_contains_no_identifiers(tmp_path):
    path = tmp_path / "beat.json"
    store = Store()
    reconciler = Reconciler(store, Authority(), bounded()[0], heartbeat_path=str(path), wall=lambda: 1234.9)
    reconciler.process(claim("cus_secretcustomer"))
    reconciler.heartbeat()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    text = path.read_text()
    assert json.loads(text)["at"] == 1234
    assert "cus_" not in text and not (tmp_path / "beat.json.tmp").exists()


def test_heartbeat_refuses_symlink_target(tmp_path):
    target = tmp_path / "victim"
    target.write_text("keep")
    (tmp_path / "beat.json.tmp").symlink_to(target)
    reconciler = Reconciler(Store(), Authority(), bounded()[0], heartbeat_path=str(tmp_path / "beat.json"))
    with pytest.raises(OSError):
        reconciler.heartbeat()
    assert target.read_text() == "keep"


def test_serve_stops_cleanly_and_survives_worker_errors(caplog):
    caplog.set_level(logging.DEBUG)

    class Broken(Store):
        def claim_due(self, limit, seconds):
            raise RuntimeError("synthetic-secret-detail")

    stopped = threading.Event()
    reconciler = Reconciler(
        Broken(), Authority(), bounded()[0],
        ReconcilerSettings(workers=1, idle_seconds=0.1, heartbeat_seconds=0.1),
    )
    thread = threading.Thread(target=reconciler.serve, args=(stopped,))
    thread.start()
    threading.Event().wait(0.4)
    stopped.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert "synthetic-secret-detail" not in caplog.text


def test_reconciler_entry_functions_are_exactly_the_non_owner_surface():
    assert {name.split("(")[0] for name in RECONCILER_ENTRY_FUNCTIONS} == {
        "reconcile_claim_due_v1", "reconcile_signal_v1", "reconcile_apply_v1",
        "reconcile_fail_v1", "reconcile_status_v1",
    }
    assert not any("resume" in name or "claim_one" in name or "resubscribe" in name
                   for name in RECONCILER_ENTRY_FUNCTIONS)


def test_billing_config_accepts_only_test_mode_keys_and_never_prints_secrets():
    common = ("whsec_" + "w" * 24, "price_test_1", "https://example.test/a", "https://example.test/b",
              "https://example.test/c")
    for key in ("sk_test_" + "k" * 24, "rk_test_" + "k" * 24):
        config = BillingConfig(key, *common)
        assert key not in repr(config)
    for key in ("sk_live_" + "k" * 24, "rk_live_" + "k" * 24, "k" * 30):
        with pytest.raises(Exception):
            BillingConfig(key, *common)
