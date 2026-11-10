"""Disposable-PostgreSQL tests of the migration 009 reconciliation functions and role boundary.

Opt in with GVAI_RUN_RECONCILER_POSTGRES=1. GVAI_REQUIRE_RECONCILER_POSTGRES=1 (CI) turns
every missing prerequisite into a failure instead of a skip.
"""

from __future__ import annotations

import itertools
import os
import threading

import pytest

from tests.pg_support import disposable_postgres

REQUIRE = "GVAI_REQUIRE_RECONCILER_POSTGRES"
if os.environ.get("GVAI_RUN_RECONCILER_POSTGRES") != "1" and os.environ.get(REQUIRE) != "1":
    pytest.skip("Set GVAI_RUN_RECONCILER_POSTGRES=1 to run disposable PostgreSQL tests.", allow_module_level=True)

psycopg = pytest.importorskip("psycopg") if os.environ.get(REQUIRE) != "1" else __import__("psycopg")

A = "gvai_authority."
counter = itertools.count(1)


@pytest.fixture(scope="module")
def pg():
    with disposable_postgres(REQUIRE) as server:
        yield server


class Env:
    def __init__(self, server):
        self.server = server
        self.owner = server.connect("m2_owner")
        self.owner.autocommit = True
        self.rec = server.connect("m2_reconciler")
        self.rec.autocommit = True
        self.last = {}
        self.periods = {}

    def tick(self, customer) -> int:
        # Per-customer strictly increasing Stripe-side second, bounded so it cannot approach the skew limit.
        self.last[customer] = max(self.now(), self.last.get(customer, 0) + 1)
        assert self.last[customer] - self.now() < 20, "test helper drifted toward the skew bound"
        return self.last[customer]

    def due_in(self, customer) -> float:
        return float(self.owner.execute(
            "SELECT extract(epoch FROM s.next_due_at-clock_timestamp()) FROM gvai_authority.billing_reconcile_state s "
            "JOIN gvai_authority.billing_customers b USING(tenant_ref) WHERE b.customer_id=%s", (customer,),
        ).fetchone()[0])

    def make_due(self):
        self.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp() "
                           "WHERE next_due_at<>'infinity'")

    def now(self) -> int:
        return int(self.owner.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetchone()[0])

    def tenant(self, *, subscription=True, checkout=True):
        n = next(counter)
        tenant_ref = self.owner.execute(
            "INSERT INTO gvai_authority.tenants(tenant_id,status) VALUES(%s,'active') RETURNING tenant_ref",
            (f"tenant-{n}",),
        ).fetchone()[0]
        customer = f"cus_t{n}"
        self.owner.execute(
            "INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id) VALUES(%s,%s)",
            (tenant_ref, customer),
        )
        if checkout:
            self.owner.execute(
                "UPDATE gvai_authority.billing_customers SET checkout_started_at=clock_timestamp() "
                "WHERE tenant_ref=%s", (tenant_ref,),
            )
        return tenant_ref, customer

    def claim(self, customer, seconds=30):
        row = self.owner.execute("SELECT * FROM gvai_authority.reconcile_claim_one_v1(%s,%s)", (customer, seconds)).fetchone()
        return row

    def apply(self, customer, ticket, *, obs=None, sub=None, invoice=None, start=None, end=None,
              eligible=True, access=None, terminal=False):
        sub = sub or "sub_" + customer
        invoice = invoice or "in_" + customer
        now = self.now()
        # A Stripe invoice period is immutable: derive it once per invoice, never from the wall clock per call.
        start = self.periods.setdefault((customer, invoice), now - 10) if start is None else start
        end = start + 30 * 86400 if end is None else end
        access = end if access is None else access
        low, high = obs if obs else (self.tick(customer),) * 2
        return self.rec.execute(
            "SELECT gvai_authority.reconcile_apply_v1(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (customer, ticket, low, high, sub, invoice if eligible else None, start if eligible else None,
             end if eligible else None, eligible, access if eligible else None, terminal),
        ).fetchone()[0]

    def billing(self, customer):
        return self.owner.execute(
            "SELECT eligible, verified_until > clock_timestamp(), access_until > clock_timestamp(), revoked, "
            "subscription_id, subscription_terminal_at IS NOT NULL, extract(epoch FROM verified_until) "
            "FROM gvai_authority.billing_customers WHERE customer_id=%s", (customer,),
        ).fetchone()

    def state(self, customer):
        return self.owner.execute(
            "SELECT s.phase, s.last_outcome, s.consecutive_failures, s.stripe_floor, s.applied_min, "
            "s.claim_ticket IS NOT NULL FROM gvai_authority.billing_reconcile_state s "
            "JOIN gvai_authority.billing_customers b USING(tenant_ref) WHERE b.customer_id=%s", (customer,),
        ).fetchone()

    def signal(self, customer, event, created, denial=False, digest="a" * 64):
        return self.rec.execute(
            "SELECT * FROM gvai_authority.reconcile_signal_v1(%s,%s,%s,%s,%s)",
            (customer, event, digest, created, denial),
        ).fetchone()


@pytest.fixture()
def env(pg):
    return Env(pg)


def paid(env, customer, sub=None, invoice=None):
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, sub=sub, invoice=invoice) == "applied_eligible"
    return ticket


def test_role_has_only_the_five_functions_and_no_table_access(env):
    _, customer = env.tenant()
    for statement in (
        "SELECT * FROM gvai_authority.billing_customers",
        "UPDATE gvai_authority.billing_customers SET eligible=true",
        "SELECT * FROM gvai_authority.billing_reconcile_state",
        "SELECT * FROM gvai_authority.billing_reconcile_tickets",
        "SELECT * FROM gvai_authority.billing_periods",
        "INSERT INTO gvai_authority.billing_events(event_id,tenant_ref,payload_hash) VALUES('evt_1',1,repeat('a',64))",
        "SELECT * FROM gvai_authority.reconcile_claim_one_v1('" + customer + "',30)",
        "SELECT gvai_authority.reconcile_resume_v1('" + customer + "')",
        "SELECT gvai_authority.reconcile_begin_resubscribe_v1('" + customer + "')",
        "SELECT gvai_authority.reconcile_release_v1(1,1,now(),'x',false)",
        "SELECT gvai_authority.reserve_paid_v1('t','\\x00','r',1,'a','b','c','d')",
        "CREATE TABLE gvai_authority.x(a int)",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            env.rec.execute(statement)
    config = env.owner.execute(
        "SELECT p.proname, p.prosecdef, p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='gvai_authority' AND p.proname LIKE 'reconcile_%' AND p.proname<>'reconcile_release_v1'"
    ).fetchall()
    assert config
    for name, definer, settings in config:
        assert definer, name
        assert settings == ["search_path=pg_catalog, gvai_authority, pg_temp"], name
    assert not env.owner.execute(
        "SELECT 1 FROM information_schema.routine_privileges WHERE grantee='PUBLIC' "
        "AND routine_schema='gvai_authority' AND routine_name LIKE 'reconcile_%'"
    ).fetchall()


def test_claim_bounds_and_single_flight(env):
    _, customer = env.tenant()
    for limit, seconds in ((0, 30), (101, 30), (5, 9), (5, 56), (None, 30)):
        with pytest.raises(psycopg.errors.RaiseException):
            env.rec.execute("SELECT * FROM gvai_authority.reconcile_claim_due_v1(%s,%s)", (limit, seconds))
    first = env.claim(customer)
    assert first and first[2] is False
    assert env.claim(customer) is None, "A tenant with a live claim is not claimed twice."
    assert env.state(customer)[5] is True


def test_apply_grants_lease_anchored_at_claim_start_and_is_single_use(env):
    _, customer = env.tenant()
    row = env.claim(customer)
    ticket, started = row[3], row[4]
    assert env.apply(customer, ticket) == "applied_eligible"
    eligible, leased, access, revoked, sub, terminal, until = env.billing(customer)
    assert (eligible, leased, access, revoked, sub, terminal) == (True, True, True, False, "sub_" + customer, False)
    assert abs(float(until) - (started.timestamp() + 60)) < 0.01, "Lease starts at ticket issue, never at apply time."
    assert env.state(customer)[0:2] == ("active", "applied_eligible")
    assert env.apply(customer, ticket) == "ticket_invalid"


def test_ticket_is_tenant_bound_and_expires(env):
    _, one = env.tenant()
    _, two = env.tenant()
    ticket = env.claim(one)[3]
    assert env.apply(two, ticket) == "ticket_invalid"
    assert env.billing(two)[0] is False
    expired = env.claim(two, 10)[3]
    env.owner.execute(
        "UPDATE gvai_authority.billing_reconcile_tickets SET started_at=clock_timestamp()-interval '2 seconds', "
        "expires_at=clock_timestamp()-interval '1 second' WHERE ticket_id=%s", (expired,),
    )
    assert env.apply(two, expired) == "ticket_invalid"
    assert env.billing(two)[0] is False


def test_unknown_ticket_and_unmapped_customer_grant_nothing(env):
    _, customer = env.tenant()
    assert env.apply(customer, 987654321) == "ticket_invalid"
    with pytest.raises(psycopg.errors.RaiseException):
        env.apply("cus_nobody", 1)
    assert env.billing(customer)[0] is False


def test_stale_paid_snapshot_cannot_pass_the_stripe_floor(env):
    _, customer = env.tenant()
    now = env.now()
    ticket = env.claim(customer)[3]
    env.signal(customer, "evt_stale1", now, denial=False)
    assert env.apply(customer, ticket, obs=(now, now)) == "stale_snapshot"
    assert env.billing(customer)[0] is False
    assert env.state(customer)[1] == "stale_snapshot"


def test_observation_boundaries_are_enforced(env):
    _, customer = env.tenant()
    now = env.now()
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, obs=(now - 120, now - 120)) == "clock_skew"
    assert 0 < env.due_in(customer) <= 6, "A failed attempt retries after bounded backoff."
    env.make_due()
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, obs=(now, now + 3600)) == "clock_skew"
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.rec.execute(
        "SELECT gvai_authority.reconcile_apply_v1(%s,%s,NULL,NULL,%s,'in_9',%s,%s,true,%s,false)",
        (customer, ticket, "sub_" + customer, now - 5, now + 86400, now + 86400),
    ).fetchone()[0] == "observation_missing"
    assert env.billing(customer)[0] is False


def test_denied_snapshot_always_applies_and_suspends(env):
    _, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, eligible=False, terminal=True) == "applied_denied"
    eligible, leased, access, revoked, _, terminal, _ = env.billing(customer)
    assert (eligible, leased, access, terminal) == (False, False, False, True)
    assert env.state(customer)[0] == "terminal"


def test_fresh_denial_event_suspends_immediately_but_old_replay_does_not(env):
    _, customer = env.tenant()
    paid(env, customer)
    now = env.now()
    old = env.signal(customer, "evt_old1", now - 4000, denial=True, digest="b" * 64)
    assert old[0] is False
    assert env.billing(customer)[0] is True, "A replayed old denial must not suspend a paid customer."
    fresh = env.signal(customer, "evt_new1", now, denial=True, digest="c" * 64)
    assert fresh[0] is False and fresh[3] is not None
    assert env.billing(customer)[:2] == (False, False)


def test_stale_paid_snapshot_after_cancellation_event_cannot_restore_access(env):
    _, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    now = env.now()
    env.signal(customer, "evt_cancel", now, denial=True, digest="d" * 64)
    assert env.billing(customer)[0] is False
    assert env.apply(customer, ticket, obs=(now - 1, now)) == "stale_snapshot"
    assert env.billing(customer)[:2] == (False, False)


def test_fresher_paid_snapshot_after_a_denial_event_is_the_stripe_truth(env):
    _, customer = env.tenant()
    paid(env, customer)
    now = env.now()
    event = env.signal(customer, "evt_fail1", now, denial=True, digest="e" * 64)
    assert env.billing(customer)[0] is False
    assert env.apply(customer, event[3], obs=(now + 1, now + 1)) == "applied_eligible"
    assert env.billing(customer)[0:2] == (True, True)
    assert env.state(customer)[2] == 0


def test_event_idempotency_and_collision(env):
    _, one = env.tenant()
    _, two = env.tenant()
    now = env.now()
    signalled = env.signal(one, "evt_same", now, digest="1" * 64)
    assert env.apply(one, signalled[3], obs=(now + 1, now + 1)) in {"applied_eligible", "stale_snapshot"}
    ticket = env.signal(one, "evt_same2", now, digest="2" * 64)[3]
    assert env.apply(one, ticket, obs=(now + 1, now + 1), eligible=False, terminal=False) == "applied_denied"
    assert env.signal(one, "evt_same2", now, digest="2" * 64)[0] is True
    with pytest.raises(psycopg.errors.RaiseException):
        env.signal(one, "evt_same2", now, digest="3" * 64)
    with pytest.raises(psycopg.errors.RaiseException):
        env.signal(two, "evt_same2", now, digest="2" * 64)
    for bad in (("evt bad", now), ("evt_ok", 0), ("evt_ok", now + 4000)):
        with pytest.raises(psycopg.errors.RaiseException):
            env.signal(one, bad[0], bad[1])


def test_covered_event_is_acknowledged_without_regranting(env):
    _, customer = env.tenant()
    now = env.now()
    event = env.signal(customer, "evt_cover", now - 5, digest="4" * 64)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET applied_min=%s, stripe_floor=%s", (now - 1, now))
    outcome = env.apply(customer, event[3], obs=(now, now))
    assert outcome == "covered_by_newer"
    assert env.signal(customer, "evt_cover", now - 5, digest="4" * 64)[0] is True
    assert env.billing(customer)[0] is False


def test_transient_failure_keeps_lease_and_backs_off_integrity_suspends(env):
    _, customer = env.tenant()
    paid(env, customer)
    before = env.billing(customer)[6]
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,'transient','stripe_unavailable')", (customer, ticket)).fetchone()[0] == "stripe_unavailable"
    assert env.billing(customer)[6] == before and env.billing(customer)[0] is True
    assert env.state(customer)[2:3] == (1,)
    assert 3 < env.due_in(customer) <= 5.1, "Backoff applies after a transient failure."
    ticket = env.claim(customer)[3]
    assert env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,'integrity','bad_shape')", (customer, ticket)).fetchone()[0] == "suspended"
    assert env.billing(customer)[:3] == (False, False, False)
    assert env.state(customer)[0] == "needs_operator"
    for args in ((customer, 1, "weird", "x"), (customer, 1, "transient", "Bad Code")):
        with pytest.raises(psycopg.errors.RaiseException):
            env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,%s,%s)", args)


def test_needs_operator_is_not_claimed_and_resume_is_owner_only(env):
    _, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,'integrity','x')", (customer, ticket))
    batch = env.rec.execute("SELECT o_customer FROM gvai_authority.reconcile_claim_due_v1(100,30)").fetchall()
    assert (customer,) not in batch
    assert env.owner.execute("SELECT gvai_authority.reconcile_resume_v1(%s)", (customer,)).fetchone()[0] is True
    assert env.state(customer)[0] == "active"
    assert env.billing(customer)[0] is False, "Resume never restores entitlement; only a verified snapshot does."


def test_revoked_tenant_is_never_reactivated_by_a_paid_snapshot(env):
    tenant, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_customers SET revoked=true,eligible=false WHERE tenant_ref=%s", (tenant,))
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket) == "applied_denied"
    eligible, leased, access, revoked, *_ = env.billing(customer)
    assert (eligible, leased, access, revoked) == (False, False, False, True)
    env.make_due()
    assert (customer,) not in env.rec.execute("SELECT o_customer FROM gvai_authority.reconcile_claim_due_v1(100,30)").fetchall()


def test_subscription_replacement_and_period_shape_are_rejected(env):
    _, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, sub="sub_2", invoice="in_2") == "rejected_subscription_replacement_rejected"
    assert env.billing(customer)[0] is False and env.state(customer)[0] == "needs_operator"
    for index, kwargs in enumerate((
        dict(end_delta=40 * 86400), dict(access_delta=1), dict(invoice="bad"),
    )):
        _, other = env.tenant()
        ticket = env.claim(other)[3]
        now = env.now()
        start, end = now - 10, now - 10 + kwargs.get("end_delta", 30 * 86400)
        access = end + kwargs.get("access_delta", 0)
        result = env.apply(other, ticket, invoice=kwargs.get("invoice", f"in_x{index}"), start=start, end=end, access=access)
        assert result == "rejected_paid_period_rejected", kwargs
        assert env.billing(other)[0] is False


def test_paid_window_excluding_database_time_never_grants(env):
    _, customer = env.tenant()
    ticket = env.claim(customer)[3]
    now = env.now()
    assert env.apply(customer, ticket, start=now + 3600, end=now + 7200) == "applied_denied"
    assert env.billing(customer)[0] is False


def test_renewal_preserves_period_consumption_and_never_resets_quota(env):
    tenant, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("ALTER TABLE gvai_authority.billing_periods DISABLE TRIGGER USER")
    env.owner.execute("UPDATE gvai_authority.billing_periods SET consumed=77 WHERE tenant_ref=%s", (tenant,))
    env.owner.execute("ALTER TABLE gvai_authority.billing_periods ENABLE TRIGGER USER")
    for _ in range(2):
        env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
        ticket = env.claim(customer)[3]
        assert env.apply(customer, ticket) == "applied_eligible"
    assert env.owner.execute("SELECT consumed, allowance FROM gvai_authority.billing_periods WHERE tenant_ref=%s", (tenant,)).fetchall() == [(77, 100000)]
    now = env.now()
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, invoice="in_renew", start=now - 5 + 30 * 86400 - 30 * 86400, end=now + 30 * 86400) == "rejected_overlapping_period_rejected"
    assert env.owner.execute("SELECT consumed FROM gvai_authority.billing_periods WHERE tenant_ref=%s ORDER BY starts_at", (tenant,)).fetchall() == [(77,)]


def test_invoice_cannot_be_reassigned_across_tenants(env):
    _, one = env.tenant()
    _, two = env.tenant()
    paid(env, one, sub="sub_one", invoice="in_shared")
    ticket = env.claim(two)[3]
    assert env.apply(two, ticket, sub="sub_two", invoice="in_shared") == "rejected_invoice_reassignment_rejected"
    assert env.billing(two)[0] is False
    assert env.billing(one)[0] is True


def test_history_cannot_be_rewritten_by_the_reconciler_or_owner_update(env):
    tenant, customer = env.tenant()
    paid(env, customer)
    with pytest.raises(psycopg.errors.Error):
        env.owner.execute("UPDATE gvai_authority.billing_customers SET subscription_id='sub_other' WHERE tenant_ref=%s", (tenant,))
    with pytest.raises(psycopg.errors.Error):
        env.owner.execute("DELETE FROM gvai_authority.billing_events")
    with pytest.raises(psycopg.errors.Error):
        env.owner.execute("UPDATE gvai_authority.billing_subscription_history SET subscription_id='sub_z'")


def test_terminal_resubscription_requires_owner_transition_and_new_subscription(env):
    tenant, customer = env.tenant()
    paid(env, customer)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, eligible=False, terminal=True) == "applied_denied"
    # Not allowed before the owner opens a resubscription.
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, sub="sub_new", invoice="in_new") == "rejected_subscription_replacement_rejected"
    env.owner.execute("SELECT gvai_authority.reconcile_resume_v1(%s)", (customer,))
    assert env.owner.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)", (customer,)).fetchone()[0] == 1
    assert env.owner.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)", (customer,)).fetchone()[0] == 1
    env.owner.execute("UPDATE gvai_authority.billing_customers SET checkout_started_at=clock_timestamp() WHERE tenant_ref=%s", (tenant,))
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, sub="sub_new", invoice="in_new", start=env.now() - 2) == "applied_eligible"
    assert env.billing(customer)[0:2] == (True, True) and env.billing(customer)[4] == "sub_new"
    assert env.owner.execute("SELECT count(*) FROM gvai_authority.billing_subscription_history WHERE tenant_ref=%s", (tenant,)).fetchone()[0] == 2
    # Old subscription is not resurrected.
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(customer)[3]
    assert env.apply(customer, ticket, sub="sub_" + customer, invoice="in_old") == "rejected_subscription_replacement_rejected"
    assert env.billing(customer)[0] is False


def test_resubscribe_rejected_for_active_or_revoked(env):
    tenant, customer = env.tenant()
    paid(env, customer)
    assert env.owner.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)", (customer,)).fetchone()[0] == 0
    assert env.billing(customer)[0] is True, "A live subscription is untouched."
    env.owner.execute("UPDATE gvai_authority.billing_customers SET revoked=true WHERE tenant_ref=%s", (tenant,))
    with pytest.raises(psycopg.errors.RaiseException):
        env.owner.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)", (customer,))


def test_dormant_and_terminal_tenants_are_not_polled_at_high_frequency(env):
    _, dormant = env.tenant(checkout=False)
    assert env.state(dormant)[0] == "dormant"
    assert env.owner.execute(
        "SELECT s.next_due_at='infinity' FROM gvai_authority.billing_reconcile_state s "
        "JOIN gvai_authority.billing_customers b USING(tenant_ref) WHERE b.customer_id=%s", (dormant,),
    ).fetchone()[0]
    _, terminal = env.tenant()
    paid(env, terminal)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at=clock_timestamp()")
    ticket = env.claim(terminal)[3]
    env.apply(terminal, ticket, eligible=False, terminal=True)
    wait = env.due_in(terminal)
    assert 850 < wait <= 900
    active = env.tenant()[1]
    paid(env, active)
    wait = env.due_in(active)
    assert 17 < wait <= 22.5, "Active cadence is 20s plus at most 2s jitter, measured from claim start."


def test_skip_locked_gives_two_reconcilers_disjoint_claims_and_oldest_first(pg):
    env = Env(pg)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at='infinity'")
    customers = []
    for index in range(40):
        _, customer = env.tenant()
        env.owner.execute(
            "UPDATE gvai_authority.billing_reconcile_state s SET next_due_at=clock_timestamp()-make_interval(secs=>%s) "
            "FROM gvai_authority.billing_customers b WHERE b.tenant_ref=s.tenant_ref AND b.customer_id=%s",
            (1000 - index, customer),
        )
        customers.append(customer)
    results: list[list[str]] = [[], []]

    def run(slot):
        connection = pg.connect("m2_reconciler")
        connection.autocommit = True
        for _ in range(4):
            rows = connection.execute("SELECT o_customer FROM gvai_authority.reconcile_claim_due_v1(5,30)").fetchall()
            results[slot].extend(row[0] for row in rows)

    threads = [threading.Thread(target=run, args=(slot,)) for slot in (0, 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    first, second = set(results[0]), set(results[1])
    assert not first & second and len(first) + len(second) == 40
    assert set(results[0] + results[1]) == set(customers)
    batch = env.rec.execute("SELECT o_customer FROM gvai_authority.reconcile_claim_due_v1(100,30)").fetchall()
    assert batch == [], "Claimed tenants are not re-claimed within the claim window."


def test_claim_order_prevents_starvation_for_large_populations(pg):
    env = Env(pg)
    env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET next_due_at='infinity'")
    customers = []
    for index in range(200):
        _, customer = env.tenant()
        customers.append(customer)
    env.owner.execute(
        "UPDATE gvai_authority.billing_reconcile_state s SET next_due_at=clock_timestamp()-make_interval(secs=>b.tenant_ref%%500) "
        "FROM gvai_authority.billing_customers b WHERE b.tenant_ref=s.tenant_ref AND b.customer_id = ANY(%s)", (customers,),
    )
    seen: list[tuple[str, float]] = []
    for _ in range(40):
        rows = env.rec.execute("SELECT o_customer,o_lag FROM gvai_authority.reconcile_claim_due_v1(5,30)").fetchall()
        assert len(rows) <= 5
        seen.extend(rows)
    assert len({customer for customer, _ in seen}) == 200
    lags = [lag for _, lag in seen]
    first_batch_lags = lags[:5]
    assert min(first_batch_lags) >= max(lags[5:]) - 1, "The oldest-due tenants are always served first."


def test_status_is_aggregate_and_identifier_free(env):
    _, customer = env.tenant()
    paid(env, customer)
    status = env.rec.execute("SELECT gvai_authority.reconcile_status_v1()").fetchone()[0]
    text = repr(status)
    assert customer not in text and "sub_" not in text and "cus_" not in text
    assert {"phases", "due_now", "max_overdue_seconds", "in_flight", "failing", "needs_operator", "entitled",
            "lease_expiring", "lease_lapsed", "oldest_active_success_age_seconds"} <= set(status)
