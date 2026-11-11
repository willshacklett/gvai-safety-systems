"""Real populated-009 -> 010 -> 011 regressions, only on owned disposable PostgreSQL.

The final recovery waits out the REAL conservative 300-second boundary. No clocks,
barriers, signatures or production SQL are patched to make the test succeed.
"""
import os
import time
from types import SimpleNamespace

import pytest

if os.environ.get("GVAI_RUN_RECONCILER_POSTGRES") != "1" and os.environ.get("GVAI_REQUIRE_RECONCILER_POSTGRES") != "1":
    pytest.skip("Disposable reconciliation PostgreSQL opt-in required.", allow_module_level=True)

from tests.pg_support import MIGRATIONS, ROOT, disposable_postgres
from tests.test_reconciler_postgresql import Env, paid
from tests.test_stripe_billing import Stripe, config, event
from gvai.postgresql_billing import PAID_ENTRY_FUNCTIONS, RECONCILER_ENTRY_FUNCTIONS, PostgreSQLBillingStore
from gvai.private_staging import verify_database_role, StagingUnavailable
from gvai.self_service import PostgreSQLSelfServiceStore, SelfServiceError
from gvai.stripe_billing import BillingUnavailable, SubscriptionAuthority

REQUIRE = "GVAI_REQUIRE_RECONCILER_POSTGRES"
M010 = "010_subscription_denial_hold_v1.sql"
M011 = "011_legacy_billing_quarantine_v1.sql"


def install(env, name):
    env.owner.execute((ROOT / "migrations/postgresql" / name).read_text())


def credential(env, tenant, customer):
    membership = env.owner.execute(
        "INSERT INTO gvai_authority.tenant_memberships(tenant_ref,principal_id,status) "
        "VALUES(%s,%s,'active') RETURNING membership_ref", (tenant,customer)).fetchone()[0]
    resource, key = "project_"+customer, f"{tenant:032x}"
    env.owner.execute("INSERT INTO gvai_authority.resource_ownerships(resource_id,ownership_version,tenant_ref,resource_kind,status) VALUES(%s,1,%s,'evaluation','active')", (resource,tenant))
    env.owner.execute("INSERT INTO gvai_authority.customer_credentials(key_id,tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,expires_at) VALUES(%s,%s,%s,decode(repeat('c',64),'hex'),ARRAY['evaluation:run','usage:read'],'active',clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 day')", (key,tenant,membership))
    return key,resource


def reserve(env, key_resource, request):
    with env.server.connect("m2_runtime") as runtime:
        return runtime.execute("SELECT gvai_authority.reserve_paid_v1(%s,decode(repeat('c',64),'hex'),'m2-test',1,'disposable',%s,%s,repeat('a',64))", (key_resource[0],request,key_resource[1])).fetchone()[0]


def ledger(env):
    return tuple(env.owner.execute("SELECT * FROM gvai_authority."+table+" ORDER BY 1,2").fetchall()
                 for table in ("billing_periods","paid_attempts","billing_subscription_history","billing_events"))


@pytest.fixture(scope="module")
def legacy():
    with disposable_postgres(REQUIRE, migrations=MIGRATIONS[:MIGRATIONS.index(M010)]) as server:
        env = Env(server)
        customers = {}
        for label in ("denied","restored","polling","active","revoked","terminal","integrity","held"):
            tenant,customer = env.tenant()
            customers[label]=(tenant,customer)
            paid(env,customer)
        key_resource=credential(env,*customers["denied"])
        assert reserve(env,key_resource,"before_upgrade")=="reserved"
        for label in ("denied","restored"):
            _,customer=customers[label]
            signal=env.signal(customer,"evt_legacy_"+customer,env.now()-2,denial=True)
            assert env.apply(customer,signal[3],eligible=False)=="applied_denied"
            if label=="restored":
                assert env.apply(customer,env.claim(customer)[3])=="applied_eligible"
        for label in ("polling","terminal"):
            customer=customers[label][1]
            assert env.apply(customer,env.claim(customer)[3],eligible=False,terminal=label=="terminal")=="applied_denied"
        env.owner.execute("UPDATE gvai_authority.billing_customers SET revoked=true,eligible=false WHERE tenant_ref=%s", (customers["revoked"][0],))
        customer=customers["integrity"][1]
        env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,'integrity','test_integrity')", (customer,env.claim(customer)[3]))
        customers["dormant"]=env.tenant(checkout=False)
        install(env,M010)
        held=customers["held"][1]
        env.signal(held,"evt_real_hold_"+held,env.now()-2,denial=True)
        original_hold=env.owner.execute("SELECT denial_event,denial_held_since FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s", (customers["held"][0],)).fetchone()
        old=env.signal(customers["denied"][1],"evt_old_read",env.now())[3]
        before=ledger(env)
        install(env,M011)
        install(env,"012_bounded_billing_integrity_v1.sql")
        yield SimpleNamespace(env=env,customers=customers,key_resource=key_resource,old=old,before=before,original_hold=original_hold)


def test_populated_denied_and_automatically_restored_customers_stay_quarantined(legacy):
    env=legacy.env
    assert ledger(env)==legacy.before
    for label,(tenant,customer) in legacy.customers.items():
        assert env.billing(customer)[:3]==(False,False,False)
        case=env.owner.execute("SELECT marker_id,source,recovery_not_before,inventory,inventory_hash,classification FROM gvai_authority.billing_legacy_upgrade_cases WHERE tenant_ref=%s", (tenant,)).fetchone()
        assert case[0]=="legacy_upgrade_"+str(tenant) and not case[0].startswith("evt_")
        assert case[1]=="legacy_upgrade_quarantine"
        assert env.owner.execute("SELECT payload_hash,event_created FROM gvai_authority.billing_denials WHERE event_id=%s", (case[0],)).fetchone()==(case[4],case[2])
        assert case[3]["tenant_ref"]==tenant and case[3]["recovery_not_before"]==case[2]
        if label=="restored":
            assert case[3]["customer"]["eligible"] is True
            assert case[5]=="apparently_eligible_history_unknown"
        if label in ("denied","restored"):
            assert env.signal(customer,"evt_legacy_"+customer,env.now()-2,denial=True)[0] is True
        if label not in ("revoked","terminal","integrity"):
            assert env.apply(customer,env.claim(customer)[3])=="applied_denied"
            assert env.billing(customer)[:3]==(False,False,False)
    assert env.apply(legacy.customers["denied"][1],legacy.old)=="ticket_invalid"
    assert reserve(env,legacy.key_resource,"during_upgrade")=="unauthorized"
    after=ledger(env)
    assert after[:2]==legacy.before[:2] and after[3]==legacy.before[3]


def test_real_010_hold_and_integrity_revocation_and_quota_are_preserved(legacy):
    env=legacy.env
    assert env.owner.execute("SELECT denial_event,denial_held_since FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s", (legacy.customers["held"][0],)).fetchone()==legacy.original_hold
    assert env.billing(legacy.customers["revoked"][1])[3] is True
    assert env.state(legacy.customers["integrity"][1])[0]=="needs_operator"
    assert env.billing(legacy.customers["terminal"][1])[5] is True
    assert env.owner.execute("SELECT consumed FROM gvai_authority.billing_periods WHERE tenant_ref=%s", (legacy.customers["denied"][0],)).fetchone()==(1,)
    assert env.owner.execute("SELECT gvai_authority.billing_upgrade_ready_v1()").fetchone()==(True,)
    status=env.rec.execute("SELECT gvai_authority.reconcile_status_v1()").fetchone()[0]
    assert status["legacy_upgrade_ready"] is True and status["legacy_quarantine_cases"]==len(legacy.customers)
    assert all(customer not in repr(status) for _,customer in legacy.customers.values())


def test_internal_markers_are_tenant_bound_immutable_and_owner_only(legacy):
    env=legacy.env
    for table in ("billing_legacy_upgrade_cases","billing_legacy_upgrade_run"):
        for role in ("m2_runtime","m2_reconciler"):
            with env.server.connect(role) as connection:
                with pytest.raises(Exception) as rejected:
                    connection.execute("SELECT * FROM gvai_authority."+table)
                assert rejected.value.sqlstate=="42501"
        with pytest.raises(Exception) as rejected:
            env.owner.execute("UPDATE gvai_authority."+table+" SET "+("version=11" if table.endswith("run") else "source=source"))
        assert rejected.value.sqlstate=="P0001"
    with pytest.raises(Exception) as rejected:
        with env.owner.transaction():
            env.owner.execute("INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created) VALUES('legacy_upgrade_orphan',%s,repeat('a',64),1)", (legacy.customers["denied"][0],))
    assert rejected.value.sqlstate=="P0001"
    for role in ("m2_runtime","m2_reconciler"):
        assert env.owner.execute("SELECT has_function_privilege(%s,'gvai_authority.reconcile_recover_denial_v1(text,text,text,text,bigint,text,bigint,bigint,bigint,text,text,bigint,bigint,bigint)','EXECUTE')", (role,)).fetchone()==(False,)


def test_cross_tenant_marker_association_is_rejected_atomically(legacy):
    env=legacy.env
    tenant,_=env.tenant(checkout=False)
    other=legacy.customers["denied"][0]
    boundary=env.owner.execute("SELECT recovery_not_before FROM gvai_authority.billing_legacy_upgrade_cases LIMIT 1").fetchone()[0]
    with pytest.raises(Exception) as rejected:
        with env.owner.transaction():
            inventory=dict(tenant_ref=tenant,recovery_not_before=boundary,source="legacy_upgrade_quarantine")
            from psycopg.types.json import Jsonb
            env.owner.execute("INSERT INTO gvai_authority.billing_legacy_upgrade_cases(tenant_ref,marker_id,classification,recovery_not_before,inventory,inventory_hash) SELECT %s,%s,'dormant_history_unknown',%s,%s::jsonb,encode(gvai_authority.digest(convert_to((%s::jsonb)::text,'UTF8'),'sha256'),'hex')", (tenant,"legacy_upgrade_"+str(tenant),boundary,Jsonb(inventory),Jsonb(inventory)))
            env.owner.execute("INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created) SELECT marker_id,%s,inventory_hash,recovery_not_before FROM gvai_authority.billing_legacy_upgrade_cases WHERE tenant_ref=%s", (other,tenant))
    assert rejected.value.sqlstate in ("P0001","23503")
    assert env.owner.execute("SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases WHERE tenant_ref=%s", (tenant,)).fetchone()==(0,)
    assert env.owner.execute("SELECT gvai_authority.billing_upgrade_ready_v1()").fetchone()==(True,)


def factory(env,role):
    return lambda: env.server.connect(role)


def test_readiness_requires_committed_database_inventory_and_no_unsigned_release(legacy):
    env=legacy.env
    verify_database_role(factory(env,"m2_runtime"),entry_functions=PAID_ENTRY_FUNCTIONS)
    verify_database_role(factory(env,"m2_reconciler"),entry_functions=RECONCILER_ENTRY_FUNCTIONS)
    with env.owner.transaction(force_rollback=True):
        # Owner fault injection: ordinary roles cannot corrupt the immutable marker.
        env.owner.execute("ALTER TABLE gvai_authority.billing_legacy_upgrade_run DISABLE TRIGGER USER")
        env.owner.execute("DELETE FROM gvai_authority.billing_legacy_upgrade_run")
        assert env.owner.execute("SELECT gvai_authority.billing_upgrade_ready_v1()").fetchone()==(False,)
        customer=legacy.customers["active"][1]
        with pytest.raises(Exception,match="legacy upgrade readiness rejected"):
            with env.owner.transaction():
                env.owner.execute("UPDATE gvai_authority.billing_customers SET eligible=true WHERE customer_id=%s", (customer,))
        assert env.owner.execute("SELECT gvai_authority.reserve_paid_v1(%s,decode(repeat('c',64),'hex'),'m2-test',1,'disposable','missing_marker',%s,repeat('a',64))", legacy.key_resource).fetchone()==("unauthorized",)
    with env.owner.transaction(force_rollback=True):
        env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET denial_event=NULL WHERE tenant_ref=%s", (legacy.customers["active"][0],))
        assert env.owner.execute("SELECT gvai_authority.billing_upgrade_ready_v1()").fetchone()==(False,)
    assert env.owner.execute("SELECT gvai_authority.billing_upgrade_ready_v1()").fetchone()==(True,)


def test_committed_partial_inventory_refuses_runtime_readiness(legacy):
    env=legacy.env
    # Deliberate schema-owner fault injection; no ordinary role has this access.
    with env.owner.transaction():
        env.owner.execute("ALTER TABLE gvai_authority.billing_legacy_upgrade_run DISABLE TRIGGER USER")
        env.owner.execute("UPDATE gvai_authority.billing_legacy_upgrade_run SET inventory_count=inventory_count+1")
        env.owner.execute("ALTER TABLE gvai_authority.billing_legacy_upgrade_run ENABLE TRIGGER USER")
    try:
        for role,entries in (("m2_runtime",PAID_ENTRY_FUNCTIONS),("m2_reconciler",RECONCILER_ENTRY_FUNCTIONS)):
            with pytest.raises(StagingUnavailable):
                verify_database_role(factory(env,role),entry_functions=entries)
        with pytest.raises(SelfServiceError):
            PostgreSQLSelfServiceStore(factory(env,"m2_owner"),verifier_secret=b"s"*32)
        assert reserve(env,legacy.key_resource,"partial_inventory")=="unauthorized"
    finally:
        with env.owner.transaction():
            env.owner.execute("ALTER TABLE gvai_authority.billing_legacy_upgrade_run DISABLE TRIGGER USER")
            env.owner.execute("UPDATE gvai_authority.billing_legacy_upgrade_run SET inventory_count=inventory_count-1")
            env.owner.execute("ALTER TABLE gvai_authority.billing_legacy_upgrade_run ENABLE TRIGGER USER")


def test_missing_011_refuses_paid_reconciler_and_self_service_readiness():
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(M011)]) as server:
        env=Env(server)
        for role,entries in (("m2_runtime",PAID_ENTRY_FUNCTIONS),("m2_reconciler",RECONCILER_ENTRY_FUNCTIONS)):
            with pytest.raises(StagingUnavailable):
                verify_database_role(factory(env,role),entry_functions=entries)
        with pytest.raises(SelfServiceError):
            PostgreSQLSelfServiceStore(factory(env,"m2_owner"),verifier_secret=b"s"*32)


def test_unverifiable_future_boundary_rolls_back_instead_of_inventing_evidence():
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(M011)]) as server:
        env=Env(server)
        tenant,customer=env.tenant()
        paid(env,customer)
        env.owner.execute("UPDATE gvai_authority.billing_reconcile_state SET stripe_floor=%s WHERE tenant_ref=%s", (env.now()+10000,tenant))
        with pytest.raises(Exception,match="legacy boundary unverifiable"):
            install(env,M011)
        env.owner.execute("ROLLBACK")
        assert env.owner.execute("SELECT to_regclass('gvai_authority.billing_legacy_upgrade_run')").fetchone()==(None,)
        assert env.billing(customer)[0] is True


def test_empty_install_preserves_normal_paid_entitlement_without_quarantine():
    with disposable_postgres(REQUIRE) as server:
        env=Env(server)
        assert env.owner.execute("SELECT inventory_count FROM gvai_authority.billing_legacy_upgrade_run").fetchone()==(0,)
        tenant,customer=env.tenant()
        paid(env,customer)
        assert env.billing(customer)[:3]==(True,True,True)
        assert env.owner.execute("SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases").fetchone()==(0,)
        assert reserve(env,credential(env,tenant,customer),"fresh_install")=="reserved"


def paid_authority(env,customer,*,target_sub=None,target_invoice=None,start=None):
    # Exercise the real current-chain verifier against synthetic TEST objects.
    api=Stripe()
    label=customer.removeprefix("cus_")
    api.add(label)
    sub="sub_"+label
    invoice="in_"+label
    # Env's established immutable period is keyed by its helper's invoice naming.
    target_sub=target_sub or "sub_"+customer
    target_invoice=target_invoice or "in_"+customer
    api.subscriptions[customer]=[{"id":target_sub}]
    subscription=api.objects.pop("/v1/subscriptions/"+sub)
    subscription.update(id=target_sub,latest_invoice=target_invoice)
    start=env.periods[(customer,target_invoice)] if start is None else start
    subscription.update(current_period_start=start,current_period_end=start+30*86400)
    api.objects["/v1/subscriptions/"+target_sub]=subscription
    inv=api.objects.pop("/v1/invoices/"+invoice)
    inv.update(id=target_invoice,subscription=target_sub)
    inv["lines"]["data"][0].update(subscription=target_sub,period={"start":start,"end":start+30*86400})
    api.objects["/v1/invoices/"+target_invoice]=inv
    api.objects["/v1/payment_intents/pi_"+label]["invoice"]=target_invoice
    api.clock=env.now
    return SubscriptionAuthority(api,config(),clock=env.now),api


def test_signed_later_recovery_obeys_real_cutover_boundary_tenant_and_quota(legacy):
    env=legacy.env
    tenant,customer=legacy.customers["denied"]
    marker,boundary=env.owner.execute("SELECT marker_id,recovery_not_before FROM gvai_authority.billing_legacy_upgrade_cases WHERE tenant_ref=%s", (tenant,)).fetchone()
    # The real safety margin must elapse; never weaken production ordering for a test.
    deadline=time.monotonic()+330
    while env.now()<=boundary:
        assert time.monotonic()<deadline,"database clock failed to pass conservative boundary"
        time.sleep(0.5)
    authority,api=paid_authority(env,customer)
    store=PostgreSQLBillingStore(factory(env,"m2_owner"))
    tenant_id=env.owner.execute("SELECT tenant_id FROM gvai_authority.tenants WHERE tenant_ref=%s", (tenant,)).fetchone()[0]
    def evidence(paid_at,**overrides):
        claims=dict(customer=customer,object="invoice",id="in_"+customer,subscription="sub_"+customer,
            livemode=False,status="paid",paid=True,paid_out_of_band=False,status_transitions={"paid_at":paid_at})
        claims.update(overrides)
        return event(event_id="evt_legacy_recovery_"+customer,at=env.now(),created=env.now(),**claims)
    def release_failed_claim():
        ticket=env.owner.execute("SELECT claim_ticket FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s", (tenant,)).fetchone()[0]
        if ticket is not None:
            env.rec.execute("SELECT gvai_authority.reconcile_fail_v1(%s,%s,'transient','test_retry')", (customer,ticket))
    for at in (boundary-1,boundary):
        with pytest.raises(BillingUnavailable):
            store.recover_denial(tenant_id,marker,*evidence(at),"verified legacy payment",authority)
        release_failed_claim()
        assert env.billing(customer)[:3]==(False,False,False)
    for overrides in (dict(customer=legacy.customers["active"][1]),dict(livemode=True),dict(subscription="sub_wrong"),dict(id="in_wrong"),dict(status_transitions={"paid_at":True})):
        with pytest.raises(BillingUnavailable):
            store.recover_denial(tenant_id,marker,*evidence(boundary+1,**overrides),"verified legacy payment",authority)
        release_failed_claim()
    raw,signature=evidence(boundary+1)
    with pytest.raises(BillingUnavailable):
        store.recover_denial(tenant_id,marker,raw+b" ",signature,"verified legacy payment",authority)
    charge=api.objects["/v1/charges/ch_"+customer.removeprefix("cus_")]
    charge["disputed"]=True
    with pytest.raises(BillingUnavailable):
        store.recover_denial(tenant_id,marker,raw,signature,"verified legacy payment",authority)
    release_failed_claim()
    charge["disputed"]=False
    assert store.recover_denial(tenant_id,marker,raw,signature,"verified legacy payment",authority)=="recovered"
    assert env.billing(customer)[:3]==(True,True,True)
    assert env.owner.execute("SELECT denial_event FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s", (tenant,)).fetchone()==(None,)
    assert env.owner.execute("SELECT payment_created,denial_event FROM gvai_authority.billing_denial_recoveries WHERE tenant_ref=%s", (tenant,)).fetchone()==(boundary+1,marker)
    assert env.signal(customer,"evt_legacy_"+customer,env.now()-1000,denial=True)[0] is True
    env.signal(customer,"evt_late_legacy_"+customer,boundary,denial=True)
    assert env.billing(customer)[:3]==(True,True,True)
    assert reserve(env,legacy.key_resource,"before_upgrade")=="replay"
    assert reserve(env,legacy.key_resource,"after_upgrade")=="reserved"
    assert env.owner.execute("SELECT consumed FROM gvai_authority.billing_periods WHERE tenant_ref=%s", (tenant,)).fetchone()==(2,)
    with pytest.raises(BillingUnavailable):
        store.recover_denial(tenant_id,marker,raw,signature,"reused recovery rejected",authority)
    release_failed_claim()
    # A real 010 hold is retained, but recovery must also cross the 011 marker.
    held_tenant,held_customer=legacy.customers["held"]
    held_authority,_=paid_authority(env,held_customer)
    held_id=env.owner.execute("SELECT tenant_id FROM gvai_authority.tenants WHERE tenant_ref=%s", (held_tenant,)).fetchone()[0]
    held_raw,held_signature=event(event_id="evt_held_legacy_recovery",at=env.now(),created=env.now(),
        customer=held_customer,object="invoice",id="in_"+held_customer,subscription="sub_"+held_customer,
        livemode=False,status="paid",paid=True,paid_out_of_band=False,status_transitions={"paid_at":boundary+1})
    assert store.recover_denial(held_id,legacy.original_hold[0],held_raw,held_signature,"verified retained hold payment",held_authority)=="recovered"
    assert env.billing(held_customer)[:3]==(True,True,True)
    assert env.owner.execute("SELECT denial_event FROM gvai_authority.billing_denial_recoveries WHERE tenant_ref=%s", (held_tenant,)).fetchone()==(legacy.original_hold[0],)
    # An equal-time denial is not covered by the authenticated payment.
    env.signal(customer,"evt_equal_legacy_payment",boundary+1,denial=True)
    assert env.billing(customer)[:3]==(False,False,False)
    assert reserve(env,legacy.key_resource,"held_again")=="unauthorized"

    # Legacy terminal replacement cannot escape its marker via owner checkout approval.
    terminal_tenant,terminal_customer=legacy.customers["terminal"]
    assert env.owner.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)",(terminal_customer,)).fetchone()[0]==1
    env.owner.execute("UPDATE gvai_authority.billing_customers SET checkout_started_at=clock_timestamp() WHERE tenant_ref=%s",(terminal_tenant,))
    new_sub,new_invoice="sub_replacement_"+terminal_customer,"in_replacement_"+terminal_customer
    replacement_start=env.now()-1
    assert env.apply(terminal_customer,env.claim(terminal_customer)[3],sub=new_sub,invoice=new_invoice,start=replacement_start)=="applied_denied"
    assert env.billing(terminal_customer)[:3]==(False,False,False)
    terminal_hold=env.owner.execute("SELECT denial_event FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s",(terminal_tenant,)).fetchone()[0]
    terminal_authority,_=paid_authority(env,terminal_customer,target_sub=new_sub,target_invoice=new_invoice,start=replacement_start)
    terminal_raw,terminal_signature=event(event_id="evt_terminal_legacy_payment",at=env.now(),created=env.now(),
        customer=terminal_customer,object="invoice",id=new_invoice,subscription=new_sub,livemode=False,
        status="paid",paid=True,paid_out_of_band=False,status_transitions={"paid_at":boundary+1})
    terminal_id=env.owner.execute("SELECT tenant_id FROM gvai_authority.tenants WHERE tenant_ref=%s",(terminal_tenant,)).fetchone()[0]
    assert store.recover_denial(terminal_id,terminal_hold,terminal_raw,terminal_signature,"verified terminal replacement",terminal_authority)=="recovered"
    assert env.billing(terminal_customer)[:6]==(True,True,True,False,new_sub,False)
    assert env.owner.execute("SELECT repin_allowed FROM gvai_authority.billing_customers WHERE tenant_ref=%s",(terminal_tenant,)).fetchone()==(False,)

    # Real signed/chain-verified legacy recovery serializes with a newer denial.
    from gvai.stripe_billing import verified_recovery_event
    import hashlib
    active_tenant,active_customer=legacy.customers["active"]
    active_authority,_=paid_authority(env,active_customer)
    active_raw,active_signature=event(event_id="evt_concurrent_legacy_payment",at=env.now(),created=env.now(),
        customer=active_customer,object="invoice",id="in_"+active_customer,subscription="sub_"+active_customer,
        livemode=False,status="paid",paid=True,paid_out_of_band=False,status_transitions={"paid_at":boundary+1})
    verified=verified_recovery_event(active_raw,active_signature,config(),env.now())
    state=active_authority.current(active_customer,"sub_"+active_customer,False)
    active_hold=env.owner.execute("SELECT denial_event FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=%s",(active_tenant,)).fetchone()[0]
    ticket=env.claim(active_customer)[3]
    begun,done=__import__('threading').Event(),__import__('threading').Event()
    failures=[]
    denial_at=env.now()
    def new_denial():
        try:
            other=Env(env.server);begun.set()
            other.signal(active_customer,"evt_legacy_concurrent_denial",denial_at,denial=True)
        except Exception as error: failures.append(error)
        finally: done.set()
    with env.owner.transaction():
        result=env.owner.execute("SELECT gvai_authority.reconcile_recover_denial_v1("+",".join(["%s"]*14)+")",
            (active_customer,active_hold,verified["id"],hashlib.sha256(active_raw).hexdigest(),boundary+1,
             "verified concurrent recovery",ticket,state.observed_min,state.observed_max,state.subscription,state.invoice,state.start,state.end,state.access_until)).fetchone()[0]
        assert result=="recovered"
        thread=__import__('threading').Thread(target=new_denial);thread.start()
        assert begun.wait(5) and not done.wait(.1)
    thread.join(10)
    assert not thread.is_alive() and not failures
    assert env.billing(active_customer)[:3]==(False,False,False)
    assert env.owner.execute("SELECT invalid_count FROM gvai_authority.billing_integrity_root").fetchone()==(0,)
    assert env.owner.execute("SELECT gvai_authority.billing_upgrade_audit_v12()").fetchone()==(True,)
