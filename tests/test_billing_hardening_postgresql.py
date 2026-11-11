"""Bounded integrity, entitlement and cutover schedules on disposable PostgreSQL only."""
import json
import os
from pathlib import Path
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

if os.environ.get('GVAI_RUN_RECONCILER_POSTGRES')!='1' and os.environ.get('GVAI_REQUIRE_RECONCILER_POSTGRES')!='1':
    pytest.skip('Disposable PostgreSQL opt-in required.',allow_module_level=True)

import psycopg
from tests.pg_support import MIGRATIONS,disposable_postgres
from tests.test_reconciler_postgresql import Env,paid
from tests.test_legacy_billing_upgrade_postgresql import install,credential,reserve,ledger
from gvai.self_service import PostgreSQLSelfServiceStore,SelfService,SelfServiceError

REQUIRE='GVAI_REQUIRE_RECONCILER_POSTGRES'
M011='011_legacy_billing_quarantine_v1.sql'
M012='012_bounded_billing_integrity_v1.sql'


@pytest.fixture()
def hardened():
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(M011)]) as server:
        env=Env(server)
        legacy,legacy_customer=env.tenant(checkout=False)
        install(env,M011)
        install(env,M012)
        tenant,customer=env.tenant()
        paid(env,customer)
        key_resource=credential(env,tenant,customer)
        token=b'd'*32
        env.owner.execute("INSERT INTO gvai_authority.customer_accounts(tenant_ref,token_verifier) VALUES(%s,%s)",(tenant,token))
        store=PostgreSQLSelfServiceStore(lambda: server.connect('m2_owner'),verifier_secret=b's'*32)
        yield env,legacy,tenant,customer,token,store,key_resource


def test_status_key_and_quota_use_same_hold_predicate(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    assert store.status(token)['entitled'] is True
    env.signal(customer,'evt_hardening_hold',env.now()-1,denial=True)
    env.owner.execute("UPDATE gvai_authority.billing_customers SET eligible=true,verified_until=clock_timestamp()+interval '1 minute',access_until=clock_timestamp()+interval '1 day' WHERE tenant_ref=%s",(tenant,))
    assert store.status(token)['entitled'] is False
    with pytest.raises(SelfServiceError) as rejected:
        store.claim_key(token)
    assert rejected.value.code=='payment_required'
    assert reserve(env,key_resource,'held')=='unauthorized'
    assert env.owner.execute('SELECT key_id FROM gvai_authority.customer_accounts WHERE tenant_ref=%s',(tenant,)).fetchone()==(None,)


def test_derived_violation_accounting_rollback_and_privileges(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    root=env.owner.execute('SELECT invalid_count,generation FROM gvai_authority.billing_integrity_root').fetchone()
    with env.owner.transaction(force_rollback=True):
        env.owner.execute('UPDATE gvai_authority.billing_reconcile_state SET denial_event=NULL WHERE tenant_ref=%s',(legacy,))
        assert env.owner.execute('SELECT invalid_count FROM gvai_authority.billing_integrity_root').fetchone()==(1,)
        assert env.owner.execute('SELECT gvai_authority.billing_integrity_ready_v12()').fetchone()==(False,)
    assert env.owner.execute('SELECT invalid_count,generation FROM gvai_authority.billing_integrity_root').fetchone()==root
    for table in ('billing_integrity_root','billing_integrity_cases','billing_integrity_faults'):
        for role in ('m2_runtime','m2_reconciler'):
            with env.server.connect(role) as connection:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    connection.execute('SELECT * FROM gvai_authority.'+table)
    with pytest.raises(psycopg.errors.RaiseException,match='sealed integrity metadata'):
        env.owner.execute('UPDATE gvai_authority.billing_integrity_root SET invalid_count=0')
    for function in ('billing_upgrade_audit_v12()','billing_entitlement_state_v12(bigint)'):
        for role in ('m2_runtime','m2_reconciler'):
            assert env.owner.execute('SELECT has_function_privilege(%s,%s,\'EXECUTE\')',(role,'gvai_authority.'+function)).fetchone()==(False,)
    assert env.owner.execute('SELECT gvai_authority.billing_upgrade_audit_v12()').fetchone()==(True,)


def test_readiness_change_between_authentication_and_key_check_is_denied(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    reached,proceed=threading.Event(),threading.Event()
    @contextmanager
    def paused_connection():
        with env.server.connect('m2_owner') as connection:
            class Cursor:
                def __enter__(self):
                    self.cursor=connection.cursor(); return self
                def __exit__(self,*args):
                    return self.cursor.__exit__(*args)
                def execute(self,sql,args=None):
                    if sql.startswith('SELECT gvai_authority.billing_entitlement_state_v12'):
                        reached.set(); assert proceed.wait(10)
                    return self.cursor.execute(sql,args)
                def __getattr__(self,name):
                    return getattr(self.cursor,name)
            class Connection:
                def cursor(self): return Cursor()
            yield Connection()
    paused=PostgreSQLSelfServiceStore(paused_connection,verifier_secret=b's'*32)
    with ThreadPoolExecutor(1) as executor:
        result=executor.submit(paused.claim_key,token)
        assert reached.wait(10)
        env.owner.execute('UPDATE gvai_authority.billing_reconcile_state SET denial_event=NULL WHERE tenant_ref=%s',(legacy,))
        proceed.set()
        with pytest.raises(SelfServiceError) as rejected: result.result(10)
        assert rejected.value.code=='unavailable'
    with pytest.raises(SelfServiceError) as rejected: store.status(token)
    assert rejected.value.code=='unavailable'
    assert reserve(env,key_resource,'unready')=='unauthorized'
    assert env.owner.execute('SELECT key_id FROM gvai_authority.customer_accounts WHERE tenant_ref=%s',(tenant,)).fetchone()==(None,)


def test_invalid_credentials_do_not_evaluate_readiness(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    with env.owner.transaction(force_rollback=True):
        env.owner.execute("CREATE OR REPLACE FUNCTION gvai_authority.billing_integrity_ready_v12() RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gvai_authority,pg_temp AS $$ BEGIN RAISE EXCEPTION 'readiness probe'; END $$")
        assert env.owner.execute("SELECT gvai_authority.reserve_paid_v1(repeat('f',32),decode(repeat('a',64),'hex'),'m2-test',1,'disposable','invalid_probe',%s,repeat('a',64))",(key_resource[1],)).fetchone()==('unauthorized',)
        with pytest.raises(psycopg.errors.RaiseException,match='readiness probe'):
            with env.owner.transaction():
                env.owner.execute("SELECT gvai_authority.reserve_paid_v1(%s,decode(repeat('c',64),'hex'),'m2-test',1,'disposable','valid_probe',%s,repeat('a',64))",key_resource)


def test_credential_expiry_is_rechecked_after_billing_lock_wait(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    env.owner.execute("INSERT INTO gvai_authority.customer_credentials(key_id,tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,expires_at) SELECT repeat('e',32),tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,clock_timestamp()+interval '2 seconds' FROM gvai_authority.customer_credentials WHERE key_id=%s",(key_resource[0],))
    begun=threading.Event()
    def expired_summary():
        with env.server.connect('m2_runtime') as runtime:
            begun.set()
            return runtime.execute("SELECT * FROM gvai_authority.paid_usage_v1(repeat('e',32),decode(repeat('c',64),'hex'),%s)",(key_resource[1],)).fetchone()
    with ThreadPoolExecutor(1) as executor:
        with env.owner.transaction():
            env.owner.execute('SELECT tenant_ref FROM gvai_authority.billing_customers WHERE tenant_ref=%s FOR UPDATE',(tenant,))
            future=executor.submit(expired_summary)
            assert begun.wait(5)
            time.sleep(2.2)
            assert not future.done()
        assert future.result(10) is None


def test_full_audit_latches_trigger_bypass_corruption(hardened):
    env,legacy,tenant,customer,token,store,key_resource=hardened
    # Explicit trusted-owner fault: ordinary roles cannot disable these triggers.
    with env.owner.transaction():
        env.owner.execute('ALTER TABLE gvai_authority.billing_legacy_upgrade_cases DISABLE TRIGGER USER')
        env.owner.execute("UPDATE gvai_authority.billing_legacy_upgrade_cases SET inventory=jsonb_set(inventory,'{source}','\"corrupt\"') WHERE tenant_ref=%s",(legacy,))
        env.owner.execute('ALTER TABLE gvai_authority.billing_legacy_upgrade_cases ENABLE TRIGGER USER')
    assert env.owner.execute('SELECT gvai_authority.billing_legacy_case_valid_v12(%s)',(legacy,)).fetchone()==(False,)
    assert env.owner.execute('SELECT gvai_authority.billing_upgrade_audit_v12()').fetchone()==(False,)
    assert env.owner.execute('SELECT gvai_authority.billing_integrity_ready_v12()').fetchone()==(False,)
    with pytest.raises(SelfServiceError): store.status(token)
    assert reserve(env,key_resource,'latched')=='unauthorized'
    with pytest.raises(psycopg.errors.RaiseException):
        env.owner.execute('DELETE FROM gvai_authority.billing_integrity_faults')


@pytest.mark.parametrize('prior',['009_subscription_reconciliation_v1.sql','010_subscription_denial_hold_v1.sql'])
def test_in_flight_writer_and_outside_transaction_read_cannot_cross_cutover(prior):
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(prior)+1]) as server:
        env=Env(server)
        tenant,customer=env.tenant(); paid(env,customer)
        outside=env.signal(customer,'evt_outside_read',env.now())[3]
        ticket=env.claim(customer)[3]
        started,finished=threading.Event(),threading.Event()
        errors=[]
        def migrate():
            try:
                other=Env(server)
                started.set()
                if prior.startswith('009'): install(other,'010_subscription_denial_hold_v1.sql')
                install(other,M011)
                install(other,M012)
            except Exception as error: errors.append(error)
            finally: finished.set()
        with env.rec.transaction():
            assert env.apply(customer,ticket,eligible=False)=='applied_denied'
            thread=threading.Thread(target=migrate);thread.start()
            assert started.wait(5)
            # Migration must wait for this real, uncommitted writer's table/row locks.
            deadline=time.monotonic()+3
            while not env.owner.execute("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND pid<>pg_backend_pid() AND wait_event_type='Lock')").fetchone()[0]:
                assert time.monotonic()<deadline
                time.sleep(.02)
            assert not finished.is_set()
        thread.join(15)
        assert not thread.is_alive() and not errors
        assert env.apply(customer,outside)=='ticket_invalid'
        assert env.apply(customer,env.claim(customer)[3])=='applied_denied'
        assert env.billing(customer)[:3]==(False,False,False)


def test_cutover_lock_timeout_leaves_no_partial_inventory_or_ledger_change():
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(M011)]) as server:
        env=Env(server);tenant,customer=env.tenant();paid(env,customer)
        before=ledger(env)
        with env.rec.transaction():
            env.rec.execute('SELECT * FROM gvai_authority.reconcile_status_v1()')
            other=Env(server)
            with pytest.raises(psycopg.errors.LockNotAvailable): install(other,M011)
            other.owner.execute('ROLLBACK')
        assert env.owner.execute("SELECT to_regclass('gvai_authority.billing_legacy_upgrade_run')").fetchone()==(None,)
        assert ledger(env)==before and env.billing(customer)[0] is True


def percentiles(values):
    values=sorted(values)
    return {name:round(values[min(len(values)-1,int(len(values)*p))]*1000,3) for name,p in [('p50_ms',.5),('p95_ms',.95),('p99_ms',.99)]}


@pytest.mark.parametrize('size',[100,1000,10000])
def test_measured_disposable_cohort_load(size):
    with disposable_postgres(REQUIRE,migrations=MIGRATIONS[:MIGRATIONS.index(M011)]) as server:
        env=Env(server)
        env.owner.execute("INSERT INTO gvai_authority.tenants(tenant_id,status) SELECT 'cohort-'||g,'active' FROM generate_series(1,%s) g",(size,))
        env.owner.execute("INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id) SELECT tenant_ref,'cus_cohort_'||tenant_ref FROM gvai_authority.tenants")
        install(env,M011)
        tenant,customer=env.tenant();paid(env,customer)
        key_resource=credential(env,tenant,customer)
        repeats=5 if size==10000 else 20
        result={'cohort':size,'workers':4,'requests_per_worker':repeats,'samples':{}}
        total_reserved=0
        def renew(target):
            ticket=target.claim(customer)[3]
            floor=target.state(customer)[3]
            observed=max(target.now(),floor+1)
            return target.apply(customer,ticket,obs=(observed,observed))
        for phase in ('011','012'):
            if phase=='012': install(env,M012)
            for kind in ('invalid','valid'):
                assert renew(env)=='applied_eligible'
                stopped=threading.Event();poll_times=[];poll_errors=[];margins=[]
                def poll():
                    other=Env(server);other.periods=env.periods.copy()
                    try:
                        while not stopped.is_set():
                            stamp=time.perf_counter()
                            outcome=renew(other)
                            poll_times.append(time.perf_counter()-stamp)
                            if outcome!='applied_eligible': poll_errors.append(outcome)
                            margins.append(float(other.owner.execute('SELECT extract(epoch FROM verified_until-clock_timestamp()) FROM gvai_authority.billing_customers WHERE tenant_ref=%s',(tenant,)).fetchone()[0]))
                            stopped.wait(1.1)
                    except Exception as error: poll_errors.append(type(error).__name__)
                    finally: other.rec.close();other.owner.close()
                poller=threading.Thread(target=poll) if kind=='valid' else None
                if poller: poller.start()
                def worker(index):
                    latencies=[];outcomes=[]
                    with server.connect('m2_runtime') as connection:
                        connection.autocommit=True
                        for n in range(repeats):
                            stamp=time.perf_counter()
                            row=connection.execute("SELECT gvai_authority.reserve_paid_v1(%s,decode(repeat('c',64),'hex'),'m2-test',1,'disposable',%s,%s,repeat('a',64))",(key_resource[0] if kind=='valid' else 'f'*32,f'{phase}_{kind}_{index}_{n}',key_resource[1])).fetchone()
                            latencies.append(time.perf_counter()-stamp);outcomes.append(row[0])
                    return latencies,outcomes
                stamp=time.perf_counter()
                with ThreadPoolExecutor(4) as executor: samples=list(executor.map(worker,range(4)))
                seconds=time.perf_counter()-stamp
                stopped.set()
                if poller:
                    poller.join(30)
                    assert not poller.is_alive()
                times=[v for sample,_ in samples for v in sample];outcomes=[v for _,sample in samples for v in sample]
                if kind=='invalid': assert set(outcomes)=={'unauthorized'}
                elif phase=='012': assert set(outcomes)=={'reserved'} and not poll_errors and min(margins)>0
                else: assert set(outcomes)<={'reserved','unauthorized'}
                reserved=outcomes.count('reserved');total_reserved+=reserved
                result['samples'][phase+'_'+kind]={**percentiles(times),'requests':len(times),'reserved':reserved,'unauthorized':outcomes.count('unauthorized'),'seconds':round(seconds,4),'rps':round(len(times)/seconds,2),'errors':0,
                    'poll_count':len(poll_times),'poll_errors':poll_errors,'poll_latency':percentiles(poll_times) if poll_times else None,'minimum_lease_margin_s':round(min(margins),3) if margins else None}
        assert env.owner.execute('SELECT consumed FROM gvai_authority.billing_periods WHERE tenant_ref=%s',(tenant,)).fetchone()==(total_reserved,)
        assert env.owner.execute('SELECT gvai_authority.billing_upgrade_audit_v12()').fetchone()==(True,)
        # The function contract references root/run/fault tables, not cohort scans.
        definition=env.owner.execute("SELECT pg_get_functiondef('gvai_authority.billing_integrity_ready_v12()'::regprocedure)").fetchone()[0]
        assert 'billing_legacy_upgrade_cases' not in definition and 'billing_denial_recoveries' not in definition
        path=Path('/tmp/gvai-m2-hardening')
        path.mkdir(exist_ok=True)
        (path/f'load-{size}-{os.getpid()}.json').write_text(json.dumps(result,indent=2))
