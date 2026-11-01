from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import secrets
import threading
import time
from types import SimpleNamespace

import pytest

from gvai.commercial_api_keys import CustomerApiKeys
from gvai.commercial_http import create_server
from gvai.commercial_identity import CommercialCapability
from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.commercial_service import CommercialEvaluationService, ServiceReason
from gvai.commercial_usage import UsageReason
from gvai.evaluation import evaluate_request
from gvai.postgresql_advisory import PostgreSQLAdvisoryUsage, PostgreSQLCustomerStore
from gvai.postgresql_reservation_authority import PostgreSQLReservationAuthority


pytestmark = pytest.mark.skipif(
    os.environ.get("GVAI_RUN_POSTGRES_INTEGRATION") != "1",
    reason="Requires explicitly authorized disposable PostgreSQL integration environment.",
)

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = AuthorityIdentity("advisory-integration", 1, "disposable-test")
TELEMETRY = {
    "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
    "repeated_action_delta": 0, "recursion_depth": 0,
}


@pytest.fixture(scope="module")
def database():
    import psycopg
    from psycopg import sql

    owner_dsn = os.environ["GVAI_TEST_POSTGRES_OWNER_DSN"]
    runtime_dsn = os.environ["GVAI_TEST_POSTGRES_RUNTIME_DSN"]

    def connect(dsn):
        connection = psycopg.connect(
            dsn, connect_timeout=3, options="-c statement_timeout=5000 -c lock_timeout=3000"
        )
        if (
            connection.info.host != "127.0.0.1"
            or not connection.info.dbname.startswith("gvai_advisory_test_")
        ):
            connection.close()
            raise RuntimeError("Integration tests require loopback disposable test database.")
        return connection

    with connect(owner_dsn) as owner, connect(runtime_dsn) as runtime:
        for connection in (owner, runtime):
            role = connection.execute(
                "SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls "
                "FROM pg_roles WHERE rolname=current_user"
            ).fetchone()
            assert role == (False, False, False, False)
        runtime_role = runtime.info.user
        assert owner.info.user != runtime_role
        assert not runtime.execute(
            "SELECT pg_has_role(current_user,%s,'MEMBER')", (owner.info.user,)
        ).fetchone()[0]
        assert owner.execute(
            "SELECT to_regnamespace('gvai_authority')"
        ).fetchone()[0] is None, "Test database must be freshly initialized."
    with psycopg.connect(owner_dsn, autocommit=True) as owner:
        for name in (
            "001_reservation_authority_v1.sql",
            "002_restricted_reservation_routine_v1.sql",
            "003_advisory_pilots_v1.sql",
        ):
            owner.execute((ROOT / "migrations/postgresql" / name).read_text())
        owner.execute(sql.SQL("GRANT USAGE ON SCHEMA gvai_authority TO {}").format(
            sql.Identifier(runtime_role)
        ))
        for signature in (
            "reserve_advisory_v1(text,bytea,text,bigint,text,text,text,text)",
            "complete_advisory_v1(text,bytea,text,text,boolean)",
            "advisory_usage_v1(text,bytea,text)",
        ):
            owner.execute(sql.SQL("GRANT EXECUTE ON FUNCTION gvai_authority."
                                  + signature + " TO {}").format(sql.Identifier(runtime_role)))
        owner.execute(
            "INSERT INTO gvai_authority.authority_state "
            "(singleton_id,authority_id,epoch,trust_domain) VALUES(1,%s,%s,%s)",
            (AUTHORITY.authority_id, AUTHORITY.epoch, AUTHORITY.trust_domain),
        )
    return SimpleNamespace(
        owner=lambda: connect(owner_dsn),
        runtime=lambda: connect(runtime_dsn),
        psycopg=psycopg,
    )


@pytest.fixture
def pilot(database):
    suffix = secrets.token_hex(6)
    now = int(time.time())
    store = PostgreSQLCustomerStore(database.owner)
    tenant, principal, project = "tenant-" + suffix, "principal-" + suffix, "project-" + suffix
    store.provision_pilot(
        tenant_id=tenant, principal_id=principal, resource_id=project,
        allowance=3, starts_at=now - 60, expires_at=now + 3600,
    )
    secret = secrets.token_bytes(32)
    keys = CustomerApiKeys(store, verifier_secret=secret)
    issued = keys.issue(
        tenant_id=tenant, principal_id=principal,
        capabilities=frozenset(CommercialCapability), expires_at=now + 3600,
    )

    def usage(factory=None):
        return PostgreSQLAdvisoryUsage(
            database.runtime if factory is None else factory,
            authority=AUTHORITY, credential_verifier_secret=secret,
        )

    return SimpleNamespace(
        tenant=tenant, principal=principal, project=project, secret=secret,
        keys=keys, key_id=issued.key_id, credential=issued.take_secret(),
        usage=usage, store=store, database=database,
    )


def evaluate(pilot, request_id="request-1", telemetry=None, service=None, project=None):
    return (service or CommercialEvaluationService(pilot.usage())).evaluate(
        pilot.credential, project or pilot.project, request_id,
        TELEMETRY if telemetry is None else telemetry, [],
    )


def counts(pilot):
    return pilot.usage().summary(pilot.credential, pilot.project)


def test_real_database_state_survives_application_restart(pilot):
    result = evaluate(pilot)
    assert result.reason is ServiceReason.EVALUATED
    assert result.evaluation.advisory_only is True
    assert result.evaluation.enforcement_applied is False
    restarted_keys = CustomerApiKeys(
        PostgreSQLCustomerStore(pilot.database.owner), verifier_secret=pilot.secret
    )
    assert restarted_keys.verify(pilot.credential).tenant_id == pilot.tenant
    assert counts(pilot).consumed == 1
    assert counts(pilot).completed == 1
    assert evaluate(pilot).reason is ServiceReason.REPLAY
    assert counts(pilot).consumed == 1


def test_real_separate_application_process_sees_persisted_accounting(pilot):
    import subprocess
    import sys

    assert evaluate(pilot).reason is ServiceReason.EVALUATED
    script = """
import json, os, sys
import psycopg
from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.postgresql_advisory import PostgreSQLAdvisoryUsage
from gvai.commercial_service import CommercialEvaluationService
input_record = json.load(sys.stdin)
usage = PostgreSQLAdvisoryUsage(
    lambda: psycopg.connect(os.environ['GVAI_TEST_POSTGRES_RUNTIME_DSN'], connect_timeout=3),
    authority=AuthorityIdentity('advisory-integration', 1, 'disposable-test'),
    credential_verifier_secret=bytes.fromhex(input_record['secret']),
)
summary = usage.summary(input_record['credential'], input_record['project'])
result = CommercialEvaluationService(usage).evaluate(
    input_record['credential'], input_record['project'], 'request-1',
    input_record['telemetry'], [],
)
print(json.dumps({'consumed': summary.consumed, 'completed': summary.completed,
                  'retry': result.reason.value}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script], check=True, capture_output=True, text=True, timeout=10,
        input=json.dumps({
            "secret": pilot.secret.hex(), "credential": pilot.credential,
            "project": pilot.project, "telemetry": TELEMETRY,
        }),
    )
    assert json.loads(result.stdout) == {"consumed": 1, "completed": 1, "retry": "replay"}


@pytest.mark.parametrize("state", ["revoked", "expired", "disabled_tenant", "disabled_member"])
def test_real_current_identity_changes_deny_before_evaluation(pilot, state):
    if state == "revoked":
        assert pilot.keys.revoke(pilot.key_id)
        assert pilot.keys.revoke(pilot.key_id)
    elif state == "expired":
        now = int(time.time())
        past_keys = CustomerApiKeys(
            pilot.store, verifier_secret=pilot.secret, clock=lambda: now - 120
        )
        expired = past_keys.issue(
            tenant_id=pilot.tenant, principal_id=pilot.principal,
            capabilities=frozenset(CommercialCapability), expires_at=now - 60,
        )
        pilot.credential = expired.take_secret()
    else:
        with pilot.database.owner() as connection:
            if state == "disabled_tenant":
                connection.execute(
                    "UPDATE gvai_authority.tenants SET status='disabled' WHERE tenant_id=%s",
                    (pilot.tenant,),
                )
            else:
                connection.execute(
                    "UPDATE gvai_authority.tenant_memberships SET status='disabled' WHERE principal_id=%s",
                    (pilot.principal,),
                )
    assert pilot.keys.verify(pilot.credential) is None
    calls = []
    service = CommercialEvaluationService(pilot.usage(), evaluator=lambda request: calls.append(request))
    assert evaluate(pilot, service=service).reason is ServiceReason.AUTHORIZATION_DENIED
    assert calls == []


def test_real_cross_tenant_project_denies(database, pilot):
    suffix = secrets.token_hex(6)
    now = int(time.time())
    foreign = "foreign-" + suffix
    PostgreSQLCustomerStore(database.owner).provision_pilot(
        tenant_id="foreign-tenant-" + suffix, principal_id="foreign-principal-" + suffix,
        resource_id=foreign, allowance=1, starts_at=now - 60, expires_at=now + 3600,
    )
    assert evaluate(pilot, project=foreign).reason is ServiceReason.AUTHORIZATION_DENIED
    assert pilot.usage().summary(pilot.credential, foreign) is None
    assert counts(pilot).consumed == 0


def test_real_usage_only_key_cannot_evaluate(pilot):
    issued = pilot.keys.issue(
        tenant_id=pilot.tenant, principal_id=pilot.principal,
        capabilities=frozenset({CommercialCapability.READ_USAGE}),
        expires_at=int(time.time()) + 3600,
    )
    pilot.credential = issued.take_secret()
    assert evaluate(pilot).reason is ServiceReason.AUTHORIZATION_DENIED
    assert counts(pilot).consumed == 0


def test_real_concurrent_final_quota_unit_cannot_overspend(pilot):
    assert evaluate(pilot, "first").reason is ServiceReason.EVALUATED
    assert evaluate(pilot, "second").reason is ServiceReason.EVALUATED
    barrier = threading.Barrier(8)

    def submit(index):
        barrier.wait(timeout=5)
        return evaluate(pilot, "race-" + str(index))

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(submit, range(8)))
    assert sum(result.reason is ServiceReason.EVALUATED for result in results) == 1
    assert sum(result.reason is ServiceReason.QUOTA_DENIED for result in results) == 7
    assert counts(pilot).consumed == 3
    assert counts(pilot).remaining == 0


def test_real_concurrent_duplicate_request_evaluates_once(pilot):
    barrier = threading.Barrier(6)
    calls = []

    def evaluator(request):
        calls.append(request["request_id"])
        return evaluate_request(request)

    service = CommercialEvaluationService(pilot.usage(), evaluator=evaluator)

    def submit(index):
        barrier.wait(timeout=5)
        return evaluate(pilot, service=service)

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(submit, range(6)))
    assert sum(result.reason is ServiceReason.EVALUATED for result in results) == 1
    assert sum(result.reason is ServiceReason.REPLAY for result in results) == 5
    assert calls == ["request-1"]
    assert counts(pilot).consumed == 1


def test_real_changed_payload_under_same_id_conflicts(pilot):
    assert evaluate(pilot).reason is ServiceReason.EVALUATED
    assert evaluate(pilot, telemetry={**TELEMETRY, "token_delta": 101}).reason is ServiceReason.CONFLICT
    assert counts(pilot).consumed == 1


def test_real_changed_project_under_same_id_conflicts(pilot):
    project = pilot.project + "-other"
    with pilot.database.owner() as connection:
        connection.execute(
            "INSERT INTO gvai_authority.resource_ownerships "
            "(tenant_ref,resource_id,ownership_version,resource_kind,status) "
            "SELECT tenant_ref,%s,1,'evaluation','active' FROM gvai_authority.tenants WHERE tenant_id=%s",
            (project, pilot.tenant),
        )
    assert evaluate(pilot).reason is ServiceReason.EVALUATED
    assert evaluate(pilot, project=project).reason is ServiceReason.CONFLICT
    assert counts(pilot).consumed == 1


@pytest.mark.parametrize("change", ["expired", "future", "disabled", "missing"])
def test_real_pilot_entitlement_changes_deny(pilot, change):
    with pilot.database.owner() as connection:
        if change == "missing":
            connection.execute(
                "DELETE FROM gvai_authority.advisory_pilots WHERE tenant_ref="
                "(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)", (pilot.tenant,),
            )
        else:
            clause = {
                "expired": "starts_at=clock_timestamp()-interval '2 hours', "
                           "expires_at=clock_timestamp()-interval '1 hour'",
                "future": "starts_at=clock_timestamp()+interval '1 hour', "
                          "expires_at=clock_timestamp()+interval '2 hours'",
                "disabled": "active=false",
            }[change]
            connection.execute(
                "UPDATE gvai_authority.advisory_pilots SET " + clause
                + " WHERE tenant_ref=(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)",
                (pilot.tenant,),
            )
    assert evaluate(pilot).reason is ServiceReason.AUTHORIZATION_DENIED


def _wait_for_database_lock(database, backend_pid):
    deadline = time.monotonic() + 5
    with database.owner() as connection:
        while time.monotonic() < deadline:
            row = connection.execute(
                "SELECT cardinality(pg_blocking_pids(%s))", (backend_pid,)
            ).fetchone()
            if row is not None and row[0] > 0:
                return
            time.sleep(0.02)
    raise AssertionError("Request did not reach the intended database lock wait.")


@pytest.mark.parametrize("expires", ["credential", "pilot"])
def test_real_expiry_during_authority_lock_wait_rolls_back_and_never_evaluates(pilot, expires):
    now = int(time.time())
    if expires == "credential":
        issued = pilot.keys.issue(
            tenant_id=pilot.tenant, principal_id=pilot.principal,
            capabilities=frozenset(CommercialCapability), expires_at=now + 2,
        )
        pilot.credential = issued.take_secret()
        expiry = now + 2
    else:
        expiry = now + 2
        with pilot.database.owner() as connection:
            connection.execute(
                "UPDATE gvai_authority.advisory_pilots SET expires_at=to_timestamp(%s) "
                "WHERE tenant_ref=(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)",
                (expiry, pilot.tenant),
            )
    connected = threading.Event()
    backend = []
    calls = []

    def connection_factory():
        connection = pilot.database.runtime()
        backend.append(connection.info.backend_pid)
        connected.set()
        return connection

    def evaluator(request):
        calls.append(request)
        return evaluate_request(request)

    service = CommercialEvaluationService(pilot.usage(connection_factory), evaluator=evaluator)
    with pilot.database.owner() as blocker:
        prior_head = blocker.execute(
            "SELECT last_sequence,last_event_hash FROM gvai_authority.authority_state FOR UPDATE"
        ).fetchone()
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(evaluate, pilot, service=service)
            try:
                assert connected.wait(timeout=3)
                _wait_for_database_lock(pilot.database, backend[0])
                blocker.execute(
                    "SELECT pg_sleep(GREATEST(0, %s-extract(epoch FROM clock_timestamp()))+0.1)",
                    (expiry,),
                )
                assert not future.done()
            finally:
                blocker.commit()
            result = future.result(timeout=10)
    assert result.reason is ServiceReason.ACCOUNTING_FAILURE
    assert result.evaluation is None
    assert calls == []
    with pilot.database.owner() as connection:
        assert connection.execute(
            "SELECT p.consumed FROM gvai_authority.advisory_pilots p "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.reservation_events e "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT COALESCE(sum(bucket.consumed),0) FROM gvai_authority.monthly_usage_buckets bucket "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.reservation_idempotency existing "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 0
        assert connection.execute(
            "SELECT last_sequence,last_event_hash FROM gvai_authority.authority_state"
        ).fetchone() == prior_head


def test_real_concurrent_revocation_winning_credential_lock_prevents_usage(pilot):
    connected = threading.Event()
    backend = []
    calls = []

    def connection_factory():
        connection = pilot.database.runtime()
        backend.append(connection.info.backend_pid)
        connected.set()
        return connection

    service = CommercialEvaluationService(
        pilot.usage(connection_factory), evaluator=lambda request: calls.append(request)
    )
    with pilot.database.owner() as revoker:
        revoker.execute(
            "UPDATE gvai_authority.customer_credentials SET status='revoked', "
            "revoked_at=clock_timestamp() WHERE key_id=%s", (pilot.key_id,),
        )
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(evaluate, pilot, service=service)
            try:
                assert connected.wait(timeout=3)
                _wait_for_database_lock(pilot.database, backend[0])
                assert not future.done()
            finally:
                revoker.commit()
            assert future.result(timeout=10).reason is ServiceReason.AUTHORIZATION_DENIED
    assert calls == []
    with pilot.database.owner() as connection:
        assert connection.execute(
            "SELECT p.consumed FROM gvai_authority.advisory_pilots p "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 0


def test_real_pilot_expiry_preserves_previously_committed_attempt_completion(pilot):
    usage = pilot.usage()
    payload = json.dumps(
        {"version": "v1", "request_id": "committed-before-expiry",
         "telemetry": TELEMETRY, "reported_effects": []},
        sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    assert usage.reserve_evaluation(
        pilot.credential, pilot.project, "committed-before-expiry", payload
    ).reason is UsageReason.RESERVED
    with pilot.database.owner() as connection:
        connection.execute(
            "UPDATE gvai_authority.advisory_pilots "
            "SET starts_at=clock_timestamp()-interval '2 hours', "
            "expires_at=clock_timestamp()-interval '1 hour' "
            "WHERE tenant_ref=(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)",
            (pilot.tenant,),
        )
    assert usage.complete(
        pilot.credential, pilot.project, "committed-before-expiry", succeeded=True
    ).reason is UsageReason.COMPLETED
    assert usage.complete(
        pilot.credential, pilot.project, "committed-before-expiry", succeeded=True
    ).reason is UsageReason.REPLAY
    assert evaluate(pilot, "committed-before-expiry").reason is ServiceReason.AUTHORIZATION_DENIED
    assert counts(pilot).consumed == 1 and counts(pilot).completed == 1


def test_real_revocation_after_committed_reservation_withholds_completion_without_refund(pilot):
    calls = []

    def evaluator(request):
        calls.append(request)
        assert pilot.keys.revoke(pilot.key_id)
        return evaluate_request(request)

    service = CommercialEvaluationService(pilot.usage(), evaluator=evaluator)
    assert evaluate(pilot, service=service).reason is ServiceReason.AUTHORIZATION_DENIED
    assert evaluate(pilot, service=service).reason is ServiceReason.AUTHORIZATION_DENIED
    assert len(calls) == 1
    with pilot.database.owner() as connection:
        assert connection.execute(
            "SELECT p.consumed FROM gvai_authority.advisory_pilots p "
            "JOIN gvai_authority.tenants t USING(tenant_ref) WHERE t.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == 1
        assert connection.execute(
            "SELECT attempt.state FROM gvai_authority.advisory_attempts attempt "
            "JOIN gvai_authority.reservation_events event USING(event_id) "
            "JOIN gvai_authority.tenants tenant USING(tenant_ref) WHERE tenant.tenant_id=%s", (pilot.tenant,),
        ).fetchone()[0] == "reserved"

def test_real_runtime_cannot_mutate_or_bypass_entitlements(database, pilot):
    statements = [
        "UPDATE gvai_authority.advisory_pilots SET allowance=100000",
        "SELECT * FROM gvai_authority.customer_credentials",
        "DELETE FROM gvai_authority.advisory_attempts",
        "TRUNCATE gvai_authority.reservation_events",
        "CREATE TABLE gvai_authority.runtime_escape(id int)",
        "CREATE TABLE public.runtime_escape(id int)",
        "SELECT gvai_authority.advisory_customer_v1(NULL,NULL,NULL,NULL)",
        "SELECT * FROM gvai_authority.reserve_v1(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)",
    ]
    for statement in statements:
        with database.runtime() as connection:
            with pytest.raises(database.psycopg.errors.InsufficientPrivilege):
                connection.execute(statement)
    assert counts(pilot).allowance == 3


def test_real_evaluation_failure_charged_and_never_reexecuted(pilot):
    calls = []

    def failing(request):
        calls.append(request)
        raise RuntimeError("test-only evaluation failure")

    service = CommercialEvaluationService(pilot.usage(), evaluator=failing)
    assert evaluate(pilot, service=service).reason is ServiceReason.EVALUATION_FAILURE
    assert evaluate(pilot, service=service).reason is ServiceReason.REPLAY
    assert len(calls) == 1
    summary = counts(pilot)
    assert summary.consumed == 1 and summary.failed == 1


def test_real_zero_allowance_denies_and_exact_replay_at_cap_remains_safe(pilot):
    with pilot.database.owner() as connection:
        connection.execute(
            "UPDATE gvai_authority.advisory_pilots SET allowance=0 WHERE tenant_ref="
            "(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)", (pilot.tenant,),
        )
    assert evaluate(pilot).reason is ServiceReason.QUOTA_DENIED
    assert counts(pilot).consumed == 0
    with pilot.database.owner() as connection:
        connection.execute(
            "UPDATE gvai_authority.advisory_pilots SET allowance=1 WHERE tenant_ref="
            "(SELECT tenant_ref FROM gvai_authority.tenants WHERE tenant_id=%s)", (pilot.tenant,),
        )
    assert evaluate(pilot).reason is ServiceReason.EVALUATED
    assert evaluate(pilot).reason is ServiceReason.REPLAY
    assert evaluate(pilot, telemetry={**TELEMETRY, "token_delta": 101}).reason is ServiceReason.CONFLICT
    assert evaluate(pilot, "new-request").reason is ServiceReason.QUOTA_DENIED
    assert counts(pilot).consumed == 1


def test_real_revocation_cannot_be_rolled_back(pilot):
    assert pilot.keys.revoke(pilot.key_id)
    with pilot.database.owner() as connection:
        with pytest.raises(pilot.database.psycopg.errors.RaiseException):
            connection.execute(
                "UPDATE gvai_authority.customer_credentials SET status='active',revoked_at=NULL "
                "WHERE key_id=%s", (pilot.key_id,),
            )
    assert pilot.keys.verify(pilot.credential) is None


def test_real_failed_provisioning_does_not_leave_partial_tenant(pilot):
    from gvai.commercial_api_keys import ApiKeyOperationError

    tenant = pilot.tenant + "-duplicate-project"
    now = int(time.time())
    with pytest.raises(ApiKeyOperationError):
        pilot.store.provision_pilot(
            tenant_id=tenant, principal_id=pilot.principal + "-other",
            resource_id=pilot.project, allowance=1, starts_at=now - 60, expires_at=now + 3600,
        )
    with pilot.database.owner() as connection:
        assert connection.execute(
            "SELECT count(*) FROM gvai_authority.tenants WHERE tenant_id=%s", (tenant,),
        ).fetchone()[0] == 0


def test_real_completion_is_idempotent_without_refunds(pilot):
    assert evaluate(pilot).reason is ServiceReason.EVALUATED
    usage = pilot.usage()
    assert usage.complete(
        pilot.credential, pilot.project, "request-1", succeeded=True
    ).reason is UsageReason.REPLAY
    assert usage.complete(
        pilot.credential, pilot.project, "request-1", succeeded=False
    ).reason is UsageReason.CONFLICT
    assert counts(pilot).consumed == 1 and counts(pilot).completed == 1


@pytest.mark.parametrize("acknowledgement", ["before_commit", "after_commit"])
def test_injected_commit_failure_on_real_database_never_evaluates(pilot, acknowledgement):
    calls = []

    class LostAcknowledgement:
        def __init__(self):
            self.connection = pilot.database.runtime()

        def __getattr__(self, name):
            return getattr(self.connection, name)

        @property
        def autocommit(self):
            return self.connection.autocommit

        @autocommit.setter
        def autocommit(self, value):
            self.connection.autocommit = value

        def commit(self):
            if acknowledgement == "after_commit":
                self.connection.commit()
            raise pilot.database.psycopg.OperationalError("injected commit acknowledgement loss")

    service = CommercialEvaluationService(
        pilot.usage(LostAcknowledgement), evaluator=lambda request: calls.append(request)
    )
    assert evaluate(pilot, service=service).reason is ServiceReason.ACCOUNTING_FAILURE
    assert calls == []
    if acknowledgement == "after_commit":
        assert counts(pilot).consumed == 1 and counts(pilot).reserved == 1
        assert evaluate(pilot).reason is ServiceReason.REPLAY
    else:
        assert counts(pilot).consumed == 0
        assert evaluate(pilot).reason is ServiceReason.EVALUATED


def test_real_trigger_failure_rolls_back_all_accounting(database, pilot):
    with database.owner() as connection:
        connection.execute(
            "CREATE FUNCTION gvai_authority.reject_test_attempt() RETURNS trigger LANGUAGE plpgsql AS "
            "$$ BEGIN RAISE EXCEPTION 'injected attempt insertion rejection'; END $$"
        )
        connection.execute(
            "CREATE TRIGGER reject_test_attempt BEFORE INSERT ON gvai_authority.advisory_attempts "
            "FOR EACH ROW EXECUTE FUNCTION gvai_authority.reject_test_attempt()"
        )
    try:
        assert evaluate(pilot).reason is ServiceReason.ACCOUNTING_FAILURE
        assert counts(pilot).consumed == 0
    finally:
        with database.owner() as connection:
            connection.execute("DROP TRIGGER reject_test_attempt ON gvai_authority.advisory_attempts")
            connection.execute("DROP FUNCTION gvai_authority.reject_test_attempt()")
    assert evaluate(pilot).reason is ServiceReason.EVALUATED


def test_real_unsigned_reservation_still_cannot_supply_authenticated_head(database, pilot):
    authority = PostgreSQLReservationAuthority(
        database.owner, authority=AUTHORITY, credential_verifier_secret=pilot.secret
    )
    from gvai.postgresql_reservation_authority import PostgreSQLAuthorityUnavailable

    with pytest.raises(PostgreSQLAuthorityUnavailable):
        authority.read_authenticated_head()


def test_real_http_advisory_conflicts_and_untrusted_entitlement_claims(pilot):
    server = create_server(CommercialEvaluationService(pilot.usage()))
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    payload = {
        "version": "v1", "resource_id": pilot.project, "request_id": "http-request",
        "telemetry": TELEMETRY, "reported_effects": [],
    }

    def request(body):
        connection = HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        try:
            connection.request(
                "POST", "/v1/evaluations", body=json.dumps(body),
                headers={"Authorization": "Bearer " + pilot.credential, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    try:
        for field in ("tenant_id", "allowance", "capabilities", "paid"):
            assert request({**payload, field: "untrusted"})[0] == 400
        assert counts(pilot).consumed == 0
        status, body = request(payload)
        assert status == 200
        assert body["evaluation"]["advisory_only"] is True
        assert body["evaluation"]["enforcement_applied"] is False
        assert request(payload)[0] == 409
        status, body = request({**payload, "telemetry": {**TELEMETRY, "token_delta": 101}})
        assert status == 409 and body["error"]["code"] == "conflict"
        assert counts(pilot).consumed == 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
