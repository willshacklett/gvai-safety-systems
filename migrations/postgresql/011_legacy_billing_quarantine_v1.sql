BEGIN;
SET LOCAL lock_timeout = '5s';
DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user
        AND NOT r.rolsuper AND NOT r.rolbypassrls) THEN
        RAISE EXCEPTION 'requires non-superuser authority owner';
    END IF;
    IF to_regclass('gvai_authority.billing_scoped_denials') IS NULL
        OR to_regprocedure('gvai_authority.reconcile_recover_denial_v1(text,text,text,text,bigint,text,bigint,bigint,bigint,text,text,bigint,bigint,bigint)') IS NULL THEN
        RAISE EXCEPTION 'migration 010 required';
    END IF;
END;
$guard$;
-- Local/disposable validation only. Operational fencing/clock assurance would require
-- separate authorization before any real deployment. Locks drain prior DB writers;
-- all pre-cutover tickets are invalidated, including reads outside transactions.
LOCK TABLE gvai_authority.billing_customers IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gvai_authority.billing_reconcile_state, gvai_authority.billing_reconcile_tickets,
    gvai_authority.billing_events, gvai_authority.billing_periods,
    gvai_authority.billing_denials, gvai_authority.billing_scoped_denials,
    gvai_authority.billing_denial_recoveries IN ACCESS EXCLUSIVE MODE;

CREATE TABLE gvai_authority.billing_legacy_upgrade_run (
    version integer PRIMARY KEY CHECK(version=11),
    cutover_at timestamptz NOT NULL,
    inventory_count bigint NOT NULL CHECK(inventory_count>=0),
    operator_name text NOT NULL DEFAULT session_user,
    boundary_basis text NOT NULL CHECK(boundary_basis='fenced_database_cutover_plus_300')
);
ALTER TABLE gvai_authority.billing_denials ADD CONSTRAINT billing_denials_event_tenant_v11
    UNIQUE(event_id,tenant_ref);
CREATE TABLE gvai_authority.billing_legacy_upgrade_cases (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.billing_customers(tenant_ref),
    version integer NOT NULL DEFAULT 11 REFERENCES gvai_authority.billing_legacy_upgrade_run(version)
        DEFERRABLE INITIALLY DEFERRED,
    marker_id text UNIQUE NOT NULL CHECK(marker_id='legacy_upgrade_' || tenant_ref::text),
    source text NOT NULL DEFAULT 'legacy_upgrade_quarantine' CHECK(source='legacy_upgrade_quarantine'),
    classification text NOT NULL CHECK(classification IN (
        'observed_revoked','observed_terminal','observed_integrity_incident',
        'observed_ineligible','apparently_eligible_history_unknown','dormant_history_unknown')),
    recovery_not_before bigint NOT NULL CHECK(recovery_not_before>0),
    inventory jsonb NOT NULL,
    inventory_hash text NOT NULL CHECK(inventory_hash ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY(marker_id,tenant_ref) REFERENCES gvai_authority.billing_denials(event_id,tenant_ref)
        DEFERRABLE INITIALLY DEFERRED
);
COMMENT ON TABLE gvai_authority.billing_legacy_upgrade_cases IS
    'Immutable uncertainty inventory, not historical Stripe evidence. No eligibility-based exemptions.';
COMMENT ON COLUMN gvai_authority.billing_denials.event_created IS
    'Stripe event time or internal poll/control boundary. legacy_upgrade_* rows carry an explicitly linked conservative cutover boundary, never a reconstructed historical event time.';
COMMENT ON COLUMN gvai_authority.billing_legacy_upgrade_cases.inventory_hash IS
    'SHA256 of canonical PostgreSQL inventory JSONB text; an integrity digest, not a Stripe signature.';
CREATE TRIGGER billing_legacy_run_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_legacy_upgrade_run FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
CREATE TRIGGER billing_legacy_case_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_legacy_upgrade_cases FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
REVOKE ALL ON gvai_authority.billing_legacy_upgrade_run, gvai_authority.billing_legacy_upgrade_cases FROM PUBLIC;

CREATE FUNCTION gvai_authority.billing_legacy_pair_check_v11()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
DECLARE marker text;
BEGIN
    marker := CASE WHEN TG_TABLE_NAME='billing_denials' THEN to_jsonb(NEW)->>'event_id' ELSE to_jsonb(NEW)->>'marker_id' END;
    IF left(marker,15)='legacy_upgrade_' AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_legacy_upgrade_cases c
        JOIN gvai_authority.billing_denials d ON d.event_id=c.marker_id AND d.tenant_ref=c.tenant_ref
        JOIN gvai_authority.billing_legacy_upgrade_run r ON r.version=c.version
        WHERE c.marker_id=marker AND d.event_created=c.recovery_not_before
            AND d.payload_hash=c.inventory_hash
            AND c.inventory_hash=encode(gvai_authority.digest(convert_to(c.inventory::text,'UTF8'),'sha256'),'hex')
            AND c.inventory->>'tenant_ref'=c.tenant_ref::text
            AND (c.inventory->>'recovery_not_before')::bigint=c.recovery_not_before
            AND c.recovery_not_before>=floor(extract(epoch FROM r.cutover_at))::bigint+300
    ) THEN RAISE EXCEPTION 'legacy marker provenance rejected'; END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_legacy_pair_check_v11() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER billing_legacy_case_pair AFTER INSERT
ON gvai_authority.billing_legacy_upgrade_cases DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_legacy_pair_check_v11();
CREATE CONSTRAINT TRIGGER billing_legacy_marker_pair AFTER INSERT
ON gvai_authority.billing_denials DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_legacy_pair_check_v11();

DO $cutover$
DECLARE c timestamptz:=clock_timestamp(); boundary bigint;
BEGIN
    boundary:=floor(extract(epoch FROM c))::bigint+300;
    -- Refuse corrupt/future observations or missing state. Never trim a floor,
    -- infer an earlier retirement date, or manufacture a historical denial.
    IF EXISTS (SELECT 1 FROM gvai_authority.billing_customers b
        LEFT JOIN gvai_authority.billing_reconcile_state s USING(tenant_ref)
        WHERE s.tenant_ref IS NULL OR s.stripe_floor>boundary OR s.applied_min>boundary
            OR s.last_attempt_at>c OR s.last_success_at>c)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_reconcile_tickets WHERE event_created>boundary OR started_at>c)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_events WHERE reconciled_at>c)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_denials WHERE event_created>boundary OR recorded_at>c)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_scoped_denials WHERE event_created>boundary OR recorded_at>c)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries WHERE recovered_at>c)
    THEN RAISE EXCEPTION 'legacy boundary unverifiable'; END IF;
    INSERT INTO gvai_authority.billing_legacy_upgrade_cases
        (tenant_ref,marker_id,classification,recovery_not_before,inventory,inventory_hash)
    SELECT b.tenant_ref,'legacy_upgrade_'||b.tenant_ref::text,p.classification,boundary,j.value,
        encode(gvai_authority.digest(convert_to(j.value::text,'UTF8'),'sha256'),'hex')
    FROM gvai_authority.billing_customers b JOIN gvai_authority.billing_reconcile_state s USING(tenant_ref)
    CROSS JOIN LATERAL (SELECT CASE WHEN b.revoked THEN 'observed_revoked'
        WHEN b.subscription_terminal_at IS NOT NULL THEN 'observed_terminal'
        WHEN s.phase='needs_operator' THEN 'observed_integrity_incident'
        WHEN b.eligible THEN 'apparently_eligible_history_unknown'
        WHEN b.subscription_id IS NULL AND s.last_outcome='never' THEN 'dormant_history_unknown'
        ELSE 'observed_ineligible' END AS classification) p
    CROSS JOIN LATERAL (SELECT jsonb_build_object(
        'source','legacy_upgrade_quarantine','tenant_ref',b.tenant_ref,
        'classification',p.classification,'cutover_at',c,'recovery_not_before',boundary,
        'boundary_basis','fenced_database_cutover_plus_300',
        'customer',jsonb_build_object('customer_id',b.customer_id,'eligible',b.eligible,'revoked',b.revoked,
            'subscription_id',b.subscription_id,'current_invoice',b.current_invoice,
            'verified_until',b.verified_until,'access_until',b.access_until,
            'terminal_at',b.subscription_terminal_at,'repin_allowed',b.repin_allowed,
            'checkout_generation',b.checkout_generation),
        'state',jsonb_build_object('phase',s.phase,'last_outcome',s.last_outcome,
            'stripe_floor',s.stripe_floor,'applied_min',s.applied_min,'denial_event',s.denial_event),
        'event_count',(SELECT count(*) FROM gvai_authority.billing_events e WHERE e.tenant_ref=b.tenant_ref),
        'period_count',(SELECT count(*) FROM gvai_authority.billing_periods q WHERE q.tenant_ref=b.tenant_ref),
        'ticket_count',(SELECT count(*) FROM gvai_authority.billing_reconcile_tickets t WHERE t.tenant_ref=b.tenant_ref)
    ) AS value) j;
    INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created)
    SELECT marker_id,tenant_ref,inventory_hash,recovery_not_before FROM gvai_authority.billing_legacy_upgrade_cases;
    UPDATE gvai_authority.billing_reconcile_state s
    SET denial_event=COALESCE(s.denial_event,k.marker_id),
        denial_held_since=COALESCE(s.denial_held_since,c),claim_ticket=NULL,claim_until='-infinity'
    FROM gvai_authority.billing_legacy_upgrade_cases k WHERE k.tenant_ref=s.tenant_ref;
    UPDATE gvai_authority.billing_customers SET eligible=false,verified_until='-infinity',access_until='-infinity';
    DELETE FROM gvai_authority.billing_reconcile_tickets;
    INSERT INTO gvai_authority.billing_legacy_upgrade_run(version,cutover_at,inventory_count,boundary_basis)
    VALUES(11,c,(SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases),'fenced_database_cutover_plus_300');
END;
$cutover$;

CREATE FUNCTION gvai_authority.billing_upgrade_ready_v1()
RETURNS boolean LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
    SELECT EXISTS (SELECT 1 FROM gvai_authority.billing_legacy_upgrade_run r
        WHERE r.version=11 AND r.cutover_at<=clock_timestamp()
        AND r.inventory_count=(SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases))
    AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_legacy_upgrade_cases c
        LEFT JOIN gvai_authority.billing_denials d ON d.event_id=c.marker_id AND d.tenant_ref=c.tenant_ref
        LEFT JOIN gvai_authority.billing_reconcile_state s ON s.tenant_ref=c.tenant_ref
        WHERE d.event_id IS NULL OR d.event_created<>c.recovery_not_before OR d.payload_hash<>c.inventory_hash
            OR c.inventory_hash<>encode(gvai_authority.digest(convert_to(c.inventory::text,'UTF8'),'sha256'),'hex')
            OR s.tenant_ref IS NULL
            OR (NOT EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries h
                WHERE h.tenant_ref=c.tenant_ref AND h.payment_created>c.recovery_not_before)
                AND NOT EXISTS (SELECT 1 FROM gvai_authority.billing_denials held
                    WHERE held.event_id=s.denial_event AND held.tenant_ref=c.tenant_ref))
    );
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_upgrade_ready_v1() FROM PUBLIC;

-- Positive writes and paid access independently require a consistent committed
-- cutover. This does not replace 010's active denial/tenant/payment checks.
CREATE FUNCTION gvai_authority.billing_legacy_grant_guard_v11()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
BEGIN
    IF NEW.eligible AND NOT gvai_authority.billing_upgrade_ready_v1() THEN
        RAISE EXCEPTION 'legacy upgrade readiness rejected';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_legacy_grant_guard_v11() FROM PUBLIC;
CREATE TRIGGER billing_legacy_grant_guard BEFORE INSERT OR UPDATE
ON gvai_authority.billing_customers FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_legacy_grant_guard_v11();

CREATE OR REPLACE FUNCTION gvai_authority.paid_customer_v1(
    p_key text, p_verifier bytea, p_resource text, p_capability text
)
RETURNS bigint LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    billing gvai_authority.billing_customers%ROWTYPE;
BEGIN
    IF NOT gvai_authority.billing_upgrade_ready_v1() THEN RETURN NULL; END IF;
    customer:=gvai_authority.advisory_customer_v1(p_key,p_verifier,p_resource,p_capability);
    IF customer IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO billing FROM gvai_authority.billing_customers b
    WHERE b.tenant_ref=customer FOR UPDATE;
    IF NOT FOUND OR NOT billing.eligible OR billing.revoked
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_reconcile_state s
                   WHERE s.tenant_ref=customer AND s.denial_event IS NOT NULL)
        OR billing.verified_until<=clock_timestamp()
        OR billing.access_until<=clock_timestamp()
        OR billing.current_invoice IS NULL THEN RETURN NULL; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.customer_credentials c
        WHERE c.key_id=p_key AND c.expires_at>clock_timestamp()
    ) THEN RETURN NULL; END IF;
    RETURN customer;
END;
$function$;
CREATE OR REPLACE FUNCTION gvai_authority.reconcile_status_v1()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    RETURN pg_catalog.jsonb_build_object(
        'legacy_upgrade_ready',gvai_authority.billing_upgrade_ready_v1(),
        'legacy_quarantine_cases',(SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases),
        'unrecovered_legacy_cases',(SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases c WHERE NOT EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries h WHERE h.tenant_ref=c.tenant_ref AND h.payment_created>c.recovery_not_before)),
         'active_denial_holds', (SELECT count(*) FROM gvai_authority.billing_reconcile_state WHERE denial_event IS NOT NULL),
        'oldest_denial_hold_age_seconds', (SELECT COALESCE(max(extract(epoch FROM (v_now-COALESCE(s.denial_held_since,d.recorded_at)))),0)::double precision
            FROM gvai_authority.billing_reconcile_state s JOIN gvai_authority.billing_denials d ON d.event_id=s.denial_event),
        'now_epoch', pg_catalog.floor(extract(epoch FROM v_now))::bigint,
        'phases', (SELECT COALESCE(pg_catalog.jsonb_object_agg(x.phase, x.n), '{}'::jsonb)
                   FROM (SELECT phase, count(*) AS n FROM gvai_authority.billing_reconcile_state GROUP BY phase) AS x),
        'due_now', (SELECT count(*) FROM gvai_authority.billing_reconcile_state s
                    JOIN gvai_authority.billing_customers b ON b.tenant_ref = s.tenant_ref
                    WHERE s.phase IN ('awaiting', 'active', 'terminal') AND NOT b.revoked
                      AND s.next_due_at <= v_now AND s.claim_until <= v_now),
        'max_overdue_seconds', (SELECT COALESCE(max(extract(epoch FROM (v_now - s.next_due_at))), 0)::double precision
                    FROM gvai_authority.billing_reconcile_state s
                    JOIN gvai_authority.billing_customers b ON b.tenant_ref = s.tenant_ref
                    WHERE s.phase IN ('awaiting', 'active', 'terminal') AND NOT b.revoked
                      AND s.next_due_at <= v_now AND s.claim_until <= v_now),
        'in_flight', (SELECT count(*) FROM gvai_authority.billing_reconcile_state WHERE claim_until > v_now),
        'failing', (SELECT count(*) FROM gvai_authority.billing_reconcile_state WHERE consecutive_failures > 0),
        'max_consecutive_failures', (SELECT COALESCE(max(consecutive_failures), 0)
                    FROM gvai_authority.billing_reconcile_state),
        'needs_operator', (SELECT count(*) FROM gvai_authority.billing_reconcile_state WHERE phase = 'needs_operator'),
        'entitled', (SELECT count(*) FROM gvai_authority.billing_customers
                    WHERE eligible AND NOT revoked AND access_until > v_now AND verified_until > v_now),
        'lease_expiring', (SELECT count(*) FROM gvai_authority.billing_customers
                    WHERE eligible AND NOT revoked AND access_until > v_now
                      AND verified_until > v_now AND verified_until <= v_now + interval '20 seconds'),
        'lease_lapsed', (SELECT count(*) FROM gvai_authority.billing_customers
                    WHERE eligible AND NOT revoked AND access_until > v_now AND verified_until <= v_now),
        'oldest_active_success_age_seconds', (SELECT COALESCE(max(extract(epoch FROM (v_now - s.last_success_at))), 0)::double precision
                    FROM gvai_authority.billing_reconcile_state s
                    WHERE s.phase = 'active' AND s.last_success_at IS NOT NULL)
    );
END;
$function$;


-- Copy only existing trusted paid/signal EXECUTE grantees, preserving custom roles.
DO $acl$
DECLARE entry record;
BEGIN
    FOR entry IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid IN ('gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)'::regprocedure,
            'gvai_authority.reconcile_signal_v1(text,text,text,bigint,boolean)'::regprocedure)
        AND a.privilege_type='EXECUTE' AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION gvai_authority.billing_upgrade_ready_v1() TO %I',entry.rolname);
    END LOOP;
END;
$acl$;
COMMIT;
