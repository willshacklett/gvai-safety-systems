BEGIN;
SET LOCAL lock_timeout='5s';
DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user AND NOT r.rolsuper AND NOT r.rolbypassrls)
        OR to_regclass('gvai_authority.billing_legacy_upgrade_run') IS NULL THEN
        RAISE EXCEPTION 'non-superuser authority owner and migration 011 required';
    END IF;
END;
$guard$;
LOCK TABLE gvai_authority.billing_customers IN ACCESS EXCLUSIVE MODE;
LOCK TABLE gvai_authority.billing_reconcile_state,gvai_authority.billing_denial_recoveries,
    gvai_authority.billing_denials,gvai_authority.billing_legacy_upgrade_cases,
    gvai_authority.billing_legacy_upgrade_run IN ACCESS EXCLUSIVE MODE;
DO $audit$
BEGIN
    IF NOT gvai_authority.billing_upgrade_ready_v1() THEN
        RAISE EXCEPTION 'complete 011 integrity audit required';
    END IF;
END;
$audit$;
CREATE INDEX billing_recovery_tenant_payment_v12
    ON gvai_authority.billing_denial_recoveries(tenant_ref,payment_created);
CREATE TABLE gvai_authority.billing_integrity_root (
    version integer PRIMARY KEY CHECK(version=12),
    case_count bigint NOT NULL CHECK(case_count>=0),
    legacy_cutover_at timestamptz NOT NULL,
    invalid_count bigint NOT NULL CHECK(invalid_count BETWEEN 0 AND case_count),
    generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0)
);
CREATE TABLE gvai_authority.billing_integrity_cases (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.billing_customers(tenant_ref),
    expected_marker text NOT NULL,
    expected_hash text NOT NULL,
    expected_boundary bigint NOT NULL,
    valid boolean NOT NULL
);
CREATE TABLE gvai_authority.billing_integrity_faults (
    version integer PRIMARY KEY CHECK(version=12),
    code text NOT NULL CHECK(code='full_audit_failed'),
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    operator_name text NOT NULL DEFAULT session_user
);
REVOKE ALL ON gvai_authority.billing_integrity_root,gvai_authority.billing_integrity_cases,
    gvai_authority.billing_integrity_faults FROM PUBLIC;
COMMENT ON TABLE gvai_authority.billing_integrity_root IS
    'Derived transactional case/violation accounting, never a configurable ready flag. Trigger bypass by a schema owner requires a full audit.';
CREATE FUNCTION gvai_authority.billing_legacy_case_valid_v12(p_tenant bigint)
RETURNS boolean LANGUAGE sql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
    SELECT CASE WHEN k.tenant_ref IS NULL THEN NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_legacy_upgrade_cases c WHERE c.tenant_ref=p_tenant)
    ELSE EXISTS (
        SELECT 1 FROM gvai_authority.billing_legacy_upgrade_cases c
        JOIN gvai_authority.billing_denials d ON d.event_id=c.marker_id AND d.tenant_ref=c.tenant_ref
        JOIN gvai_authority.billing_reconcile_state s ON s.tenant_ref=c.tenant_ref
        WHERE c.tenant_ref=p_tenant AND c.marker_id=k.expected_marker
            AND c.inventory_hash=k.expected_hash AND c.recovery_not_before=k.expected_boundary
            AND d.event_created=k.expected_boundary AND d.payload_hash=k.expected_hash
            AND c.inventory_hash=encode(gvai_authority.digest(convert_to(c.inventory::text,'UTF8'),'sha256'),'hex')
            AND (EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries h
                WHERE h.tenant_ref=p_tenant AND h.payment_created>k.expected_boundary)
                OR EXISTS (SELECT 1 FROM gvai_authority.billing_denials held
                    WHERE held.event_id=s.denial_event AND held.tenant_ref=p_tenant))
    ) END
    FROM (SELECT p_tenant AS tenant_ref) input
    LEFT JOIN gvai_authority.billing_integrity_cases k USING(tenant_ref);
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_legacy_case_valid_v12(bigint) FROM PUBLIC;
INSERT INTO gvai_authority.billing_integrity_cases
SELECT tenant_ref,marker_id,inventory_hash,recovery_not_before,true FROM gvai_authority.billing_legacy_upgrade_cases;
INSERT INTO gvai_authority.billing_integrity_root(version,case_count,legacy_cutover_at,invalid_count)
SELECT 12,inventory_count,cutover_at,0 FROM gvai_authority.billing_legacy_upgrade_run WHERE version=11;

CREATE FUNCTION gvai_authority.billing_integrity_seal_v12()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
BEGIN
    IF TG_TABLE_NAME='billing_integrity_cases' THEN
        IF TG_OP='UPDATE' AND pg_trigger_depth()>=2
            AND (to_jsonb(NEW)-'valid')=(to_jsonb(OLD)-'valid')
            AND NEW.valid=gvai_authority.billing_legacy_case_valid_v12(NEW.tenant_ref) THEN RETURN NEW; END IF;
    ELSIF TG_TABLE_NAME='billing_integrity_root' THEN
        IF TG_OP='UPDATE' AND pg_trigger_depth()>=3
            AND (to_jsonb(NEW)-ARRAY['invalid_count','generation'])=(to_jsonb(OLD)-ARRAY['invalid_count','generation'])
            AND NEW.generation=OLD.generation+1 THEN RETURN NEW; END IF;
    END IF;
    RAISE EXCEPTION 'sealed integrity metadata';
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_integrity_seal_v12() FROM PUBLIC;
CREATE TRIGGER billing_integrity_root_seal BEFORE INSERT OR UPDATE OR DELETE
ON gvai_authority.billing_integrity_root FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_integrity_seal_v12();
CREATE TRIGGER billing_integrity_case_seal BEFORE INSERT OR UPDATE OR DELETE
ON gvai_authority.billing_integrity_cases FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_integrity_seal_v12();
CREATE TRIGGER billing_legacy_inventory_seal BEFORE INSERT
ON gvai_authority.billing_legacy_upgrade_cases FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_integrity_seal_v12();
CREATE TRIGGER billing_integrity_fault_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_integrity_faults FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();

CREATE FUNCTION gvai_authority.billing_integrity_count_v12()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
BEGIN
    UPDATE gvai_authority.billing_integrity_root
    SET invalid_count=invalid_count+CASE WHEN NEW.valid THEN -1 ELSE 1 END,generation=generation+1
    WHERE version=12;
    IF NOT FOUND THEN RAISE EXCEPTION 'integrity root missing'; END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_integrity_count_v12() FROM PUBLIC;
CREATE TRIGGER billing_integrity_count AFTER UPDATE OF valid
ON gvai_authority.billing_integrity_cases FOR EACH ROW WHEN(OLD.valid IS DISTINCT FROM NEW.valid)
EXECUTE FUNCTION gvai_authority.billing_integrity_count_v12();
CREATE FUNCTION gvai_authority.billing_integrity_refresh_v12()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
DECLARE current_valid boolean; next_valid boolean;
BEGIN
    SELECT valid INTO current_valid FROM gvai_authority.billing_integrity_cases
    WHERE tenant_ref=NEW.tenant_ref FOR UPDATE;
    IF FOUND THEN
        next_valid:=gvai_authority.billing_legacy_case_valid_v12(NEW.tenant_ref);
        IF current_valid IS DISTINCT FROM next_valid THEN
            UPDATE gvai_authority.billing_integrity_cases SET valid=next_valid WHERE tenant_ref=NEW.tenant_ref;
        END IF;
    END IF;
    RETURN NULL;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_integrity_refresh_v12() FROM PUBLIC;
CREATE TRIGGER billing_integrity_state AFTER INSERT OR UPDATE ON gvai_authority.billing_reconcile_state
FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_integrity_refresh_v12();
CREATE TRIGGER billing_integrity_recovery AFTER INSERT ON gvai_authority.billing_denial_recoveries
FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_integrity_refresh_v12();

CREATE FUNCTION gvai_authority.billing_integrity_ready_v12()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
    SELECT EXISTS (SELECT 1 FROM gvai_authority.billing_integrity_root k
        JOIN gvai_authority.billing_legacy_upgrade_run r ON r.version=11
        WHERE k.version=12 AND k.invalid_count=0 AND k.case_count=r.inventory_count
            AND k.legacy_cutover_at=r.cutover_at AND r.cutover_at<=clock_timestamp())
        AND NOT EXISTS (SELECT 1 FROM gvai_authority.billing_integrity_faults WHERE version=12);
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_integrity_ready_v12() FROM PUBLIC;
CREATE OR REPLACE FUNCTION gvai_authority.billing_upgrade_ready_v1()
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$ SELECT gvai_authority.billing_integrity_ready_v12(); $function$;

CREATE FUNCTION gvai_authority.billing_upgrade_audit_v12()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
DECLARE ok boolean;
BEGIN
    PERFORM 1 FROM gvai_authority.billing_integrity_root WHERE version=12 FOR UPDATE;
    ok:=FOUND AND gvai_authority.billing_integrity_ready_v12();
    ok:=ok AND EXISTS (SELECT 1 FROM gvai_authority.billing_integrity_root
        WHERE version=12 AND case_count=(SELECT count(*) FROM gvai_authority.billing_legacy_upgrade_cases)
            AND case_count=(SELECT count(*) FROM gvai_authority.billing_integrity_cases)
            AND invalid_count=(SELECT count(*) FROM gvai_authority.billing_integrity_cases WHERE NOT valid));
    ok:=ok AND NOT EXISTS (SELECT 1 FROM gvai_authority.billing_integrity_cases c
        WHERE c.valid IS DISTINCT FROM gvai_authority.billing_legacy_case_valid_v12(c.tenant_ref) OR NOT c.valid);
    IF NOT ok THEN
        INSERT INTO gvai_authority.billing_integrity_faults(version,code) VALUES(12,'full_audit_failed')
        ON CONFLICT(version) DO NOTHING;
    END IF;
    RETURN ok;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_upgrade_audit_v12() FROM PUBLIC;

CREATE FUNCTION gvai_authority.billing_entitlement_state_v12(p_tenant bigint)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
DECLARE b gvai_authority.billing_customers%ROWTYPE;
BEGIN
    -- Callers acquire the customer's billing lock BEFORE this shared root lock.
    -- Only violation transitions/recovery/audit need an exclusive root lock.
    PERFORM 1 FROM gvai_authority.billing_integrity_root WHERE version=12 FOR SHARE;
    IF NOT FOUND OR NOT gvai_authority.billing_integrity_ready_v12()
        OR NOT gvai_authority.billing_legacy_case_valid_v12(p_tenant) THEN RETURN 'unavailable'; END IF;
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE tenant_ref=p_tenant;
    IF NOT FOUND THEN RETURN 'payment_required'; END IF;
    IF b.revoked THEN RETURN 'suspended'; END IF;
    IF NOT b.eligible OR b.current_invoice IS NULL OR b.access_until<=clock_timestamp()
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=p_tenant AND denial_event IS NOT NULL)
        OR NOT EXISTS (SELECT 1 FROM gvai_authority.billing_periods p
            WHERE p.tenant_ref=p_tenant AND p.invoice_id=b.current_invoice AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp())
    THEN RETURN 'payment_required'; END IF;
    IF b.verified_until<=clock_timestamp() THEN RETURN 'verification_pending'; END IF;
    RETURN 'active';
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.billing_entitlement_state_v12(bigint) FROM PUBLIC;
CREATE OR REPLACE FUNCTION gvai_authority.billing_legacy_grant_guard_v11()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
BEGIN
    IF NEW.eligible THEN
        PERFORM 1 FROM gvai_authority.billing_integrity_root WHERE version=12 FOR SHARE;
        IF NOT FOUND OR NOT gvai_authority.billing_upgrade_ready_v1()
            OR NOT gvai_authority.billing_legacy_case_valid_v12(NEW.tenant_ref) THEN
            RAISE EXCEPTION 'legacy upgrade readiness rejected';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;
CREATE OR REPLACE FUNCTION gvai_authority.paid_customer_v1(
    p_key text,p_verifier bytea,p_resource text,p_capability text
) RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,gvai_authority,pg_temp
AS $function$
DECLARE customer bigint;
BEGIN
    customer:=gvai_authority.advisory_customer_v1(p_key,p_verifier,p_resource,p_capability);
    IF customer IS NULL OR NOT EXISTS (SELECT 1 FROM gvai_authority.customer_credentials
        WHERE key_id=p_key AND expires_at>clock_timestamp()) THEN RETURN NULL; END IF;
    PERFORM 1 FROM gvai_authority.billing_customers WHERE tenant_ref=customer FOR UPDATE;
    IF gvai_authority.billing_entitlement_state_v12(customer)<>'active' THEN RETURN NULL; END IF;
    -- Recheck expiry after billing/root lock waits, as required by the paid contract.
    IF NOT EXISTS (SELECT 1 FROM gvai_authority.customer_credentials
        WHERE key_id=p_key AND expires_at>clock_timestamp()) THEN RETURN NULL; END IF;
    RETURN customer;
END;
$function$;
DO $acl$
DECLARE entry record;
BEGIN
    FOR entry IN SELECT r.rolname FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
        JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='gvai_authority.billing_upgrade_ready_v1()'::regprocedure
        AND a.privilege_type='EXECUTE' AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION gvai_authority.billing_integrity_ready_v12() TO %I',entry.rolname);
    END LOOP;
END;
$acl$;
COMMIT;
