BEGIN;

DO $owner_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS n
        JOIN pg_catalog.pg_roles AS r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user AND NOT r.rolsuper
    ) THEN
        RAISE EXCEPTION 'paid migration requires non-superuser authority owner';
    END IF;
    IF pg_catalog.to_regprocedure(
        'gvai_authority.advisory_customer_v1(text,bytea,text,text)'
    ) IS NULL THEN
        RAISE EXCEPTION 'advisory migration 003 required';
    END IF;
END;
$owner_guard$;

CREATE TABLE gvai_authority.billing_customers (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.tenants(tenant_ref),
    customer_id text UNIQUE NOT NULL CHECK (customer_id ~ '^cus_[A-Za-z0-9_]{1,124}$'),
    subscription_id text UNIQUE CHECK (subscription_id ~ '^sub_[A-Za-z0-9_]{1,124}$'),
    current_invoice text,
    eligible boolean NOT NULL DEFAULT false,
    revoked boolean NOT NULL DEFAULT false,
    verified_until timestamptz NOT NULL DEFAULT '-infinity',
    access_until timestamptz NOT NULL DEFAULT '-infinity',
    checkout_started_at timestamptz,
    checkout_session_id text UNIQUE,
    checkout_url text,
    UNIQUE (tenant_ref, customer_id),
    UNIQUE (tenant_ref, subscription_id)
);

CREATE TABLE gvai_authority.billing_periods (
    invoice_id text PRIMARY KEY CHECK (invoice_id ~ '^in_[A-Za-z0-9_]{1,125}$'),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers(tenant_ref),
    subscription_id text NOT NULL,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL CHECK (ends_at > starts_at),
    allowance bigint NOT NULL DEFAULT 100000 CHECK (allowance = 100000),
    consumed bigint NOT NULL DEFAULT 0 CHECK (consumed BETWEEN 0 AND allowance),
    FOREIGN KEY (tenant_ref,subscription_id)
        REFERENCES gvai_authority.billing_customers(tenant_ref,subscription_id)
        DEFERRABLE INITIALLY DEFERRED,
    UNIQUE (tenant_ref, starts_at),
    UNIQUE (tenant_ref, invoice_id)
);
ALTER TABLE gvai_authority.billing_customers
    ADD CONSTRAINT billing_current_period_fk FOREIGN KEY (tenant_ref,current_invoice)
    REFERENCES gvai_authority.billing_periods(tenant_ref,invoice_id);

CREATE TABLE gvai_authority.billing_events (
    event_id text PRIMARY KEY CHECK (event_id ~ '^evt_[A-Za-z0-9_]{1,124}$'),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers(tenant_ref),
    payload_hash text NOT NULL CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE gvai_authority.paid_attempts (
    tenant_ref bigint NOT NULL,
    invoice_id text NOT NULL,
    request_id_digest text NOT NULL CHECK (request_id_digest ~ '^[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    resource_digest text NOT NULL CHECK (resource_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN ('reserved','completed','failed')),
    PRIMARY KEY (tenant_ref,request_id_digest),
    FOREIGN KEY (tenant_ref,invoice_id)
        REFERENCES gvai_authority.billing_periods(tenant_ref,invoice_id)
);

CREATE FUNCTION gvai_authority.paid_history_guard_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'paid history is immutable'; END IF;
    IF TG_TABLE_NAME='billing_customers' THEN
        IF NEW.tenant_ref<>OLD.tenant_ref OR NEW.customer_id<>OLD.customer_id
            OR (OLD.revoked AND NOT NEW.revoked)
            OR (OLD.subscription_id IS NOT NULL AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id)
            OR (OLD.checkout_started_at IS NOT NULL AND
                NEW.checkout_started_at IS DISTINCT FROM OLD.checkout_started_at) THEN
            RAISE EXCEPTION 'billing identity or revocation rewrite rejected';
        END IF;
    ELSIF TG_TABLE_NAME='billing_periods' THEN
        IF (to_jsonb(NEW)-'consumed') IS DISTINCT FROM (to_jsonb(OLD)-'consumed')
            OR NEW.consumed<>OLD.consumed+1 THEN
            RAISE EXCEPTION 'paid period rewrite rejected';
        END IF;
    ELSIF TG_TABLE_NAME='paid_attempts' THEN
        IF (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state')
            OR OLD.state<>'reserved' OR NEW.state NOT IN ('completed','failed') THEN
            RAISE EXCEPTION 'paid attempt rewrite rejected';
        END IF;
    ELSE
        RAISE EXCEPTION 'billing event rewrite rejected';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER billing_customer_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.billing_customers FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
CREATE TRIGGER billing_period_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.billing_periods FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
CREATE TRIGGER billing_event_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.billing_events FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
CREATE TRIGGER paid_attempt_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.paid_attempts FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();

CREATE FUNCTION gvai_authority.paid_count_check_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_periods p
        WHERE p.tenant_ref=NEW.tenant_ref AND p.invoice_id=NEW.invoice_id
          AND p.consumed=(SELECT count(*) FROM gvai_authority.paid_attempts a
              WHERE a.tenant_ref=p.tenant_ref AND a.invoice_id=p.invoice_id)
    ) THEN RAISE EXCEPTION 'paid count mismatch'; END IF;
    RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER paid_attempt_count AFTER INSERT ON gvai_authority.paid_attempts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_count_check_v1();
CREATE CONSTRAINT TRIGGER paid_period_count AFTER INSERT OR UPDATE ON gvai_authority.billing_periods
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_count_check_v1();

CREATE FUNCTION gvai_authority.no_paid_pilot_bypass_v1()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF EXISTS (
        SELECT 1 FROM gvai_authority.reservation_events e
        JOIN gvai_authority.billing_customers b ON b.tenant_ref=e.tenant_ref
        WHERE e.event_id=NEW.event_id
    ) THEN
        RAISE EXCEPTION 'paid tenant cannot acquire new pilot attempts' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER no_paid_pilot_bypass BEFORE INSERT ON gvai_authority.advisory_attempts
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.no_paid_pilot_bypass_v1();

CREATE FUNCTION gvai_authority.paid_customer_v1(
    p_key text, p_verifier bytea, p_resource text, p_capability text
)
RETURNS bigint LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    billing gvai_authority.billing_customers%ROWTYPE;
BEGIN
    customer:=gvai_authority.advisory_customer_v1(p_key,p_verifier,p_resource,p_capability);
    IF customer IS NULL THEN RETURN NULL; END IF;
    SELECT * INTO billing FROM gvai_authority.billing_customers b
    WHERE b.tenant_ref=customer FOR UPDATE;
    IF NOT FOUND OR NOT billing.eligible OR billing.revoked
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

CREATE FUNCTION gvai_authority.reserve_paid_v1(
    p_key text, p_verifier bytea, p_authority text, p_epoch bigint, p_domain text,
    p_request text, p_resource text, p_payload text
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    period gvai_authority.billing_periods%ROWTYPE;
    prior gvai_authority.paid_attempts%ROWTYPE;
    request_hash text;
    resource_hash text;
    payload_hash text;
    pilot record;
BEGIN
    IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_payload IS NULL OR p_payload !~ '^[0-9a-f]{64}$' THEN RETURN 'invalid_input'; END IF;
    customer:=gvai_authority.paid_customer_v1(p_key,p_verifier,p_resource,'evaluation:run');
    IF customer IS NULL THEN RETURN 'unauthorized'; END IF;
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.authority_state a
        WHERE a.singleton_id=1 AND a.authority_id=p_authority
          AND a.epoch=p_epoch AND a.trust_domain=p_domain
    ) THEN RETURN 'unauthorized'; END IF;
    SELECT p.* INTO period FROM gvai_authority.billing_periods p
    JOIN gvai_authority.billing_customers b ON b.current_invoice=p.invoice_id
      AND b.tenant_ref=p.tenant_ref
    WHERE b.tenant_ref=customer FOR UPDATE OF p;
    IF NOT FOUND THEN RAISE EXCEPTION 'paid period missing'; END IF;
    -- Validate after all accounting lock waits, not at transaction-start time.
    IF gvai_authority.paid_customer_v1(p_key,p_verifier,p_resource,'evaluation:run')
        IS DISTINCT FROM customer OR period.starts_at>clock_timestamp()
        OR period.ends_at<=clock_timestamp() THEN RETURN 'unauthorized'; END IF;
    request_hash:=encode(gvai_authority.digest(convert_to(p_request,'UTF8'),'sha256'),'hex');
    resource_hash:=encode(gvai_authority.digest(convert_to(p_resource,'UTF8'),'sha256'),'hex');
    payload_hash:=encode(gvai_authority.digest(
        convert_to('gvai-reservation-request-v1','UTF8') || decode('00','hex') ||
        convert_to('{"payload_digest":"'||p_payload||'","request_id":"'||p_request||
          '","resource_id":"'||p_resource||'","version":1}','UTF8'),'sha256'),'hex');
    SELECT * INTO prior FROM gvai_authority.paid_attempts a
    WHERE a.tenant_ref=customer AND a.request_id_digest=request_hash;
    IF FOUND THEN
        IF prior.request_digest=payload_hash AND prior.resource_digest=resource_hash THEN
            RETURN 'replay';
        END IF;
        RETURN 'conflict';
    END IF;
    SELECT * INTO pilot FROM gvai_authority.reservation_idempotency i
    WHERE i.tenant_ref=customer AND i.request_id_digest=request_hash LIMIT 1;
    IF FOUND THEN
        IF pilot.request_digest=payload_hash AND pilot.resource_digest=resource_hash THEN
            RETURN 'replay';
        END IF;
        RETURN 'conflict';
    END IF;
    IF period.consumed>=period.allowance THEN RETURN 'quota_exhausted'; END IF;
    INSERT INTO gvai_authority.paid_attempts
    VALUES(customer,period.invoice_id,request_hash,payload_hash,resource_hash,'reserved');
    UPDATE gvai_authority.billing_periods p SET consumed=p.consumed+1
    WHERE p.invoice_id=period.invoice_id;
    RETURN 'reserved';
END;
$function$;

CREATE FUNCTION gvai_authority.complete_paid_v1(
    p_key text, p_verifier bytea, p_resource text, p_request text, p_success boolean
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    prior gvai_authority.paid_attempts%ROWTYPE;
    target text;
BEGIN
    customer:=gvai_authority.paid_customer_v1(p_key,p_verifier,p_resource,'evaluation:run');
    IF customer IS NULL THEN RETURN 'unauthorized'; END IF;
    IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_success IS NULL THEN RETURN 'invalid_input'; END IF;
    SELECT * INTO prior FROM gvai_authority.paid_attempts a
    WHERE a.tenant_ref=customer
      AND a.request_id_digest=encode(gvai_authority.digest(convert_to(p_request,'UTF8'),'sha256'),'hex')
      AND a.resource_digest=encode(gvai_authority.digest(convert_to(p_resource,'UTF8'),'sha256'),'hex')
    FOR UPDATE;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF gvai_authority.paid_customer_v1(p_key,p_verifier,p_resource,'evaluation:run')
        IS DISTINCT FROM customer THEN RETURN 'unauthorized'; END IF;
    target:=CASE WHEN p_success THEN 'completed' ELSE 'failed' END;
    IF prior.state=target THEN RETURN 'replay'; END IF;
    IF prior.state<>'reserved' THEN RETURN 'conflict'; END IF;
    UPDATE gvai_authority.paid_attempts a SET state=target
    WHERE a.tenant_ref=customer AND a.request_id_digest=prior.request_id_digest;
    RETURN target;
END;
$function$;

CREATE FUNCTION gvai_authority.paid_usage_v1(p_key text,p_verifier bytea,p_resource text)
RETURNS TABLE(allowance bigint,consumed bigint,reserved bigint,completed bigint,failed bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
BEGIN
    customer:=gvai_authority.paid_customer_v1(p_key,p_verifier,p_resource,'usage:read');
    IF customer IS NULL THEN RETURN; END IF;
    RETURN QUERY SELECT p.allowance,p.consumed,
        count(a.*) FILTER (WHERE a.state='reserved'),
        count(a.*) FILTER (WHERE a.state='completed'),
        count(a.*) FILTER (WHERE a.state='failed')
    FROM gvai_authority.billing_customers b
    JOIN gvai_authority.billing_periods p ON p.tenant_ref=b.tenant_ref AND p.invoice_id=b.current_invoice
    LEFT JOIN gvai_authority.paid_attempts a ON a.tenant_ref=p.tenant_ref AND a.invoice_id=p.invoice_id
    WHERE b.tenant_ref=customer AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
    GROUP BY p.invoice_id;
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.billing_customers,gvai_authority.billing_periods,
    gvai_authority.billing_events,gvai_authority.paid_attempts FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.paid_history_guard_v1(),
    gvai_authority.paid_count_check_v1(),
    gvai_authority.no_paid_pilot_bypass_v1(),
    gvai_authority.paid_customer_v1(text,bytea,text,text),
    gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text),
    gvai_authority.complete_paid_v1(text,bytea,text,text,boolean),
    gvai_authority.paid_usage_v1(text,bytea,text) FROM PUBLIC;
COMMIT;
