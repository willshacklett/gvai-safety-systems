BEGIN;

DO $guard$
DECLARE
    owner_oid oid;
BEGIN
    SELECT n.nspowner INTO owner_oid FROM pg_namespace n
    JOIN pg_roles r ON r.oid=n.nspowner
    WHERE n.nspname='gvai_authority' AND r.rolname=current_user
      AND NOT r.rolsuper AND NOT r.rolbypassrls;
    IF owner_oid IS NULL
        OR to_regprocedure('gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)') IS NULL
        OR to_regclass('gvai_authority.billing_periods') IS NULL
        OR to_regclass('gvai_authority.paid_attempts') IS NULL
        OR to_regclass('gvai_authority.billing_installation') IS NOT NULL
        OR to_regclass('gvai_authority.billing_subscriptions') IS NOT NULL
        OR to_regclass('gvai_authority.checkout_attempts') IS NOT NULL
        OR to_regprocedure('gvai_authority.reserve_subscription_advisory_v1(text,bytea,text,bigint,text,text,text,text)') IS NOT NULL
        OR ARRAY(SELECT a.attname::text FROM pg_attribute a
            WHERE a.attrelid=to_regclass('gvai_authority.billing_customers')
              AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum)
            IS DISTINCT FROM ARRAY['tenant_ref','customer_id','subscription_id',
                'current_invoice','eligible','revoked','verified_until','access_until',
                'checkout_started_at','checkout_session_id','checkout_url']
        OR EXISTS (
            SELECT 1 FROM pg_namespace n,
                LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a
            WHERE n.nspname='gvai_authority' AND a.privilege_type='CREATE'
              AND a.grantee<>owner_oid
        ) THEN
        RAISE EXCEPTION 'paid Checkout requires the unmixed baseline 001-004 and trusted owner';
    END IF;
END;
$guard$;

CREATE TABLE gvai_authority.paid_checkout_installation (
    singleton_id smallint PRIMARY KEY CHECK (singleton_id=1),
    account_id text NOT NULL CHECK (account_id ~ '^acct_[A-Za-z0-9]{1,123}$'),
    environment text NOT NULL CHECK (environment='sandbox'),
    price_id text NOT NULL CHECK (price_id ~ '^price_[A-Za-z0-9]{1,122}$'),
    currency text NOT NULL CHECK (currency='usd'),
    unit_amount integer NOT NULL CHECK (unit_amount=9900),
    interval_unit text NOT NULL CHECK (interval_unit='month'),
    quantity integer NOT NULL CHECK (quantity=1),
    success_url text NOT NULL CHECK (success_url ~ '^https://[a-z0-9.-]+/[A-Za-z0-9/_-]*$'),
    cancel_url text NOT NULL CHECK (cancel_url ~ '^https://[a-z0-9.-]+/[A-Za-z0-9/_-]*$'),
    admission_enabled boolean NOT NULL DEFAULT false CHECK (NOT admission_enabled),
    CHECK (success_url<>cancel_url)
);

-- A dedicated internal login is bound to exactly one tenant and membership.
CREATE TABLE gvai_authority.paid_checkout_workers (
    role_name name PRIMARY KEY,
    tenant_ref bigint NOT NULL,
    membership_ref bigint NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    FOREIGN KEY (tenant_ref,membership_ref)
        REFERENCES gvai_authority.tenant_memberships(tenant_ref,membership_ref)
);

CREATE TABLE gvai_authority.paid_checkout_requests (
    attempt_id text PRIMARY KEY CHECK (attempt_id ~ '^[0-9a-f]{32}$'
        AND attempt_id<>repeat('0',32)),
    tenant_ref bigint NOT NULL UNIQUE REFERENCES gvai_authority.billing_customers(tenant_ref),
    membership_ref bigint NOT NULL,
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 16384),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN ('prepared','unknown','quarantined')),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation>=0),
    FOREIGN KEY (tenant_ref,membership_ref)
        REFERENCES gvai_authority.tenant_memberships(tenant_ref,membership_ref),
    CHECK (request_digest=encode(gvai_authority.digest(request_bytes,'sha256'),'hex'))
);

CREATE FUNCTION gvai_authority.paid_checkout_guard_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Checkout history cannot be deleted'; END IF;
    IF TG_TABLE_NAME='paid_checkout_installation' THEN
        RAISE EXCEPTION 'Checkout installation is immutable';
    ELSIF TG_TABLE_NAME='paid_checkout_workers' THEN
        IF (NEW.role_name,NEW.tenant_ref,NEW.membership_ref)
            IS DISTINCT FROM (OLD.role_name,OLD.tenant_ref,OLD.membership_ref) THEN
            RAISE EXCEPTION 'Checkout worker binding is immutable';
        END IF;
    ELSIF (to_jsonb(NEW)-'state'-'generation')
        IS DISTINCT FROM (to_jsonb(OLD)-'state'-'generation')
        OR OLD.generation=9223372036854775807 OR NEW.generation<>OLD.generation+1
        OR NOT ((OLD.state='prepared' AND NEW.state IN ('unknown','quarantined'))
            OR (OLD.state='unknown' AND NEW.state='quarantined')) THEN
        RAISE EXCEPTION 'Checkout immutable request or transition conflict';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER paid_checkout_installation_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.paid_checkout_installation FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_checkout_guard_v1();
CREATE TRIGGER paid_checkout_worker_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.paid_checkout_workers FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_checkout_guard_v1();
CREATE TRIGGER paid_checkout_request_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.paid_checkout_requests FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.paid_checkout_guard_v1();

CREATE FUNCTION gvai_authority.paid_checkout_scope_v1()
RETURNS gvai_authority.paid_checkout_workers LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    binding gvai_authority.paid_checkout_workers%ROWTYPE;
BEGIN
    SELECT * INTO binding FROM gvai_authority.paid_checkout_workers
    WHERE role_name=session_user;
    IF NOT FOUND OR NOT binding.enabled OR NOT EXISTS (
        SELECT 1 FROM pg_roles r JOIN pg_namespace n ON n.nspname='gvai_authority'
        WHERE r.rolname=session_user AND NOT r.rolsuper AND NOT r.rolbypassrls
          AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication
          AND r.rolcanlogin AND NOT pg_has_role(r.oid,n.nspowner,'MEMBER')
    ) THEN
        RAISE EXCEPTION 'Checkout worker unavailable' USING ERRCODE='42501';
    END IF;
    -- Match the existing tenant-before-membership billing lock order.
    PERFORM 1 FROM gvai_authority.tenants
    WHERE tenant_ref=binding.tenant_ref AND status='active' FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Checkout tenant unavailable' USING ERRCODE='42501'; END IF;
    PERFORM 1 FROM gvai_authority.tenant_memberships
    WHERE tenant_ref=binding.tenant_ref AND membership_ref=binding.membership_ref
      AND status='active' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Checkout membership unavailable' USING ERRCODE='42501'; END IF;
    PERFORM 1 FROM gvai_authority.paid_checkout_workers
    WHERE role_name=session_user AND enabled FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Checkout worker disabled' USING ERRCODE='42501'; END IF;
    RETURN binding;
END;
$function$;

CREATE FUNCTION gvai_authority.prepare_paid_checkout_v1(p_attempt text,p_request bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    binding gvai_authority.paid_checkout_workers%ROWTYPE;
    installation gvai_authority.paid_checkout_installation%ROWTYPE;
    customer gvai_authority.billing_customers%ROWTYPE;
    prior gvai_authority.paid_checkout_requests%ROWTYPE;
    expected jsonb;
    tenant_name text;
BEGIN
    binding:=gvai_authority.paid_checkout_scope_v1();
    IF p_attempt IS NULL OR p_attempt !~ '^[0-9a-f]{32}$' OR p_attempt=repeat('0',32)
        OR p_request IS NULL OR octet_length(p_request) NOT BETWEEN 1 AND 16384 THEN
        RAISE EXCEPTION 'invalid Checkout request' USING ERRCODE='22023';
    END IF;
    SELECT * INTO STRICT installation FROM gvai_authority.paid_checkout_installation
    WHERE singleton_id=1 FOR SHARE;
    SELECT * INTO STRICT customer FROM gvai_authority.billing_customers
    WHERE tenant_ref=binding.tenant_ref FOR UPDATE;
    IF customer.revoked OR customer.subscription_id IS NOT NULL
        OR customer.checkout_started_at IS NOT NULL OR customer.checkout_session_id IS NOT NULL
        OR customer.checkout_url IS NOT NULL THEN
        RAISE EXCEPTION 'existing billing or legacy Checkout requires review' USING ERRCODE='42501';
    END IF;
    SELECT tenant_id INTO STRICT tenant_name FROM gvai_authority.tenants
    WHERE tenant_ref=binding.tenant_ref;
    IF tenant_name='gvai-internal' THEN RAISE EXCEPTION 'external tenant required'; END IF;
    expected:=jsonb_build_object(
        'version',1,'attempt_id',p_attempt,'tenant_id',tenant_name,
        'account_id',installation.account_id,'environment',installation.environment,
        'customer_id',customer.customer_id,'price_id',installation.price_id,
        'currency',installation.currency,'unit_amount',installation.unit_amount,
        'interval',installation.interval_unit,'quantity',installation.quantity,
        'success_url',installation.success_url,'cancel_url',installation.cancel_url);
    IF convert_from(p_request,'UTF8')::jsonb IS DISTINCT FROM expected
        OR convert_to(expected::text,'UTF8') IS DISTINCT FROM p_request THEN
        RAISE EXCEPTION 'Checkout request must match database canonical binding' USING ERRCODE='22023';
    END IF;
    SELECT * INTO prior FROM gvai_authority.paid_checkout_requests
    WHERE attempt_id=p_attempt OR tenant_ref=binding.tenant_ref FOR UPDATE;
    IF FOUND THEN
        IF prior.tenant_ref<>binding.tenant_ref OR prior.attempt_id<>p_attempt
            OR prior.membership_ref<>binding.membership_ref OR prior.request_bytes<>p_request THEN
            RAISE EXCEPTION 'Checkout unresolved purchase conflict' USING ERRCODE='23505';
        END IF;
        RETURN to_jsonb(prior);
    END IF;
    INSERT INTO gvai_authority.paid_checkout_requests
        (attempt_id,tenant_ref,membership_ref,request_bytes,request_digest)
    VALUES(p_attempt,binding.tenant_ref,binding.membership_ref,p_request,
        encode(gvai_authority.digest(p_request,'sha256'),'hex'))
    RETURNING * INTO prior;
    RETURN to_jsonb(prior);
END;
$function$;

CREATE FUNCTION gvai_authority.read_paid_checkout_v1(p_attempt text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    binding gvai_authority.paid_checkout_workers%ROWTYPE;
    result jsonb;
BEGIN
    binding:=gvai_authority.paid_checkout_scope_v1();
    SELECT to_jsonb(r) INTO result FROM gvai_authority.paid_checkout_requests r
    WHERE r.attempt_id=p_attempt AND r.tenant_ref=binding.tenant_ref
      AND r.membership_ref=binding.membership_ref;
    IF result IS NULL THEN RAISE EXCEPTION 'Checkout request unavailable' USING ERRCODE='42501'; END IF;
    RETURN result;
END;
$function$;

CREATE FUNCTION gvai_authority.block_paid_checkout_v1(p_attempt text,p_expected jsonb,p_state text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    binding gvai_authority.paid_checkout_workers%ROWTYPE;
    prior gvai_authority.paid_checkout_requests%ROWTYPE;
BEGIN
    binding:=gvai_authority.paid_checkout_scope_v1();
    SELECT * INTO prior FROM gvai_authority.paid_checkout_requests
    WHERE attempt_id=p_attempt AND tenant_ref=binding.tenant_ref
      AND membership_ref=binding.membership_ref FOR UPDATE;
    IF NOT FOUND OR p_expected IS DISTINCT FROM to_jsonb(prior)
        OR p_state IS NULL OR p_state NOT IN ('unknown','quarantined') THEN
        RAISE EXCEPTION 'Checkout full-record fence lost' USING ERRCODE='42501';
    END IF;
    UPDATE gvai_authority.paid_checkout_requests
    SET state=p_state,generation=generation+1 WHERE attempt_id=p_attempt
    RETURNING * INTO prior;
    RETURN to_jsonb(prior);
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.paid_checkout_installation,
    gvai_authority.paid_checkout_workers,gvai_authority.paid_checkout_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.paid_checkout_guard_v1(),
    gvai_authority.paid_checkout_scope_v1(),
    gvai_authority.prepare_paid_checkout_v1(text,bytea),
    gvai_authority.read_paid_checkout_v1(text),
    gvai_authority.block_paid_checkout_v1(text,jsonb,text) FROM PUBLIC;

DO $acl_guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,
            LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
        WHERE n.nspname='gvai_authority' AND c.relname LIKE 'paid_checkout_%'
          AND a.grantee<>n.nspowner
    ) OR EXISTS (
        SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,
            LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        WHERE n.nspname='gvai_authority'
          AND p.proname IN ('paid_checkout_guard_v1','paid_checkout_scope_v1',
              'prepare_paid_checkout_v1','read_paid_checkout_v1','block_paid_checkout_v1')
          AND a.grantee<>n.nspowner
    ) THEN RAISE EXCEPTION 'unexpected inherited Checkout ACL'; END IF;
END;
$acl_guard$;

COMMIT;
