BEGIN;

-- Offline source only. Installation and runtime grants require separate approval.
-- The future adapter must set a statement timeout before issuing calls, commit
-- before dispatch, and resolve unknown commits by reading the same durable key.
-- Provisioning must share the tenant admission lock; no Stripe call is made here.
DO $owner_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS role ON role.oid = namespace.nspowner
        WHERE namespace.nspname = 'gvai_authority'
          AND role.rolname = current_user AND NOT role.rolsuper
          AND NOT role.rolbypassrls
    ) OR NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_installation
        WHERE migration_id = '004_subscription_billing_v1' AND contract_version = 1
    ) THEN
        RAISE EXCEPTION 'checkout migration requires billing schema and its non-superuser owner';
    END IF;
    IF current_setting('server_encoding') <> 'UTF8' THEN
        RAISE EXCEPTION 'checkout canonical bytes require UTF8';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS namespace,
            LATERAL pg_catalog.aclexplode(coalesce(namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner))) AS privilege
        WHERE namespace.nspname = 'gvai_authority'
          AND privilege.privilege_type = 'CREATE' AND privilege.grantee <> namespace.nspowner
    ) THEN
        RAISE EXCEPTION 'checkout schema must be writable only by its trusted owner';
    END IF;
END;
$owner_guard$;

CREATE TABLE gvai_authority.checkout_authorizations (
    authorization_ref text PRIMARY KEY CHECK (authorization_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    issuer text NOT NULL CHECK (issuer ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    principal_id text NOT NULL CHECK (principal_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    tenant_ref bigint NOT NULL,
    membership_ref bigint NOT NULL,
    active boolean NOT NULL DEFAULT false,
    checkout_approved boolean NOT NULL DEFAULT false,
    expires_at timestamptz CHECK (expires_at IS NULL OR gvai_authority.billing_valid_time(expires_at)),
    UNIQUE (issuer, principal_id, tenant_ref),
    UNIQUE (authorization_ref, issuer, principal_id, tenant_ref, membership_ref),
    FOREIGN KEY (tenant_ref, membership_ref) REFERENCES gvai_authority.tenant_memberships (tenant_ref, membership_ref)
);

CREATE TABLE gvai_authority.checkout_attempts (
    stripe_account_id text NOT NULL CHECK (stripe_account_id ~ '^acct_[A-Za-z0-9]{1,123}$'),
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    attempt_id text NOT NULL CHECK (attempt_id ~ '^[0-9a-f]{32}$'
        AND attempt_id <> '00000000000000000000000000000000'),
    authorization_ref text NOT NULL,
    issuer text NOT NULL,
    principal_id text NOT NULL,
    tenant_ref bigint NOT NULL,
    membership_ref bigint NOT NULL,
    customer_id text NOT NULL CHECK (customer_id ~ '^cus_[A-Za-z0-9]{1,124}$'),
    price_id text NOT NULL CHECK (price_id ~ '^price_[A-Za-z0-9]{1,122}$'),
    intent_bytes bytea NOT NULL CHECK (octet_length(intent_bytes) BETWEEN 1 AND 16384),
    intent_fingerprint bytea NOT NULL CHECK (octet_length(intent_fingerprint) = 32),
    request_bytes bytea NOT NULL CHECK (octet_length(request_bytes) BETWEEN 1 AND 32768),
    request_fingerprint bytea NOT NULL CHECK (octet_length(request_fingerprint) = 32),
    parameters bytea NOT NULL CHECK (octet_length(parameters) BETWEEN 1 AND 8192),
    idempotency_key text NOT NULL CHECK (idempotency_key ~ '^gvai-checkout-v1-[0-9a-f]{64}$'),
    adapter_version text NOT NULL CHECK (adapter_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    api_version text NOT NULL CHECK (api_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    authenticated_until timestamptz NOT NULL CHECK (gvai_authority.billing_valid_time(authenticated_until)),
    state text NOT NULL DEFAULT 'prepared' CHECK (state IN (
        'prepared', 'dispatching', 'session_attached', 'unknown',
        'quarantined', 'expired_unsent', 'closed_verified'
    )),
    generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    created_at timestamptz NOT NULL CHECK (gvai_authority.billing_valid_time(created_at)),
    updated_at timestamptz NOT NULL CHECK (gvai_authority.billing_valid_time(updated_at)),
    prepare_expires_at timestamptz NOT NULL CHECK (gvai_authority.billing_valid_time(prepare_expires_at)),
    lease_id text CHECK (lease_id IS NULL OR lease_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    lease_expires_at timestamptz CHECK (lease_expires_at IS NULL OR gvai_authority.billing_valid_time(lease_expires_at)),
    session_id text CHECK (session_id IS NULL OR session_id ~ '^cs_test_[A-Za-z0-9]{1,120}$'),
    session_status text CHECK (session_status IS NULL OR session_status IN ('open', 'expired', 'complete')),
    session_observed_at timestamptz CHECK (session_observed_at IS NULL OR gvai_authority.billing_valid_time(session_observed_at)),
    session_expires_at timestamptz CHECK (session_expires_at IS NULL OR gvai_authority.billing_valid_time(session_expires_at)),
    subscription_id text CHECK (subscription_id IS NULL OR subscription_id ~ '^sub_[A-Za-z0-9]{1,124}$'),
    handoff_id text CHECK (handoff_id IS NULL OR handoff_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    CHECK (membership_ref > 0),
    CHECK (prepare_expires_at > created_at),
    CHECK (authenticated_until > created_at),
    CHECK (updated_at >= created_at),
    CHECK ((lease_id IS NULL AND lease_expires_at IS NULL)
        OR (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_expires_at > updated_at
            AND lease_expires_at <= updated_at + INTERVAL '300 seconds'
            AND state IN ('dispatching', 'unknown', 'session_attached'))),
    CHECK (state <> 'dispatching' OR lease_id IS NOT NULL),
    CHECK ((session_id IS NULL AND session_status IS NULL AND session_observed_at IS NULL
            AND session_expires_at IS NULL AND subscription_id IS NULL AND handoff_id IS NULL
            AND state NOT IN ('session_attached', 'closed_verified'))
        OR (session_id IS NOT NULL AND session_status IS NOT NULL
            AND session_observed_at IS NOT NULL AND session_expires_at IS NOT NULL
            AND session_observed_at <= updated_at
            AND state IN ('session_attached', 'unknown', 'quarantined', 'closed_verified')
            AND (session_status <> 'open' OR session_observed_at < session_expires_at)
            AND (session_status <> 'expired' OR session_observed_at >= session_expires_at)
            AND ((session_status = 'complete' AND subscription_id IS NOT NULL)
                OR (session_status <> 'complete' AND subscription_id IS NULL))
            AND (handoff_id IS NULL OR session_status = 'complete'))),
    CHECK (state <> 'expired_unsent' OR updated_at >= prepare_expires_at),
    CHECK (state <> 'closed_verified'
        OR (lease_id IS NULL AND (session_status = 'expired'
            OR (session_status = 'complete' AND handoff_id IS NOT NULL)))),
    PRIMARY KEY (stripe_account_id, environment, attempt_id),
    UNIQUE (stripe_account_id, environment, idempotency_key),
    UNIQUE (stripe_account_id, environment, session_id),
    UNIQUE (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id),
    FOREIGN KEY (authorization_ref, issuer, principal_id, tenant_ref, membership_ref) REFERENCES gvai_authority.checkout_authorizations (authorization_ref, issuer, principal_id, tenant_ref, membership_ref),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, customer_id) REFERENCES gvai_authority.billing_customers (stripe_account_id, environment, tenant_ref, customer_id),
    FOREIGN KEY (stripe_account_id, environment, price_id) REFERENCES gvai_authority.billing_prices (stripe_account_id, environment, price_id)
);

CREATE UNIQUE INDEX checkout_attempts_one_unresolved ON gvai_authority.checkout_attempts (tenant_ref)
    WHERE state NOT IN ('expired_unsent', 'closed_verified');

CREATE TABLE gvai_authority.checkout_handoffs (
    handoff_id text PRIMARY KEY CHECK (handoff_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    attempt_id text NOT NULL,
    session_id text NOT NULL,
    customer_id text NOT NULL,
    subscription_id text NOT NULL,
    price_id text NOT NULL,
    verified_at timestamptz NOT NULL CHECK (gvai_authority.billing_valid_time(verified_at)),
    UNIQUE (stripe_account_id, environment, attempt_id),
    UNIQUE (stripe_account_id, environment, subscription_id),
    UNIQUE (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id, handoff_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, price_id) REFERENCES gvai_authority.billing_subscriptions (stripe_account_id, environment, tenant_ref, subscription_id, price_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id) REFERENCES gvai_authority.checkout_attempts (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE gvai_authority.checkout_attempts ADD CONSTRAINT checkout_attempt_handoff
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id, handoff_id) REFERENCES gvai_authority.checkout_handoffs (stripe_account_id, environment, tenant_ref, attempt_id, session_id, customer_id, price_id, handoff_id)
    DEFERRABLE INITIALLY DEFERRED;

-- Only printable ASCII strings and integer JSON numbers occur in the frozen model.
-- Reconstruct known shapes, then compare bytes; never hash jsonb's rendering.
CREATE FUNCTION gvai_authority.checkout_canonical(p_value jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    result text;
    item record;
    separator text := '';
BEGIN
    CASE jsonb_typeof(p_value)
    WHEN 'object' THEN
        result := '{';
        FOR item IN SELECT key, value FROM jsonb_each(p_value) ORDER BY key COLLATE "C" LOOP
            result := result || separator || gvai_authority.checkout_canonical(to_jsonb(item.key))
                || ':' || gvai_authority.checkout_canonical(item.value);
            separator := ',';
        END LOOP;
        RETURN result || '}';
    WHEN 'array' THEN
        result := '[';
        FOR item IN SELECT value FROM jsonb_array_elements(p_value) WITH ORDINALITY ORDER BY ordinality LOOP
            result := result || separator || gvai_authority.checkout_canonical(item.value);
            separator := ',';
        END LOOP;
        RETURN result || ']';
    WHEN 'string' THEN
        result := p_value #>> '{}';
        IF result COLLATE "C" ~ '[^ -~]' THEN
            RAISE EXCEPTION 'unsupported checkout canonical string';
        END IF;
        RETURN to_json(result)::text;
    WHEN 'number' THEN
        result := p_value::text;
        IF result !~ '^(0|[1-9][0-9]*)$' THEN
            RAISE EXCEPTION 'unsupported checkout canonical number';
        END IF;
        RETURN result;
    ELSE
        RAISE EXCEPTION 'unsupported checkout canonical value';
    END CASE;
END;
$function$;

CREATE FUNCTION gvai_authority.checkout_redirect_valid(p_url text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    host text;
    label text;
    path text;
BEGIN
    IF p_url IS NULL OR length(p_url) NOT BETWEEN 1 AND 2048
        OR p_url COLLATE "C" !~ '^https://[a-z0-9.-]+/[A-Za-z0-9/_.-]*$' THEN
        RETURN false;
    END IF;
    host := split_part(substr(p_url, 9), '/', 1);
    path := substr(p_url, 9 + length(host));
    IF length(host) > 253 OR host !~ '[.][a-z]+$'
        OR host ~ '[.](localhost|local)$' OR path ~ '(^|/)[.]{1,2}(/|$)' THEN
        RETURN false;
    END IF;
    FOREACH label IN ARRAY string_to_array(host, '.') LOOP
        IF label !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$function$;

CREATE FUNCTION gvai_authority.checkout_authorization_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'checkout authorization tombstones cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.authorization_ref, NEW.issuer, NEW.principal_id, NEW.tenant_ref, NEW.membership_ref
    ) IS DISTINCT FROM (
        OLD.authorization_ref, OLD.issuer, OLD.principal_id, OLD.tenant_ref, OLD.membership_ref
    ) THEN
        RAISE EXCEPTION 'checkout authorization identity cannot change';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.tenant_memberships AS membership
        JOIN gvai_authority.tenants AS tenant USING (tenant_ref)
        WHERE membership.tenant_ref = NEW.tenant_ref
          AND membership.membership_ref = NEW.membership_ref
          AND membership.principal_id = NEW.principal_id
          AND tenant.tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant.tenant_id <> 'gvai-internal'
    ) THEN
        RAISE EXCEPTION 'checkout authorization membership mismatch';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER checkout_authorization_identity BEFORE INSERT OR UPDATE OR DELETE ON gvai_authority.checkout_authorizations
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.checkout_authorization_guard();

CREATE FUNCTION gvai_authority.checkout_request_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    tenant_name text;
    supplied jsonb;
    intent jsonb;
    outbound jsonb;
    frozen jsonb;
    key_bytes bytea;
    expected_intent bytea;
    expected_parameters bytea;
    expected_request bytea;
    success_url text;
    cancel_url text;
BEGIN
    IF TG_OP = 'INSERT' AND (
        NEW.state IS DISTINCT FROM 'prepared' OR NEW.generation IS DISTINCT FROM 0
        OR NEW.updated_at IS DISTINCT FROM NEW.created_at
        OR NEW.lease_id IS NOT NULL OR NEW.lease_expires_at IS NOT NULL
        OR NEW.session_id IS NOT NULL OR NEW.session_status IS NOT NULL
        OR NEW.session_observed_at IS NOT NULL OR NEW.session_expires_at IS NOT NULL
        OR NEW.subscription_id IS NOT NULL OR NEW.handoff_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'checkout creation must be unsent prepared generation zero';
    END IF;
    SELECT tenant_id INTO STRICT tenant_name FROM gvai_authority.tenants
    WHERE tenant_ref = NEW.tenant_ref;
    IF tenant_name !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR tenant_name = 'gvai-internal' THEN
        RAISE EXCEPTION 'checkout requires an external tenant';
    END IF;
    supplied := convert_from(NEW.intent_bytes, 'UTF8')::jsonb;
    success_url := supplied #>> '{intent,success_url}';
    cancel_url := supplied #>> '{intent,cancel_url}';
    IF NOT gvai_authority.checkout_redirect_valid(success_url)
        OR NOT gvai_authority.checkout_redirect_valid(cancel_url)
        OR success_url = cancel_url THEN
        RAISE EXCEPTION 'invalid frozen checkout redirects';
    END IF;
    key_bytes := convert_to(gvai_authority.checkout_canonical(jsonb_build_object(
        'domain', 'gvai-sandbox-checkout-attempt-v1', 'account', NEW.stripe_account_id,
        'environment', NEW.environment, 'attempt', NEW.attempt_id
    )), 'UTF8');
    IF NEW.idempotency_key IS DISTINCT FROM
        'gvai-checkout-v1-' || encode(gvai_authority.digest(key_bytes, 'sha256'), 'hex') THEN
        RAISE EXCEPTION 'checkout idempotency conflict';
    END IF;
    intent := jsonb_build_object(
        'version', 1, 'association', jsonb_build_object(
            'issuer', NEW.issuer, 'principal_id', NEW.principal_id,
            'tenant_id', tenant_name, 'attempt_id', NEW.attempt_id),
        'stripe_account_id', NEW.stripe_account_id, 'environment', NEW.environment,
        'product', 'GVAI Advisory API', 'mode', 'subscription', 'price_id', NEW.price_id,
        'currency', 'usd', 'unit_amount', 9900, 'recurring_interval', 'month',
        'recurring_interval_count', 1, 'quantity', 1, 'success_url', success_url,
        'cancel_url', cancel_url, 'idempotency_key', NEW.idempotency_key,
        'request_fingerprint', ''
    );
    -- intent_bytes is the Phase 3A digest preimage, with its fingerprint blank.
    expected_intent := convert_to(gvai_authority.checkout_canonical(jsonb_build_object(
        'domain', 'gvai-sandbox-checkout-intent-v1', 'intent', intent
    )), 'UTF8');
    IF NEW.intent_bytes IS DISTINCT FROM expected_intent
        OR NEW.intent_fingerprint IS DISTINCT FROM gvai_authority.digest(expected_intent, 'sha256') THEN
        RAISE EXCEPTION 'checkout intent bytes or fingerprint conflict';
    END IF;
    intent := jsonb_set(intent, '{request_fingerprint}', to_jsonb(encode(NEW.intent_fingerprint, 'hex')));
    outbound := jsonb_build_object(
        'mode', 'subscription', 'customer', NEW.customer_id,
        'line_items', jsonb_build_array(jsonb_build_object('price', NEW.price_id, 'quantity', 1)),
        'success_url', success_url, 'cancel_url', cancel_url,
        'client_reference_id', NEW.attempt_id
    );
    expected_parameters := convert_to(gvai_authority.checkout_canonical(outbound), 'UTF8');
    frozen := jsonb_build_object(
        'domain', 'gvai-frozen-checkout-request-v1', 'intent', intent,
        'membership_ref', NEW.membership_ref, 'customer_id', NEW.customer_id,
        'adapter_version', NEW.adapter_version, 'api_version', NEW.api_version,
        'parameters', convert_from(expected_parameters, 'UTF8')
    );
    expected_request := convert_to(gvai_authority.checkout_canonical(frozen), 'UTF8');
    IF NEW.parameters IS DISTINCT FROM expected_parameters
        OR NEW.request_bytes IS DISTINCT FROM expected_request
        OR NEW.request_fingerprint IS DISTINCT FROM gvai_authority.digest(expected_request, 'sha256') THEN
        RAISE EXCEPTION 'checkout frozen request conflict';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER checkout_request_identity BEFORE INSERT OR UPDATE ON gvai_authority.checkout_attempts
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.checkout_request_guard();

CREATE FUNCTION gvai_authority.checkout_attempt_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'checkout attempts cannot be deleted'; END IF;
    IF (NEW.stripe_account_id, NEW.environment, NEW.attempt_id, NEW.authorization_ref,
        NEW.issuer, NEW.principal_id, NEW.tenant_ref, NEW.membership_ref, NEW.customer_id,
        NEW.price_id, NEW.intent_bytes, NEW.intent_fingerprint, NEW.request_bytes,
        NEW.request_fingerprint, NEW.parameters, NEW.idempotency_key,
        NEW.adapter_version, NEW.api_version, NEW.authenticated_until,
        NEW.created_at, NEW.prepare_expires_at)
        IS DISTINCT FROM
       (OLD.stripe_account_id, OLD.environment, OLD.attempt_id, OLD.authorization_ref,
        OLD.issuer, OLD.principal_id, OLD.tenant_ref, OLD.membership_ref, OLD.customer_id,
        OLD.price_id, OLD.intent_bytes, OLD.intent_fingerprint, OLD.request_bytes,
        OLD.request_fingerprint, OLD.parameters, OLD.idempotency_key,
        OLD.adapter_version, OLD.api_version, OLD.authenticated_until,
        OLD.created_at, OLD.prepare_expires_at) THEN
        RAISE EXCEPTION 'immutable checkout association conflict';
    END IF;
    IF NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
    IF OLD.generation = 9223372036854775807 THEN
        RAISE EXCEPTION 'checkout generation exhausted';
    END IF;
    IF NEW.generation <> OLD.generation + 1 OR NEW.updated_at < OLD.updated_at
        OR OLD.state IN ('quarantined', 'expired_unsent', 'closed_verified')
        OR NOT (
            (OLD.state = 'prepared' AND NEW.state IN ('dispatching', 'expired_unsent', 'quarantined'))
            OR (OLD.state IN ('dispatching', 'unknown', 'session_attached')
                AND NEW.state IN ('unknown', 'session_attached', 'quarantined'))
            OR (OLD.state = 'session_attached' AND NEW.state = 'closed_verified')
        ) THEN
        RAISE EXCEPTION 'illegal checkout transition';
    END IF;
    IF OLD.session_id IS NOT NULL AND (
        NEW.session_id IS DISTINCT FROM OLD.session_id
        OR NEW.session_expires_at IS DISTINCT FROM OLD.session_expires_at
        OR NEW.session_observed_at < OLD.session_observed_at
        OR NEW.session_observed_at IS NULL
        OR (OLD.session_status <> 'open' AND NEW.session_status IS DISTINCT FROM OLD.session_status)
        OR (OLD.subscription_id IS NOT NULL AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id)
        OR (OLD.handoff_id IS NOT NULL AND NEW.handoff_id IS DISTINCT FROM OLD.handoff_id)
    ) THEN
        RAISE EXCEPTION 'checkout session evidence cannot regress';
    END IF;
    IF NEW.state IN ('unknown', 'quarantined', 'closed_verified') AND
        (NEW.session_id, NEW.session_status, NEW.session_observed_at,
         NEW.session_expires_at, NEW.subscription_id, NEW.handoff_id)
        IS DISTINCT FROM
        (OLD.session_id, OLD.session_status, OLD.session_observed_at,
         OLD.session_expires_at, OLD.subscription_id, OLD.handoff_id) THEN
        RAISE EXCEPTION 'recovery must preserve checkout evidence';
    END IF;
    IF NEW.handoff_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.checkout_handoffs
        WHERE handoff_id = NEW.handoff_id
          AND (stripe_account_id, environment, tenant_ref, attempt_id, session_id,
               customer_id, price_id, subscription_id)
              IS NOT DISTINCT FROM
              (NEW.stripe_account_id, NEW.environment, NEW.tenant_ref, NEW.attempt_id, NEW.session_id,
               NEW.customer_id, NEW.price_id, NEW.subscription_id)
    ) THEN
        RAISE EXCEPTION 'checkout handoff does not match the stored session';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER checkout_attempt_transition BEFORE UPDATE OR DELETE ON gvai_authority.checkout_attempts
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.checkout_attempt_guard();

CREATE FUNCTION gvai_authority.checkout_handoff_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
BEGIN
    IF TG_OP <> 'INSERT' THEN RAISE EXCEPTION 'checkout handoffs are append-only'; END IF;
    SELECT * INTO STRICT subscription FROM gvai_authority.billing_subscriptions
    WHERE stripe_account_id = NEW.stripe_account_id AND environment = NEW.environment
      AND tenant_ref = NEW.tenant_ref AND subscription_id = NEW.subscription_id FOR SHARE;
    IF NOT subscription.admitted OR subscription.customer_id IS DISTINCT FROM NEW.customer_id
        OR subscription.price_id IS DISTINCT FROM NEW.price_id
        OR NEW.verified_at > clock_timestamp() THEN
        RAISE EXCEPTION 'checkout handoff subscription association denied';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER checkout_handoff_identity BEFORE INSERT OR UPDATE OR DELETE ON gvai_authority.checkout_handoffs
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.checkout_handoff_guard();

CREATE FUNCTION gvai_authority.checkout_same_request(
    p_left gvai_authority.checkout_attempts, p_right gvai_authority.checkout_attempts
)
RETURNS boolean LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
    SELECT (p_left.stripe_account_id, p_left.environment, p_left.attempt_id,
        p_left.authorization_ref, p_left.issuer, p_left.principal_id, p_left.tenant_ref,
        p_left.membership_ref, p_left.customer_id, p_left.price_id,
        p_left.intent_bytes, p_left.intent_fingerprint, p_left.request_bytes,
        p_left.request_fingerprint, p_left.parameters, p_left.idempotency_key,
        p_left.adapter_version, p_left.api_version)
        IS NOT DISTINCT FROM
       (p_right.stripe_account_id, p_right.environment, p_right.attempt_id,
        p_right.authorization_ref, p_right.issuer, p_right.principal_id, p_right.tenant_ref,
        p_right.membership_ref, p_right.customer_id, p_right.price_id,
        p_right.intent_bytes, p_right.intent_fingerprint, p_right.request_bytes,
        p_right.request_fingerprint, p_right.parameters, p_right.idempotency_key,
        p_right.adapter_version, p_right.api_version)
$function$;

CREATE FUNCTION gvai_authority.checkout_check_fence(
    p_current gvai_authority.checkout_attempts, p_expected_record gvai_authority.checkout_attempts,
    p_expected_generation bigint, p_now timestamptz, p_changing boolean
)
RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF p_current.attempt_id IS NULL OR p_expected_record.attempt_id IS NULL
        OR p_expected_generation IS NULL OR p_changing IS NULL
        OR p_current IS DISTINCT FROM p_expected_record
        OR p_current.generation IS DISTINCT FROM p_expected_generation
        OR NOT gvai_authority.billing_valid_time(p_now) OR p_now < p_current.updated_at THEN
        RAISE EXCEPTION 'checkout full-record fence lost';
    END IF;
    IF p_changing AND p_current.generation = 9223372036854775807 THEN
        RAISE EXCEPTION 'checkout generation exhausted';
    END IF;
END;
$function$;

CREATE FUNCTION gvai_authority.checkout_lock_tenant(p_expected_record gvai_authority.checkout_attempts)
RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    PERFORM 1 FROM gvai_authority.tenants
    WHERE tenant_ref = p_expected_record.tenant_ref FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'checkout tenant unavailable'; END IF;
END;
$function$;

-- These routines return only sanitized outcomes. Readback/commit certainty belongs
-- to the future trusted transaction adapter; no return value permits Stripe retry.
CREATE FUNCTION gvai_authority.prepare_checkout_attempt_v1(p_candidate gvai_authority.checkout_attempts)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    candidate gvai_authority.checkout_attempts%ROWTYPE;
    existing gvai_authority.checkout_attempts%ROWTYPE;
    authorization_row gvai_authority.checkout_authorizations%ROWTYPE;
    membership gvai_authority.tenant_memberships%ROWTYPE;
    customer gvai_authority.billing_customers%ROWTYPE;
    price gvai_authority.billing_prices%ROWTYPE;
    checked_at timestamptz;
BEGIN
    IF p_candidate.state IS DISTINCT FROM 'prepared' OR p_candidate.generation IS DISTINCT FROM 0
        OR p_candidate.lease_id IS NOT NULL OR p_candidate.lease_expires_at IS NOT NULL
        OR p_candidate.session_id IS NOT NULL OR p_candidate.session_status IS NOT NULL
        OR p_candidate.session_observed_at IS NOT NULL OR p_candidate.session_expires_at IS NOT NULL
        OR p_candidate.subscription_id IS NOT NULL OR p_candidate.handoff_id IS NOT NULL THEN
        RAISE EXCEPTION 'checkout prepare requires an unsent candidate';
    END IF;
    PERFORM gvai_authority.checkout_lock_tenant(p_candidate);
    SELECT * INTO STRICT membership FROM gvai_authority.tenant_memberships
    WHERE tenant_ref = p_candidate.tenant_ref AND membership_ref = p_candidate.membership_ref FOR SHARE;
    SELECT * INTO STRICT authorization_row FROM gvai_authority.checkout_authorizations
    WHERE authorization_ref = p_candidate.authorization_ref FOR SHARE;
    SELECT * INTO STRICT customer FROM gvai_authority.billing_customers
    WHERE stripe_account_id = p_candidate.stripe_account_id AND environment = p_candidate.environment
      AND tenant_ref = p_candidate.tenant_ref AND customer_id = p_candidate.customer_id FOR SHARE;
    SELECT * INTO STRICT price FROM gvai_authority.billing_prices
    WHERE stripe_account_id = p_candidate.stripe_account_id AND environment = p_candidate.environment
      AND price_id = p_candidate.price_id FOR SHARE;
    checked_at := date_trunc('second', clock_timestamp());
    IF NOT EXISTS (SELECT 1 FROM gvai_authority.tenants
            WHERE tenant_ref = p_candidate.tenant_ref AND status = 'active')
        OR membership.status <> 'active' OR membership.principal_id IS DISTINCT FROM p_candidate.principal_id
        OR (authorization_row.issuer, authorization_row.principal_id, authorization_row.tenant_ref, authorization_row.membership_ref)
            IS DISTINCT FROM (p_candidate.issuer, p_candidate.principal_id, p_candidate.tenant_ref, p_candidate.membership_ref)
        OR NOT authorization_row.active OR NOT authorization_row.checkout_approved
        OR (authorization_row.expires_at IS NOT NULL AND authorization_row.expires_at <= clock_timestamp())
        OR p_candidate.authenticated_until IS NULL OR p_candidate.authenticated_until <= clock_timestamp()
        OR NOT price.approved THEN
        RAISE EXCEPTION 'checkout authorization denied' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO existing FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_candidate.stripe_account_id AND environment = p_candidate.environment
      AND attempt_id = p_candidate.attempt_id FOR UPDATE;
    IF FOUND THEN
        IF gvai_authority.checkout_same_request(existing, p_candidate)
            AND (existing.request_bytes, existing.parameters)
                IS NOT DISTINCT FROM (p_candidate.request_bytes, p_candidate.parameters)
        THEN RETURN 'duplicate'; END IF;
        RETURN 'conflict';
    END IF;
    IF EXISTS (SELECT 1 FROM gvai_authority.advisory_pilots WHERE tenant_ref = p_candidate.tenant_ref)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_subscriptions
            WHERE tenant_ref = p_candidate.tenant_ref AND admitted)
        OR EXISTS (SELECT 1 FROM gvai_authority.checkout_attempts
            WHERE tenant_ref = p_candidate.tenant_ref AND state NOT IN ('expired_unsent', 'closed_verified'))
        OR p_candidate.prepare_expires_at IS NULL OR p_candidate.prepare_expires_at <= clock_timestamp()
        OR p_candidate.prepare_expires_at > p_candidate.authenticated_until THEN
        RAISE EXCEPTION 'checkout purchase admission denied';
    END IF;
    candidate := p_candidate;
    -- Request identity is supplied by the gateway; creation time is database-owned.
    candidate.created_at := checked_at;
    candidate.updated_at := checked_at;
    INSERT INTO gvai_authority.checkout_attempts SELECT (candidate).*
    ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN 'prepared'; END IF;
    RETURN 'conflict';
END;
$function$;

CREATE FUNCTION gvai_authority.claim_checkout_attempt_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint,
    p_lease_id text, p_lease_seconds integer
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    authorization_row gvai_authority.checkout_authorizations%ROWTYPE;
    membership gvai_authority.tenant_memberships%ROWTYPE;
    customer gvai_authority.billing_customers%ROWTYPE;
    price gvai_authority.billing_prices%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT membership FROM gvai_authority.tenant_memberships
    WHERE tenant_ref = p_expected_record.tenant_ref AND membership_ref = p_expected_record.membership_ref FOR SHARE;
    SELECT * INTO STRICT authorization_row FROM gvai_authority.checkout_authorizations
    WHERE authorization_ref = p_expected_record.authorization_ref FOR SHARE;
    SELECT * INTO STRICT customer FROM gvai_authority.billing_customers
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND tenant_ref = p_expected_record.tenant_ref AND customer_id = p_expected_record.customer_id FOR SHARE;
    SELECT * INTO STRICT price FROM gvai_authority.billing_prices
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND price_id = p_expected_record.price_id FOR SHARE;
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state <> 'prepared' OR attempt.generation = 9223372036854775807
        OR attempt.prepare_expires_at <= clock_timestamp()
        OR attempt.authenticated_until <= clock_timestamp()
        OR p_lease_id IS NULL OR p_lease_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 1 AND 300
        OR NOT EXISTS (SELECT 1 FROM gvai_authority.tenants
            WHERE tenant_ref = attempt.tenant_ref AND status = 'active')
        OR membership.status <> 'active' OR membership.principal_id IS DISTINCT FROM attempt.principal_id
        OR (authorization_row.issuer, authorization_row.principal_id, authorization_row.tenant_ref, authorization_row.membership_ref)
            IS DISTINCT FROM (attempt.issuer, attempt.principal_id, attempt.tenant_ref, attempt.membership_ref)
        OR NOT authorization_row.active OR NOT authorization_row.checkout_approved
        OR (authorization_row.expires_at IS NOT NULL AND authorization_row.expires_at <= clock_timestamp())
        OR NOT price.approved
        OR EXISTS (SELECT 1 FROM gvai_authority.advisory_pilots WHERE tenant_ref = attempt.tenant_ref)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_subscriptions
            WHERE tenant_ref = attempt.tenant_ref AND admitted) THEN
        RAISE EXCEPTION 'checkout creation claim denied';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'dispatching', generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = p_lease_id, lease_expires_at = checked_at + make_interval(secs => p_lease_seconds)
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'dispatching';
END;
$function$;

-- p_evidence is exclusively trusted authoritative adapter output, never a client
-- or webhook payload. Function permission, not a caller boolean, is the boundary.
CREATE FUNCTION gvai_authority.confirm_checkout_session_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint,
    p_lease_id text, p_evidence gvai_authority.checkout_attempts
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    other_attempt gvai_authority.checkout_attempts%ROWTYPE;
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, false);
    IF attempt.state = 'session_attached' AND attempt.lease_id IS NULL
        AND gvai_authority.checkout_same_request(attempt, p_evidence)
        AND attempt.request_bytes IS NOT DISTINCT FROM p_evidence.request_bytes
        AND attempt.request_fingerprint IS NOT DISTINCT FROM p_evidence.request_fingerprint
        AND (attempt.session_id, attempt.session_status, attempt.session_observed_at,
             attempt.session_expires_at, attempt.subscription_id, attempt.handoff_id)
            IS NOT DISTINCT FROM
            (p_evidence.session_id, p_evidence.session_status, p_evidence.session_observed_at,
             p_evidence.session_expires_at, p_evidence.subscription_id, p_evidence.handoff_id)
    THEN
        RETURN 'duplicate';
    END IF;
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state NOT IN ('dispatching', 'unknown', 'session_attached')
        OR p_lease_id IS NULL OR attempt.lease_id IS DISTINCT FROM p_lease_id
        OR attempt.lease_expires_at IS NULL OR attempt.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'checkout confirmation lease lost';
    END IF;
    IF NOT gvai_authority.checkout_same_request(attempt, p_evidence)
        OR p_evidence.session_id IS NULL OR p_evidence.session_id !~ '^cs_test_[A-Za-z0-9]{1,120}$'
        OR NOT gvai_authority.billing_valid_time(p_evidence.session_observed_at)
        OR NOT gvai_authority.billing_valid_time(p_evidence.session_expires_at)
        OR p_evidence.session_observed_at < attempt.updated_at
        OR p_evidence.session_observed_at > checked_at
        OR p_evidence.session_status IS NULL OR p_evidence.session_status NOT IN ('open', 'expired', 'complete')
        OR (p_evidence.session_status = 'open' AND p_evidence.session_observed_at >= p_evidence.session_expires_at)
        OR (p_evidence.session_status = 'expired' AND p_evidence.session_observed_at < p_evidence.session_expires_at)
        OR (p_evidence.session_status = 'complete' AND (p_evidence.subscription_id IS NULL
            OR p_evidence.subscription_id !~ '^sub_[A-Za-z0-9]{1,124}$'))
        OR (p_evidence.session_status <> 'complete' AND
            (p_evidence.subscription_id IS NOT NULL OR p_evidence.handoff_id IS NOT NULL))
        OR (attempt.session_id IS NOT NULL AND (
            p_evidence.session_id IS DISTINCT FROM attempt.session_id
            OR p_evidence.session_expires_at IS DISTINCT FROM attempt.session_expires_at
            OR p_evidence.session_observed_at < attempt.session_observed_at
            OR (attempt.session_status <> 'open' AND p_evidence.session_status IS DISTINCT FROM attempt.session_status)
            OR (attempt.subscription_id IS NOT NULL AND p_evidence.subscription_id IS DISTINCT FROM attempt.subscription_id)
            OR (attempt.handoff_id IS NOT NULL AND p_evidence.handoff_id IS DISTINCT FROM attempt.handoff_id)
        )) THEN
        UPDATE gvai_authority.checkout_attempts
        SET state = 'quarantined', generation = attempt.generation + 1, updated_at = checked_at,
            lease_id = NULL, lease_expires_at = NULL
        WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
          AND attempt_id = attempt.attempt_id;
        RETURN 'conflict';
    END IF;
    -- Serialize session identity even when its row does not exist yet.
    PERFORM pg_advisory_xact_lock(hashtextextended(
        attempt.stripe_account_id || ':' || attempt.environment || ':' || p_evidence.session_id, 0));
    IF attempt.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'checkout lease expired waiting for session identity';
    END IF;
    SELECT * INTO other_attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND session_id = p_evidence.session_id AND attempt_id <> attempt.attempt_id;
    IF FOUND THEN
        UPDATE gvai_authority.checkout_attempts
        SET state = 'quarantined', generation = attempt.generation + 1, updated_at = checked_at,
            lease_id = NULL, lease_expires_at = NULL
        WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
          AND attempt_id = attempt.attempt_id;
        RETURN 'conflict';
    END IF;
    IF p_evidence.handoff_id IS NOT NULL THEN
        SELECT * INTO subscription FROM gvai_authority.billing_subscriptions
        WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
          AND subscription_id = p_evidence.subscription_id FOR SHARE;
        IF attempt.lease_expires_at <= clock_timestamp() THEN
            RAISE EXCEPTION 'checkout lease expired waiting for subscription';
        END IF;
        IF NOT FOUND OR NOT subscription.admitted OR subscription.tenant_ref IS DISTINCT FROM attempt.tenant_ref
            OR subscription.customer_id IS DISTINCT FROM attempt.customer_id
            OR subscription.price_id IS DISTINCT FROM attempt.price_id THEN
            UPDATE gvai_authority.checkout_attempts
            SET state = 'quarantined', generation = attempt.generation + 1, updated_at = checked_at,
                lease_id = NULL, lease_expires_at = NULL
            WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
              AND attempt_id = attempt.attempt_id;
            RETURN 'conflict';
        END IF;
        INSERT INTO gvai_authority.checkout_handoffs
            (handoff_id, stripe_account_id, environment, tenant_ref, attempt_id,
             session_id, customer_id, subscription_id, price_id, verified_at)
        VALUES (p_evidence.handoff_id, attempt.stripe_account_id, attempt.environment, attempt.tenant_ref,
            attempt.attempt_id, p_evidence.session_id, attempt.customer_id,
            p_evidence.subscription_id, attempt.price_id, p_evidence.session_observed_at)
        ON CONFLICT DO NOTHING;
        IF NOT EXISTS (
            SELECT 1 FROM gvai_authority.checkout_handoffs
            WHERE handoff_id = p_evidence.handoff_id
              AND (stripe_account_id, environment, tenant_ref, attempt_id, session_id,
                   customer_id, subscription_id, price_id)
                  IS NOT DISTINCT FROM
                  (attempt.stripe_account_id, attempt.environment, attempt.tenant_ref, attempt.attempt_id,
                   p_evidence.session_id, attempt.customer_id, p_evidence.subscription_id, attempt.price_id)
        ) THEN
            IF attempt.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'checkout lease expired waiting for handoff identity';
            END IF;
            UPDATE gvai_authority.checkout_attempts
            SET state = 'quarantined', generation = attempt.generation + 1, updated_at = checked_at,
                lease_id = NULL, lease_expires_at = NULL
            WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
              AND attempt_id = attempt.attempt_id;
            RETURN 'conflict';
        END IF;
    END IF;
    IF attempt.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'checkout lease expired during confirmation';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'session_attached', generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = NULL, lease_expires_at = NULL, session_id = p_evidence.session_id,
        session_status = p_evidence.session_status, session_observed_at = p_evidence.session_observed_at,
        session_expires_at = p_evidence.session_expires_at, subscription_id = p_evidence.subscription_id,
        handoff_id = p_evidence.handoff_id
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'session_attached';
END;
$function$;

CREATE FUNCTION gvai_authority.claim_checkout_reconciliation_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint,
    p_lease_id text, p_lease_seconds integer
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state NOT IN ('dispatching', 'unknown', 'session_attached')
        OR (attempt.lease_expires_at IS NOT NULL AND attempt.lease_expires_at > clock_timestamp())
        OR p_lease_id IS NULL OR p_lease_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION 'checkout reconciliation claim denied';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = CASE WHEN attempt.session_id IS NULL THEN 'unknown' ELSE 'session_attached' END,
        generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = p_lease_id, lease_expires_at = checked_at + make_interval(secs => p_lease_seconds)
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN CASE WHEN attempt.session_id IS NULL THEN 'unknown' ELSE 'session_attached' END;
END;
$function$;

CREATE FUNCTION gvai_authority.mark_checkout_unknown_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state NOT IN ('dispatching', 'unknown', 'session_attached') THEN
        RAISE EXCEPTION 'checkout unknown transition denied';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'unknown', generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = NULL, lease_expires_at = NULL
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'unknown';
END;
$function$;

CREATE FUNCTION gvai_authority.quarantine_checkout_attempt_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state NOT IN ('prepared', 'dispatching', 'unknown', 'session_attached') THEN
        RAISE EXCEPTION 'checkout quarantine transition denied';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'quarantined', generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = NULL, lease_expires_at = NULL
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'quarantined';
END;
$function$;

CREATE FUNCTION gvai_authority.expire_checkout_unsent_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state <> 'prepared' OR checked_at < attempt.prepare_expires_at
        OR attempt.session_id IS NOT NULL OR attempt.lease_id IS NOT NULL THEN
        RAISE EXCEPTION 'checkout attempt not proven unsent';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'expired_unsent', generation = attempt.generation + 1, updated_at = checked_at
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'expired_unsent';
END;
$function$;

CREATE FUNCTION gvai_authority.close_checkout_verified_v1(
    p_expected_record gvai_authority.checkout_attempts, p_expected_generation bigint
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
SET statement_timeout = '5s'
SET lock_timeout = '2s'
AS $function$
DECLARE
    attempt gvai_authority.checkout_attempts%ROWTYPE;
    checked_at timestamptz;
BEGIN
    PERFORM gvai_authority.checkout_lock_tenant(p_expected_record);
    SELECT * INTO STRICT attempt FROM gvai_authority.checkout_attempts
    WHERE stripe_account_id = p_expected_record.stripe_account_id AND environment = p_expected_record.environment
      AND attempt_id = p_expected_record.attempt_id FOR UPDATE;
    checked_at := date_trunc('second', clock_timestamp());
    PERFORM gvai_authority.checkout_check_fence(attempt, p_expected_record, p_expected_generation, checked_at, true);
    IF attempt.state <> 'session_attached' OR attempt.lease_id IS NOT NULL
        OR NOT (
            (attempt.session_status = 'expired' AND attempt.subscription_id IS NULL
                AND attempt.session_observed_at >= attempt.session_expires_at)
            OR (attempt.session_status = 'complete' AND attempt.handoff_id IS NOT NULL AND EXISTS (
                SELECT 1 FROM gvai_authority.checkout_handoffs AS handoff
                JOIN gvai_authority.billing_subscriptions AS subscription
                  ON (subscription.stripe_account_id, subscription.environment, subscription.tenant_ref,
                      subscription.subscription_id, subscription.customer_id, subscription.price_id)
                   = (handoff.stripe_account_id, handoff.environment, handoff.tenant_ref,
                      handoff.subscription_id, handoff.customer_id, handoff.price_id)
                WHERE handoff.handoff_id = attempt.handoff_id
                  AND (handoff.stripe_account_id, handoff.environment, handoff.tenant_ref,
                       handoff.attempt_id, handoff.session_id, handoff.customer_id, handoff.price_id,
                       handoff.subscription_id)
                    = (attempt.stripe_account_id, attempt.environment, attempt.tenant_ref,
                       attempt.attempt_id, attempt.session_id, attempt.customer_id, attempt.price_id,
                       attempt.subscription_id)
                  AND subscription.admitted
                FOR SHARE OF handoff, subscription
            ))
        ) THEN
        RAISE EXCEPTION 'checkout closure lacks authoritative evidence or durable handoff';
    END IF;
    UPDATE gvai_authority.checkout_attempts
    SET state = 'closed_verified', generation = attempt.generation + 1, updated_at = checked_at,
        lease_id = NULL, lease_expires_at = NULL
    WHERE stripe_account_id = attempt.stripe_account_id AND environment = attempt.environment
      AND attempt_id = attempt.attempt_id;
    RETURN 'closed_verified';
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.checkout_authorizations FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.checkout_attempts FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.checkout_handoffs FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_canonical(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_redirect_valid(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_authorization_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_request_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_attempt_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_handoff_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_same_request(gvai_authority.checkout_attempts, gvai_authority.checkout_attempts) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_check_fence(gvai_authority.checkout_attempts, gvai_authority.checkout_attempts, bigint, timestamptz, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.checkout_lock_tenant(gvai_authority.checkout_attempts) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.prepare_checkout_attempt_v1(gvai_authority.checkout_attempts) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.claim_checkout_attempt_v1(gvai_authority.checkout_attempts, bigint, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.confirm_checkout_session_v1(gvai_authority.checkout_attempts, bigint, text, gvai_authority.checkout_attempts) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.claim_checkout_reconciliation_v1(gvai_authority.checkout_attempts, bigint, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.mark_checkout_unknown_v1(gvai_authority.checkout_attempts, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.quarantine_checkout_attempt_v1(gvai_authority.checkout_attempts, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.expire_checkout_unsent_v1(gvai_authority.checkout_attempts, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.close_checkout_verified_v1(gvai_authority.checkout_attempts, bigint) FROM PUBLIC;

-- Refuse inherited default object ACLs rather than silently exposing new objects.
DO $acl_guard$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_class AS object
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = object.relnamespace,
            LATERAL pg_catalog.aclexplode(coalesce(object.relacl,
                pg_catalog.acldefault('r', object.relowner))) AS privilege
        WHERE namespace.nspname = 'gvai_authority'
          AND object.relname IN ('checkout_authorizations', 'checkout_attempts', 'checkout_handoffs')
          AND privilege.grantee <> object.relowner
    ) OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_proc AS object
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = object.pronamespace,
            LATERAL pg_catalog.aclexplode(coalesce(object.proacl,
                pg_catalog.acldefault('f', object.proowner))) AS privilege
        WHERE namespace.nspname = 'gvai_authority'
          AND (object.proname LIKE 'checkout_%' OR object.proname IN (
              'prepare_checkout_attempt_v1', 'claim_checkout_attempt_v1',
              'confirm_checkout_session_v1', 'claim_checkout_reconciliation_v1',
              'mark_checkout_unknown_v1', 'quarantine_checkout_attempt_v1',
              'expire_checkout_unsent_v1', 'close_checkout_verified_v1'))
          AND privilege.grantee <> object.proowner
    ) THEN
        RAISE EXCEPTION 'unexpected checkout object ACL';
    END IF;
END;
$acl_guard$;

COMMIT;
