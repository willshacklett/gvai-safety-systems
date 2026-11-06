BEGIN;

DO $owner_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS role ON role.oid = namespace.nspowner
        WHERE namespace.nspname = 'gvai_authority'
          AND role.rolname = current_user AND NOT role.rolsuper
    ) OR to_regprocedure('gvai_authority.advisory_customer_v1(text,bytea,text,text)') IS NULL
      OR to_regprocedure('gvai_authority.reserve_v1(text,bytea,text,bigint,text,text,text,text)') IS NULL
    THEN
        RAISE EXCEPTION 'billing migration requires migrations 001-003 and their non-superuser owner';
    END IF;
END;
$owner_guard$;

CREATE FUNCTION gvai_authority.billing_valid_time(p_time timestamptz)
RETURNS boolean
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
    SELECT p_time IS NOT NULL AND isfinite(p_time)
        AND p_time >= TIMESTAMPTZ '1970-01-01 00:00:00+00'
        AND date_trunc('second', p_time) = p_time
$function$;

CREATE TABLE gvai_authority.billing_prices (
    stripe_account_id text NOT NULL CHECK (stripe_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    price_id text NOT NULL CHECK (price_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    product_id text NOT NULL CHECK (product_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    currency text NOT NULL CHECK (currency = 'usd'),
    unit_amount bigint NOT NULL CHECK (unit_amount = 9900),
    interval_unit text NOT NULL CHECK (interval_unit = 'month'),
    interval_count integer NOT NULL CHECK (interval_count = 1),
    quantity integer NOT NULL CHECK (quantity = 1),
    approved boolean NOT NULL DEFAULT false,
    max_evidence_age_seconds integer CHECK (max_evidence_age_seconds BETWEEN 1 AND 86400),
    CHECK (NOT approved OR max_evidence_age_seconds IS NOT NULL),
    PRIMARY KEY (stripe_account_id, environment, price_id)
);

CREATE TABLE gvai_authority.billing_customers (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    customer_id text NOT NULL CHECK (customer_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    membership_ref bigint NOT NULL,
    PRIMARY KEY (stripe_account_id, environment, customer_id),
    UNIQUE (stripe_account_id, environment, tenant_ref),
    UNIQUE (stripe_account_id, environment, tenant_ref, customer_id),
    FOREIGN KEY (tenant_ref, membership_ref) REFERENCES gvai_authority.tenant_memberships (tenant_ref, membership_ref)
);

CREATE TABLE gvai_authority.billing_subscriptions (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    customer_id text NOT NULL,
    subscription_id text NOT NULL CHECK (subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    price_id text NOT NULL,
    status text NOT NULL DEFAULT 'incomplete' CHECK (
        status IN ('active', 'incomplete', 'incomplete_expired', 'trialing', 'past_due', 'unpaid', 'paused', 'canceled')
    ),
    cancel_at timestamptz CHECK (cancel_at IS NULL OR gvai_authority.billing_valid_time(cancel_at)),
    terminal_canceled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    uncertain boolean NOT NULL DEFAULT true,
    observed_at timestamptz CHECK (observed_at IS NULL OR gvai_authority.billing_valid_time(observed_at)),
    admitted boolean NOT NULL DEFAULT false,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at timestamptz CHECK (
        lease_expires_at IS NULL OR gvai_authority.billing_valid_time(lease_expires_at)
    ),
    lease_started_at timestamptz CHECK (
        lease_started_at IS NULL OR gvai_authority.billing_valid_time(lease_started_at)
    ),
    lease_id text,
    lease_source_event_id text,
    lease_event_generation bigint,
    CHECK (NOT terminal_canceled OR status = 'canceled'),
    CHECK ((lease_id IS NULL AND lease_started_at IS NULL AND lease_expires_at IS NULL
                AND lease_source_event_id IS NULL AND lease_event_generation IS NULL)
        OR (lease_id IS NOT NULL AND lease_started_at IS NOT NULL AND lease_expires_at IS NOT NULL
            AND lease_expires_at > lease_started_at
            AND lease_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            AND ((lease_source_event_id IS NULL AND lease_event_generation IS NULL)
                OR (lease_source_event_id IS NOT NULL AND lease_event_generation IS NOT NULL)))),
    PRIMARY KEY (stripe_account_id, environment, subscription_id),
    UNIQUE (stripe_account_id, environment, tenant_ref, subscription_id),
    UNIQUE (stripe_account_id, environment, tenant_ref, subscription_id, price_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, customer_id) REFERENCES gvai_authority.billing_customers (stripe_account_id, environment, tenant_ref, customer_id),
    FOREIGN KEY (stripe_account_id, environment, price_id) REFERENCES gvai_authority.billing_prices (stripe_account_id, environment, price_id)
);

CREATE UNIQUE INDEX billing_subscriptions_one_current ON gvai_authority.billing_subscriptions (stripe_account_id, environment, tenant_ref) WHERE admitted;
CREATE UNIQUE INDEX billing_subscriptions_one_paid_tenant ON gvai_authority.billing_subscriptions (tenant_ref) WHERE admitted;

CREATE TABLE gvai_authority.billing_event_inbox (
    stripe_account_id text NOT NULL CHECK (stripe_account_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    event_id text NOT NULL CHECK (event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    event_type text NOT NULL CHECK (event_type IN (
        'checkout.session.completed', 'customer.subscription.created',
        'customer.subscription.updated', 'customer.subscription.deleted',
        'invoice.paid', 'invoice.payment_failed', 'invoice.payment_action_required'
    )),
    api_version text NOT NULL CHECK (length(api_version) BETWEEN 1 AND 128),
    target_subscription_id text NOT NULL CHECK (
        target_subscription_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    payload bytea NOT NULL CHECK (octet_length(payload) BETWEEN 1 AND 262144),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'processing', 'processed', 'retry', 'quarantined')),
    attempts bigint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at timestamptz CHECK (
        lease_expires_at IS NULL OR gvai_authority.billing_valid_time(lease_expires_at)
    ),
    error_code text CHECK (error_code IN ('delivery_conflict', 'association_unresolved', 'verification_failed', 'transient_failure', 'evidence_conflict')),
    conflict_detected boolean NOT NULL DEFAULT false,
    CHECK (state <> 'processing' OR lease_expires_at IS NOT NULL),
    CHECK (NOT conflict_detected OR state = 'quarantined'),
    CHECK (payload_digest = gvai_authority.digest(payload, 'sha256')),
    PRIMARY KEY (stripe_account_id, environment, event_id)
);

CREATE INDEX billing_event_inbox_claimable ON gvai_authority.billing_event_inbox (state, lease_expires_at, received_at)
    WHERE state IN ('pending', 'retry', 'processing');

CREATE TABLE gvai_authority.billing_reconciliations (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    subscription_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision >= 0),
    reconciliation_id text NOT NULL CHECK (reconciliation_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    source_event_id text,
    observed_at timestamptz NOT NULL CHECK (isfinite(observed_at) AND gvai_authority.billing_valid_time(observed_at)),
    lease_generation bigint NOT NULL CHECK (lease_generation >= 0),
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    certain boolean NOT NULL DEFAULT false,
    outcome text NOT NULL CHECK (outcome IN ('applied', 'uncertain', 'terminal', 'conflict')),
    PRIMARY KEY (stripe_account_id, environment, tenant_ref, subscription_id, revision),
    UNIQUE (stripe_account_id, environment, reconciliation_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id) REFERENCES gvai_authority.billing_subscriptions (stripe_account_id, environment, tenant_ref, subscription_id),
    FOREIGN KEY (stripe_account_id, environment, source_event_id) REFERENCES gvai_authority.billing_event_inbox (stripe_account_id, environment, event_id)
);

CREATE TABLE gvai_authority.billing_invoices (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    subscription_id text NOT NULL,
    invoice_id text NOT NULL CHECK (invoice_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    status text NOT NULL CHECK (status IN ('draft', 'open', 'paid', 'void', 'uncollectible')),
    currency text NOT NULL CHECK (currency = 'usd'),
    amount_paid bigint NOT NULL CHECK (amount_paid >= 0),
    verified boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL,
    CHECK (NOT verified OR (status = 'paid' AND amount_paid = 9900)),
    PRIMARY KEY (stripe_account_id, environment, invoice_id),
    UNIQUE (stripe_account_id, environment, tenant_ref, subscription_id, invoice_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id) REFERENCES gvai_authority.billing_subscriptions (stripe_account_id, environment, tenant_ref, subscription_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, revision) REFERENCES gvai_authority.billing_reconciliations (stripe_account_id, environment, tenant_ref, subscription_id, revision)
);

CREATE TABLE gvai_authority.billing_paid_intervals (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    subscription_id text NOT NULL,
    invoice_id text NOT NULL,
    invoice_line_id text NOT NULL CHECK (invoice_line_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    price_id text NOT NULL,
    period_start timestamptz NOT NULL,
    period_end timestamptz NOT NULL,
    revision bigint NOT NULL,
    CHECK (isfinite(period_start) AND gvai_authority.billing_valid_time(period_start)),
    CHECK (isfinite(period_end) AND gvai_authority.billing_valid_time(period_end)),
    CHECK (period_end > period_start AND period_end - period_start <= INTERVAL '31 days'),
    PRIMARY KEY (stripe_account_id, environment, invoice_id, invoice_line_id),
    UNIQUE (stripe_account_id, environment, invoice_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, invoice_id) REFERENCES gvai_authority.billing_invoices (stripe_account_id, environment, tenant_ref, subscription_id, invoice_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, price_id) REFERENCES gvai_authority.billing_subscriptions (stripe_account_id, environment, tenant_ref, subscription_id, price_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, revision) REFERENCES gvai_authority.billing_reconciliations (stripe_account_id, environment, tenant_ref, subscription_id, revision)
);

CREATE INDEX billing_paid_intervals_by_subscription ON gvai_authority.billing_paid_intervals
    (tenant_ref, stripe_account_id, environment, subscription_id, period_start, period_end);

CREATE TABLE gvai_authority.billing_entitlements (
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    subscription_id text NOT NULL,
    revision bigint NOT NULL,
    eligibility text NOT NULL DEFAULT 'deny' CHECK (eligibility IN ('deny', 'eligible')),
    uncertain boolean NOT NULL DEFAULT true,
    coverage_start timestamptz,
    coverage_end timestamptz,
    fresh_until timestamptz,
    cancel_at timestamptz CHECK (cancel_at IS NULL OR gvai_authority.billing_valid_time(cancel_at)),
    CHECK (eligibility = 'deny' OR (
        NOT uncertain AND coverage_start IS NOT NULL AND coverage_end IS NOT NULL
        AND fresh_until IS NOT NULL AND isfinite(coverage_start)
        AND isfinite(coverage_end) AND isfinite(fresh_until)
        AND gvai_authority.billing_valid_time(coverage_start)
        AND gvai_authority.billing_valid_time(coverage_end)
        AND gvai_authority.billing_valid_time(fresh_until)
        AND coverage_end > coverage_start AND fresh_until > coverage_start
        AND (cancel_at IS NULL OR cancel_at > coverage_start)
    )),
    PRIMARY KEY (stripe_account_id, environment, tenant_ref, subscription_id),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, revision) REFERENCES gvai_authority.billing_reconciliations (stripe_account_id, environment, tenant_ref, subscription_id, revision)
);

CREATE TABLE gvai_authority.billing_advisory_attempts (
    event_id text PRIMARY KEY REFERENCES gvai_authority.reservation_events (event_id),
    stripe_account_id text NOT NULL,
    environment text NOT NULL CHECK (environment IN ('sandbox')),
    tenant_ref bigint NOT NULL,
    subscription_id text NOT NULL,
    revision bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('reserved', 'completed', 'failed')),
    FOREIGN KEY (stripe_account_id, environment, tenant_ref, subscription_id, revision) REFERENCES gvai_authority.billing_reconciliations (stripe_account_id, environment, tenant_ref, subscription_id, revision)
);

CREATE TABLE gvai_authority.billing_installation (
    migration_id text PRIMARY KEY CHECK (migration_id = '004_subscription_billing_v1'),
    contract_version integer NOT NULL CHECK (contract_version = 1),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION gvai_authority.billing_append_only()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    RAISE EXCEPTION 'billing evidence is append-only';
END;
$function$;

CREATE FUNCTION gvai_authority.billing_subscription_guard()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing subscription history cannot be deleted';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.stripe_account_id, NEW.environment, NEW.tenant_ref, NEW.customer_id,
                NEW.subscription_id, NEW.price_id)
            IS DISTINCT FROM
            (OLD.stripe_account_id, OLD.environment, OLD.tenant_ref, OLD.customer_id,
                OLD.subscription_id, OLD.price_id)
            OR (OLD.terminal_canceled AND NOT NEW.terminal_canceled)
            OR NEW.revision < OLD.revision
            OR NEW.lease_generation < OLD.lease_generation
            OR (OLD.observed_at IS NOT NULL AND
                (NEW.observed_at IS NULL OR NEW.observed_at < OLD.observed_at))
        THEN
            RAISE EXCEPTION 'billing subscription identity or revision conflict';
        END IF;
        IF NEW.revision = OLD.revision AND (
            NEW.status IS DISTINCT FROM OLD.status OR NEW.cancel_at IS DISTINCT FROM OLD.cancel_at
            OR NEW.observed_at IS DISTINCT FROM OLD.observed_at
            OR (OLD.uncertain AND NOT NEW.uncertain)
            OR (NOT OLD.terminal_canceled AND NEW.terminal_canceled)
        ) THEN
            RAISE EXCEPTION 'billing state change requires a new reconciliation';
        END IF;
        IF NEW.lease_generation = OLD.lease_generation AND NEW.lease_id IS NOT NULL
            AND (NEW.lease_id, NEW.lease_started_at, NEW.lease_expires_at,
                 NEW.lease_source_event_id, NEW.lease_event_generation)
                IS DISTINCT FROM
                (OLD.lease_id, OLD.lease_started_at, OLD.lease_expires_at,
                 OLD.lease_source_event_id, OLD.lease_event_generation) THEN
            RAISE EXCEPTION 'billing lease change requires a new fence';
        END IF;
    END IF;
    IF NEW.status = 'canceled' AND NOT NEW.terminal_canceled AND NOT NEW.uncertain THEN
        RAISE EXCEPTION 'certain canceled status requires a terminal tombstone';
    END IF;
    IF NEW.admitted AND EXISTS (
        SELECT 1 FROM gvai_authority.advisory_pilots WHERE tenant_ref = NEW.tenant_ref
    ) THEN
        RAISE EXCEPTION 'pilot and paid admission cannot overlap';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION gvai_authority.billing_customer_guard()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.tenants
        WHERE tenant_ref = NEW.tenant_ref
          AND tenant_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
          AND tenant_id <> 'gvai-internal'
    ) OR EXISTS (
        SELECT 1 FROM gvai_authority.advisory_pilots WHERE tenant_ref = NEW.tenant_ref
    ) THEN
        RAISE EXCEPTION 'billing customer requires an external non-pilot tenant';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER billing_customer_insert_guard BEFORE INSERT ON gvai_authority.billing_customers
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_customer_guard();

CREATE FUNCTION gvai_authority.billing_price_guard()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing Price history cannot be deleted';
    END IF;
    IF (to_jsonb(NEW) - 'approved' - 'max_evidence_age_seconds')
        IS DISTINCT FROM (to_jsonb(OLD) - 'approved' - 'max_evidence_age_seconds') THEN
        RAISE EXCEPTION 'billing Price identity cannot change';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER billing_price_identity_guard BEFORE UPDATE OR DELETE ON gvai_authority.billing_prices
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_price_guard();

CREATE TRIGGER billing_subscription_transition_guard BEFORE UPDATE OR DELETE ON gvai_authority.billing_subscriptions
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_subscription_guard();
CREATE TRIGGER billing_subscription_insert_guard BEFORE INSERT ON gvai_authority.billing_subscriptions
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_subscription_guard();

CREATE FUNCTION gvai_authority.billing_invoice_guard()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing invoice history cannot be deleted';
    END IF;
    IF (NEW.stripe_account_id, NEW.environment, NEW.tenant_ref, NEW.subscription_id, NEW.invoice_id)
        IS DISTINCT FROM
       (OLD.stripe_account_id, OLD.environment, OLD.tenant_ref, OLD.subscription_id, OLD.invoice_id)
       OR NEW.revision < OLD.revision
       OR (OLD.verified AND NEW IS DISTINCT FROM OLD)
    THEN
        RAISE EXCEPTION 'billing invoice evidence conflict';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER billing_invoice_evidence_guard BEFORE UPDATE OR DELETE ON gvai_authority.billing_invoices
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_invoice_guard();
CREATE TRIGGER billing_paid_intervals_append_only BEFORE UPDATE OR DELETE ON gvai_authority.billing_paid_intervals
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_append_only();
CREATE TRIGGER billing_reconciliations_append_only BEFORE UPDATE OR DELETE ON gvai_authority.billing_reconciliations
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_append_only();
CREATE TRIGGER billing_customer_identity_guard BEFORE UPDATE OR DELETE ON gvai_authority.billing_customers
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_append_only();

CREATE FUNCTION gvai_authority.billing_event_guard()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'billing event identity cannot be deleted';
    END IF;
    IF (NEW.stripe_account_id, NEW.environment, NEW.event_id, NEW.event_type, NEW.api_version,
            NEW.target_subscription_id, NEW.payload, NEW.payload_digest, NEW.received_at)
        IS DISTINCT FROM
       (OLD.stripe_account_id, OLD.environment, OLD.event_id, OLD.event_type, OLD.api_version,
            OLD.target_subscription_id, OLD.payload, OLD.payload_digest, OLD.received_at)
       OR NEW.attempts < OLD.attempts OR NEW.lease_generation < OLD.lease_generation
       OR (OLD.conflict_detected AND NOT NEW.conflict_detected)
       OR (OLD.state IN ('processed', 'quarantined') AND NEW.state <> OLD.state
            AND NOT (NEW.conflict_detected AND NEW.state = 'quarantined'))
       OR (NEW.state = 'processing' AND
            (NEW.attempts <> OLD.attempts + 1 OR NEW.lease_generation <> OLD.lease_generation + 1))
       OR (NEW.state IN ('processed', 'retry') AND OLD.state <> 'processing')
    THEN
        RAISE EXCEPTION 'billing event transition conflict';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER billing_event_identity_guard BEFORE UPDATE OR DELETE ON gvai_authority.billing_event_inbox
    FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_event_guard();

CREATE FUNCTION gvai_authority.billing_coverage(
    p_account text, p_environment text, p_tenant bigint, p_subscription text, p_time timestamptz
)
RETURNS tstzrange LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    item record;
    coverage_start timestamptz;
    coverage_end timestamptz;
BEGIN
    FOR item IN
        SELECT paid.period_start, paid.period_end
        FROM gvai_authority.billing_paid_intervals AS paid
        JOIN gvai_authority.billing_invoices AS invoice
          ON (invoice.stripe_account_id, invoice.environment, invoice.invoice_id)
           = (paid.stripe_account_id, paid.environment, paid.invoice_id)
        WHERE paid.stripe_account_id = p_account AND paid.environment = p_environment
          AND paid.tenant_ref = p_tenant AND paid.subscription_id = p_subscription
          AND invoice.verified AND invoice.status = 'paid'
        ORDER BY paid.period_start, paid.period_end
    LOOP
        IF coverage_end IS NULL OR item.period_start > coverage_end THEN
            IF coverage_start IS NOT NULL AND coverage_start <= p_time AND p_time < coverage_end THEN
                RETURN tstzrange(coverage_start, coverage_end, '[)');
            END IF;
            coverage_start := item.period_start;
            coverage_end := item.period_end;
        ELSE
            coverage_end := greatest(coverage_end, item.period_end);
        END IF;
    END LOOP;
    IF coverage_start <= p_time AND p_time < coverage_end THEN
        RETURN tstzrange(coverage_start, coverage_end, '[)');
    END IF;
    RETURN NULL;
END;
$function$;

CREATE FUNCTION gvai_authority.billing_projection_guard()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    projection gvai_authority.billing_entitlements%ROWTYPE;
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    price gvai_authority.billing_prices%ROWTYPE;
    coverage tstzrange;
BEGIN
    SELECT * INTO projection FROM gvai_authority.billing_entitlements
    WHERE (stripe_account_id, environment, tenant_ref, subscription_id) =
        (NEW.stripe_account_id, NEW.environment, NEW.tenant_ref, NEW.subscription_id);
    IF NOT FOUND OR projection.eligibility = 'deny' THEN RETURN NULL; END IF;
    SELECT * INTO STRICT subscription FROM gvai_authority.billing_subscriptions
    WHERE (stripe_account_id, environment, tenant_ref, subscription_id) =
        (projection.stripe_account_id, projection.environment, projection.tenant_ref, projection.subscription_id);
    SELECT * INTO STRICT price FROM gvai_authority.billing_prices
    WHERE (stripe_account_id, environment, price_id) =
        (subscription.stripe_account_id, subscription.environment, subscription.price_id);
    coverage := gvai_authority.billing_coverage(
        subscription.stripe_account_id, subscription.environment, subscription.tenant_ref,
        subscription.subscription_id, projection.coverage_start
    );
    IF subscription.terminal_canceled OR subscription.uncertain OR NOT subscription.admitted
        OR subscription.status <> 'active' OR NOT price.approved
        OR projection.revision <> subscription.revision
        OR projection.cancel_at IS DISTINCT FROM subscription.cancel_at
        OR projection.fresh_until IS DISTINCT FROM
            subscription.observed_at + make_interval(secs => price.max_evidence_age_seconds)
        OR coverage IS NULL OR projection.coverage_start < lower(coverage)
        OR projection.coverage_end > upper(coverage)
        OR NOT EXISTS (
            SELECT 1 FROM gvai_authority.billing_reconciliations AS evidence
            WHERE (evidence.stripe_account_id, evidence.environment, evidence.tenant_ref,
                   evidence.subscription_id, evidence.revision) =
                  (projection.stripe_account_id, projection.environment, projection.tenant_ref,
                   projection.subscription_id, projection.revision)
              AND evidence.certain AND evidence.outcome = 'applied'
        )
    THEN
        RAISE EXCEPTION 'billing entitlement lacks consistent payment evidence';
    END IF;
    RETURN NULL;
END;
$function$;

CREATE CONSTRAINT TRIGGER billing_entitlement_consistency AFTER INSERT OR UPDATE ON gvai_authority.billing_entitlements
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_projection_guard();
CREATE CONSTRAINT TRIGGER billing_subscription_projection_consistency AFTER INSERT OR UPDATE ON gvai_authority.billing_subscriptions
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gvai_authority.billing_projection_guard();

CREATE FUNCTION gvai_authority.enqueue_billing_event_v1(
    p_account text, p_environment text, p_event text, p_type text, p_version text,
    p_subscription text, p_payload bytea
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    existing gvai_authority.billing_event_inbox%ROWTYPE;
BEGIN
    INSERT INTO gvai_authority.billing_event_inbox
        (stripe_account_id, environment, event_id, event_type, api_version,
         target_subscription_id, payload, payload_digest)
    VALUES (p_account, p_environment, p_event, p_type, p_version,
            p_subscription, p_payload, gvai_authority.digest(p_payload, 'sha256'))
    ON CONFLICT (stripe_account_id, environment, event_id) DO NOTHING;
    IF FOUND THEN RETURN 'accepted'; END IF;
    SELECT * INTO STRICT existing FROM gvai_authority.billing_event_inbox
    WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event
    FOR UPDATE;
    IF (existing.event_type, existing.api_version, existing.target_subscription_id, existing.payload)
        IS NOT DISTINCT FROM (p_type, p_version, p_subscription, p_payload)
    THEN
        RETURN CASE WHEN existing.conflict_detected THEN 'conflict' ELSE 'duplicate' END;
    END IF;
    UPDATE gvai_authority.billing_event_inbox
    SET state = 'quarantined', conflict_detected = true, error_code = 'delivery_conflict',
        lease_expires_at = NULL
    WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event;
    UPDATE gvai_authority.billing_subscriptions SET uncertain = true
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = existing.target_subscription_id;
    UPDATE gvai_authority.billing_entitlements SET eligibility = 'deny', uncertain = true
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = existing.target_subscription_id;
    RETURN 'conflict';
END;
$function$;

CREATE FUNCTION gvai_authority.claim_billing_events_v1(p_limit integer, p_lease_seconds integer)
RETURNS SETOF gvai_authority.billing_event_inbox
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
        OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION 'invalid billing claim bounds';
    END IF;
    RETURN QUERY
    WITH candidates AS (
        SELECT stripe_account_id, environment, event_id
        FROM gvai_authority.billing_event_inbox
        WHERE state IN ('pending', 'retry')
           OR (state = 'processing' AND lease_expires_at <= clock_timestamp())
        ORDER BY received_at, event_id LIMIT p_limit FOR UPDATE SKIP LOCKED
    )
    UPDATE gvai_authority.billing_event_inbox AS inbox
    SET state = 'processing', attempts = inbox.attempts + 1,
        lease_generation = inbox.lease_generation + 1,
        lease_expires_at = date_trunc('second', clock_timestamp()) + make_interval(secs => p_lease_seconds),
        error_code = NULL
    FROM candidates
    WHERE (inbox.stripe_account_id, inbox.environment, inbox.event_id) =
        (candidates.stripe_account_id, candidates.environment, candidates.event_id)
    RETURNING inbox.*;
END;
$function$;

CREATE FUNCTION gvai_authority.begin_billing_reconciliation_v1(
    p_account text, p_environment text, p_subscription text, p_reconciliation text,
    p_event text, p_event_generation bigint, p_lease_seconds integer
)
RETURNS TABLE (generation bigint, next_revision bigint, observed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    inbox gvai_authority.billing_event_inbox%ROWTYPE;
    observation timestamptz;
BEGIN
    IF p_reconciliation IS NULL OR p_reconciliation !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_lease_seconds IS NULL OR p_lease_seconds NOT BETWEEN 1 AND 300
        OR (p_event IS NULL) <> (p_event_generation IS NULL) THEN
        RAISE EXCEPTION 'invalid reconciliation lease input';
    END IF;
    IF p_event IS NOT NULL THEN
        SELECT * INTO STRICT inbox FROM gvai_authority.billing_event_inbox
        WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event
        FOR UPDATE;
        IF inbox.state <> 'processing' OR inbox.conflict_detected
            OR inbox.lease_generation <> p_event_generation
            OR inbox.lease_expires_at <= clock_timestamp()
            OR inbox.target_subscription_id <> p_subscription THEN
            RAISE EXCEPTION 'billing event lease unavailable';
        END IF;
    END IF;
    SELECT * INTO STRICT subscription FROM gvai_authority.billing_subscriptions
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = p_subscription FOR UPDATE;
    IF NOT subscription.admitted OR subscription.terminal_canceled
        OR subscription.lease_expires_at > clock_timestamp()
        OR EXISTS (
            SELECT 1 FROM gvai_authority.billing_reconciliations
            WHERE stripe_account_id = p_account AND environment = p_environment
              AND reconciliation_id = p_reconciliation
        ) THEN
        RAISE EXCEPTION 'billing subscription lease unavailable or reconciliation already committed';
    END IF;
    observation := date_trunc('second', clock_timestamp());
    IF subscription.observed_at > observation THEN
        RAISE EXCEPTION 'billing clock rollback requires reconciliation';
    END IF;
    UPDATE gvai_authority.billing_subscriptions
    SET lease_generation = subscription.lease_generation + 1, lease_id = p_reconciliation,
        lease_started_at = observation,
        lease_expires_at = observation + make_interval(secs => p_lease_seconds),
        lease_source_event_id = p_event, lease_event_generation = p_event_generation
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = p_subscription;
    generation := subscription.lease_generation + 1;
    next_revision := subscription.revision + 1;
    observed_at := observation;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION gvai_authority.apply_billing_reconciliation_v1(
    p_account text, p_environment text, p_tenant bigint, p_customer text,
    p_subscription text, p_price text, p_reconciliation text, p_generation bigint,
    p_event text, p_event_generation bigint, p_status text, p_certain boolean,
    p_cancel_at timestamptz,
    p_invoice text, p_line text, p_invoice_status text, p_currency text, p_amount_paid bigint,
    p_verified boolean, p_period_start timestamptz, p_period_end timestamptz
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    price gvai_authority.billing_prices%ROWTYPE;
    inbox gvai_authority.billing_event_inbox%ROWTYPE;
    prior_invoice gvai_authority.billing_invoices%ROWTYPE;
    prior_interval gvai_authority.billing_paid_intervals%ROWTYPE;
    prior_evidence gvai_authority.billing_reconciliations%ROWTYPE;
    proof bytea;
    coverage tstzrange;
    fresh_until timestamptz;
    certain boolean;
    terminal boolean;
    conflict boolean := false;
    accepted_payment boolean;
    new_revision bigint;
    decision text;
BEGIN
    IF p_status IS NULL OR p_status NOT IN (
            'active', 'incomplete', 'incomplete_expired', 'trialing', 'past_due', 'unpaid', 'paused', 'canceled')
        OR p_certain IS NULL OR p_verified IS NULL
        OR (p_event IS NULL) <> (p_event_generation IS NULL)
        OR (p_cancel_at IS NOT NULL AND NOT gvai_authority.billing_valid_time(p_cancel_at))
        OR (p_invoice IS NULL AND (
            p_line IS NOT NULL OR p_invoice_status IS NOT NULL OR p_currency IS NOT NULL
            OR p_amount_paid IS NOT NULL OR p_verified
            OR p_period_start IS NOT NULL OR p_period_end IS NOT NULL))
        OR (p_invoice IS NOT NULL AND (
            p_invoice !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR p_line IS NULL OR p_line !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR p_invoice_status IS NULL OR p_invoice_status NOT IN ('draft', 'open', 'paid', 'void', 'uncollectible')
            OR p_currency IS DISTINCT FROM 'usd' OR p_amount_paid IS NULL OR p_amount_paid < 0
            OR NOT gvai_authority.billing_valid_time(p_period_start)
            OR NOT gvai_authority.billing_valid_time(p_period_end)
            OR p_period_end <= p_period_start
            OR p_period_end - p_period_start > INTERVAL '31 days'
            OR (p_verified AND (p_invoice_status <> 'paid' OR p_amount_paid <> 9900))))
    THEN
        RAISE EXCEPTION 'invalid normalized billing evidence';
    END IF;
    proof := gvai_authority.digest(convert_to(jsonb_build_array(
        p_account, p_environment, p_tenant, p_customer, p_subscription, p_price,
        p_reconciliation, p_generation, p_event, p_event_generation, p_status, p_certain,
        extract(epoch FROM p_cancel_at), p_invoice, p_line, p_invoice_status, p_currency,
        p_amount_paid, p_verified, extract(epoch FROM p_period_start), extract(epoch FROM p_period_end)
    )::text, 'UTF8'), 'sha256');
    IF p_event IS NOT NULL THEN
        SELECT * INTO STRICT inbox FROM gvai_authority.billing_event_inbox
        WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event
        FOR UPDATE;
    END IF;
    SELECT * INTO STRICT subscription FROM gvai_authority.billing_subscriptions
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = p_subscription FOR UPDATE;
    IF subscription.tenant_ref IS DISTINCT FROM p_tenant
        OR subscription.customer_id IS DISTINCT FROM p_customer
        OR subscription.price_id IS DISTINCT FROM p_price THEN
        RAISE EXCEPTION 'billing evidence association mismatch';
    END IF;
    SELECT * INTO prior_evidence FROM gvai_authority.billing_reconciliations
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND reconciliation_id = p_reconciliation;
    IF FOUND THEN
        IF prior_evidence.evidence_digest = proof AND prior_evidence.subscription_id = p_subscription THEN
            RETURN 'duplicate';
        END IF;
        UPDATE gvai_authority.billing_subscriptions SET uncertain = true
        WHERE stripe_account_id = p_account AND environment = p_environment AND subscription_id = p_subscription;
        UPDATE gvai_authority.billing_entitlements SET eligibility = 'deny', uncertain = true
        WHERE stripe_account_id = p_account AND environment = p_environment AND subscription_id = p_subscription;
        RETURN 'conflict';
    END IF;
    IF p_event IS NOT NULL AND (
        inbox.state <> 'processing' OR inbox.conflict_detected
        OR inbox.lease_generation IS DISTINCT FROM p_event_generation
        OR inbox.lease_expires_at <= clock_timestamp()
        OR inbox.target_subscription_id <> p_subscription
    ) THEN
        RAISE EXCEPTION 'billing event fence lost';
    END IF;
    IF subscription.lease_id IS DISTINCT FROM p_reconciliation
        OR subscription.lease_generation IS DISTINCT FROM p_generation
        OR subscription.lease_source_event_id IS DISTINCT FROM p_event
        OR subscription.lease_event_generation IS DISTINCT FROM p_event_generation
        OR subscription.lease_expires_at IS NULL
        OR subscription.lease_expires_at <= clock_timestamp()
        OR subscription.lease_started_at > clock_timestamp()
        OR NOT subscription.admitted THEN
        RAISE EXCEPTION 'billing reconciliation fence lost';
    END IF;
    IF subscription.terminal_canceled THEN
        RAISE EXCEPTION 'terminal billing subscription cannot be restored';
    END IF;
    SELECT * INTO STRICT price FROM gvai_authority.billing_prices
    WHERE stripe_account_id = p_account AND environment = p_environment AND price_id = p_price
    FOR SHARE;
    fresh_until := subscription.lease_started_at + make_interval(secs => price.max_evidence_age_seconds);
    certain := p_certain AND price.approved AND fresh_until IS NOT NULL
        AND fresh_until > clock_timestamp() AND (p_invoice IS NULL OR p_verified);
    terminal := p_certain AND p_status = 'canceled';
    accepted_payment := certain AND NOT terminal AND p_invoice IS NOT NULL;
    IF p_event IS NOT NULL AND (
        (p_invoice IS NOT NULL AND inbox.event_type <> 'invoice.paid')
        OR (inbox.event_type = 'customer.subscription.deleted' AND p_status <> 'canceled')
    ) THEN
        RAISE EXCEPTION 'billing event does not match normalized evidence';
    END IF;
    IF accepted_payment THEN
        SELECT * INTO prior_invoice FROM gvai_authority.billing_invoices
        WHERE stripe_account_id = p_account AND environment = p_environment AND invoice_id = p_invoice;
        IF FOUND AND (
            prior_invoice.tenant_ref <> p_tenant OR prior_invoice.subscription_id <> p_subscription
            OR (prior_invoice.verified AND
                (prior_invoice.status, prior_invoice.currency, prior_invoice.amount_paid)
                IS DISTINCT FROM (p_invoice_status, p_currency, p_amount_paid))
        ) THEN conflict := true; END IF;
        SELECT * INTO prior_interval FROM gvai_authority.billing_paid_intervals
        WHERE stripe_account_id = p_account AND environment = p_environment AND invoice_id = p_invoice;
        IF FOUND AND (
            prior_interval.tenant_ref, prior_interval.subscription_id, prior_interval.price_id,
            prior_interval.invoice_line_id, prior_interval.period_start, prior_interval.period_end
        ) IS DISTINCT FROM (p_tenant, p_subscription, p_price, p_line, p_period_start, p_period_end)
        THEN conflict := true; END IF;
    END IF;
    certain := certain AND NOT conflict;
    accepted_payment := accepted_payment AND NOT conflict;
    new_revision := subscription.revision + 1;
    decision := CASE WHEN conflict THEN 'conflict' WHEN terminal THEN 'terminal'
        WHEN certain THEN 'applied' ELSE 'uncertain' END;
    INSERT INTO gvai_authority.billing_reconciliations
        (stripe_account_id, environment, tenant_ref, subscription_id, revision,
         reconciliation_id, source_event_id, observed_at, lease_generation, evidence_digest, certain, outcome)
    VALUES (p_account, p_environment, p_tenant, p_subscription, new_revision,
        p_reconciliation, p_event, subscription.lease_started_at, p_generation, proof, certain, decision);
    IF accepted_payment THEN
        INSERT INTO gvai_authority.billing_invoices
            (stripe_account_id, environment, tenant_ref, subscription_id, invoice_id,
             status, currency, amount_paid, verified, revision)
        VALUES (p_account, p_environment, p_tenant, p_subscription, p_invoice,
            p_invoice_status, p_currency, p_amount_paid, true, new_revision)
        ON CONFLICT (stripe_account_id, environment, invoice_id) DO NOTHING;
        IF prior_invoice.invoice_id IS NOT NULL AND NOT prior_invoice.verified THEN
            UPDATE gvai_authority.billing_invoices SET status = p_invoice_status,
                currency = p_currency, amount_paid = p_amount_paid, verified = true, revision = new_revision
            WHERE stripe_account_id = p_account AND environment = p_environment AND invoice_id = p_invoice;
        END IF;
        INSERT INTO gvai_authority.billing_paid_intervals
            (stripe_account_id, environment, tenant_ref, subscription_id, invoice_id,
             invoice_line_id, price_id, period_start, period_end, revision)
        VALUES (p_account, p_environment, p_tenant, p_subscription, p_invoice,
            p_line, p_price, p_period_start, p_period_end, new_revision)
        ON CONFLICT (stripe_account_id, environment, invoice_id, invoice_line_id) DO NOTHING;
    END IF;
    UPDATE gvai_authority.billing_subscriptions
    SET status = p_status,
        cancel_at = CASE WHEN certain OR terminal THEN p_cancel_at ELSE subscription.cancel_at END,
        terminal_canceled = terminal,
        revision = new_revision, uncertain = NOT certain, observed_at = subscription.lease_started_at,
        lease_id = NULL, lease_started_at = NULL, lease_expires_at = NULL,
        lease_source_event_id = NULL, lease_event_generation = NULL
    WHERE stripe_account_id = p_account AND environment = p_environment AND subscription_id = p_subscription;
    coverage := gvai_authority.billing_coverage(
        p_account, p_environment, p_tenant, p_subscription, date_trunc('second', clock_timestamp())
    );
    INSERT INTO gvai_authority.billing_entitlements
        (stripe_account_id, environment, tenant_ref, subscription_id, revision,
         eligibility, uncertain, coverage_start, coverage_end, fresh_until, cancel_at)
    VALUES (p_account, p_environment, p_tenant, p_subscription, new_revision,
        CASE WHEN certain AND NOT terminal AND p_status = 'active' AND coverage IS NOT NULL
            AND (p_cancel_at IS NULL OR p_cancel_at > clock_timestamp()) THEN 'eligible' ELSE 'deny' END,
        NOT certain, lower(coverage), upper(coverage), fresh_until,
        CASE WHEN certain OR terminal THEN p_cancel_at ELSE subscription.cancel_at END)
    ON CONFLICT (stripe_account_id, environment, tenant_ref, subscription_id) DO UPDATE
        SET revision = EXCLUDED.revision, eligibility = EXCLUDED.eligibility,
            uncertain = EXCLUDED.uncertain, coverage_start = EXCLUDED.coverage_start,
            coverage_end = EXCLUDED.coverage_end, fresh_until = EXCLUDED.fresh_until,
            cancel_at = EXCLUDED.cancel_at;
    IF p_event IS NOT NULL THEN
        UPDATE gvai_authority.billing_event_inbox
        SET state = CASE WHEN conflict THEN 'quarantined' ELSE 'processed' END,
            error_code = CASE WHEN conflict THEN 'evidence_conflict' ELSE NULL END,
            lease_expires_at = NULL
        WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event;
    END IF;
    IF subscription.lease_expires_at <= clock_timestamp()
        OR (p_event IS NOT NULL AND inbox.lease_expires_at <= clock_timestamp()) THEN
        RAISE EXCEPTION 'billing lease expired during apply';
    END IF;
    RETURN decision;
END;
$function$;

CREATE FUNCTION gvai_authority.retry_billing_event_v1(
    p_account text, p_environment text, p_event text, p_generation bigint,
    p_error text, p_quarantine boolean
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    inbox gvai_authority.billing_event_inbox%ROWTYPE;
BEGIN
    IF p_error IS NULL OR p_error NOT IN ('association_unresolved', 'verification_failed', 'transient_failure')
        OR p_quarantine IS NULL THEN RAISE EXCEPTION 'invalid billing retry input'; END IF;
    SELECT * INTO STRICT inbox FROM gvai_authority.billing_event_inbox
    WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event
    FOR UPDATE;
    IF inbox.state <> 'processing' OR inbox.conflict_detected
        OR inbox.lease_generation IS DISTINCT FROM p_generation
        OR inbox.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'billing retry fence lost';
    END IF;
    UPDATE gvai_authority.billing_subscriptions SET uncertain = true,
        lease_id = NULL, lease_started_at = NULL, lease_expires_at = NULL,
        lease_source_event_id = NULL, lease_event_generation = NULL
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = inbox.target_subscription_id;
    UPDATE gvai_authority.billing_entitlements SET eligibility = 'deny', uncertain = true
    WHERE stripe_account_id = p_account AND environment = p_environment
      AND subscription_id = inbox.target_subscription_id;
    UPDATE gvai_authority.billing_event_inbox
    SET state = CASE WHEN p_quarantine THEN 'quarantined' ELSE 'retry' END,
        error_code = p_error, lease_expires_at = NULL
    WHERE stripe_account_id = p_account AND environment = p_environment AND event_id = p_event;
    RETURN CASE WHEN p_quarantine THEN 'quarantined' ELSE 'retry' END;
END;
$function$;

CREATE FUNCTION gvai_authority.billing_authorized_subscription(p_tenant bigint, p_key_id text)
RETURNS gvai_authority.billing_subscriptions
LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    projection gvai_authority.billing_entitlements%ROWTYPE;
    price gvai_authority.billing_prices%ROWTYPE;
    checked_at timestamptz;
BEGIN
    IF (SELECT count(*) FROM gvai_authority.billing_subscriptions
        WHERE tenant_ref = p_tenant AND admitted) <> 1
        OR EXISTS (SELECT 1 FROM gvai_authority.advisory_pilots WHERE tenant_ref = p_tenant) THEN
        RAISE EXCEPTION 'paid admission unavailable' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO STRICT subscription FROM gvai_authority.billing_subscriptions
    WHERE tenant_ref = p_tenant AND admitted FOR UPDATE;
    SELECT * INTO STRICT price FROM gvai_authority.billing_prices
    WHERE (stripe_account_id, environment, price_id) =
        (subscription.stripe_account_id, subscription.environment, subscription.price_id) FOR SHARE;
    SELECT * INTO STRICT projection FROM gvai_authority.billing_entitlements
    WHERE (stripe_account_id, environment, tenant_ref, subscription_id) =
        (subscription.stripe_account_id, subscription.environment, p_tenant, subscription.subscription_id)
    FOR UPDATE;
    checked_at := clock_timestamp();
    IF NOT EXISTS (
        SELECT 1 FROM gvai_authority.customer_credentials
        WHERE key_id = p_key_id AND tenant_ref = p_tenant
          AND status = 'active' AND revoked_at IS NULL
          AND created_at <= checked_at AND expires_at > checked_at
    ) OR subscription.terminal_canceled OR subscription.uncertain OR subscription.status <> 'active'
        OR NOT price.approved OR projection.eligibility <> 'eligible' OR projection.uncertain
        OR projection.revision <> subscription.revision
        OR subscription.observed_at IS NULL OR subscription.observed_at > checked_at
        OR projection.fresh_until IS NULL OR projection.fresh_until <= checked_at
        OR projection.fresh_until IS DISTINCT FROM
            subscription.observed_at + make_interval(secs => price.max_evidence_age_seconds)
        OR projection.coverage_start IS NULL OR projection.coverage_start > checked_at
        OR projection.coverage_end IS NULL OR projection.coverage_end <= checked_at
        OR projection.cancel_at IS DISTINCT FROM subscription.cancel_at
        OR (subscription.cancel_at IS NOT NULL AND subscription.cancel_at <= checked_at)
        OR gvai_authority.billing_coverage(
            subscription.stripe_account_id, subscription.environment, p_tenant,
            subscription.subscription_id, checked_at
        ) IS NULL THEN
        RAISE EXCEPTION 'paid entitlement unavailable' USING ERRCODE = '42501';
    END IF;
    RETURN subscription;
END;
$function$;

CREATE FUNCTION gvai_authority.reserve_subscription_advisory_v1(
    p_key_id text, p_credential_verifier bytea,
    p_expected_authority_id text, p_expected_epoch bigint, p_expected_trust_domain text,
    p_request_id text, p_resource_id text, p_payload_digest text
)
RETURNS TABLE (
    outcome text, authority_id text, authority_epoch bigint, trust_domain text,
    sequence bigint, event_id text, previous_event_hash text, event_hash text,
    tenant_digest text, principal_digest text, resource_digest text,
    request_id_digest text, request_digest text, period_start date,
    policy_version text, units smallint, contract_version smallint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    result record;
BEGIN
    customer := gvai_authority.advisory_customer_v1(
        p_key_id, p_credential_verifier, p_resource_id, 'evaluation:run'
    );
    IF customer IS NULL THEN
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    subscription := gvai_authority.billing_authorized_subscription(customer, p_key_id);
    SELECT * INTO STRICT result FROM gvai_authority.reserve_v1(
        p_key_id, p_credential_verifier,
        p_expected_authority_id, p_expected_epoch, p_expected_trust_domain,
        p_request_id, p_resource_id, p_payload_digest
    );
    IF result.outcome IN ('reserved', 'replay') THEN
        IF gvai_authority.advisory_customer_v1(
            p_key_id, p_credential_verifier, p_resource_id, 'evaluation:run'
        ) IS DISTINCT FROM customer THEN
            RAISE EXCEPTION 'paid credential expired during reservation' USING ERRCODE = '42501';
        END IF;
        subscription := gvai_authority.billing_authorized_subscription(customer, p_key_id);
    END IF;
    IF result.outcome = 'reserved' THEN
        INSERT INTO gvai_authority.billing_advisory_attempts
            (event_id, stripe_account_id, environment, tenant_ref, subscription_id, revision, state)
        VALUES (result.event_id, subscription.stripe_account_id, subscription.environment,
            customer, subscription.subscription_id, subscription.revision, 'reserved');
    ELSIF result.outcome = 'replay' AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_advisory_attempts AS attempt
        WHERE attempt.event_id = result.event_id AND attempt.tenant_ref = customer
          AND attempt.subscription_id = subscription.subscription_id
          AND attempt.stripe_account_id = subscription.stripe_account_id
          AND attempt.environment = subscription.environment
    ) THEN
        RAISE EXCEPTION 'reservation lacks matching paid attempt evidence';
    END IF;
    RETURN QUERY SELECT result.outcome, result.authority_id, result.authority_epoch,
        result.trust_domain, result.sequence, result.event_id, result.previous_event_hash,
        result.event_hash, result.tenant_digest, result.principal_digest, result.resource_digest,
        result.request_id_digest, result.request_digest, result.period_start,
        result.policy_version, result.units, result.contract_version;
END;
$function$;

CREATE FUNCTION gvai_authority.complete_subscription_advisory_v1(
    p_key_id text, p_verifier bytea, p_resource_id text, p_request_id text, p_succeeded boolean
)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    attempt gvai_authority.billing_advisory_attempts%ROWTYPE;
    target text;
BEGIN
    IF p_request_id IS NULL OR p_request_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_succeeded IS NULL THEN RAISE EXCEPTION 'invalid paid completion input'; END IF;
    customer := gvai_authority.advisory_customer_v1(p_key_id, p_verifier, p_resource_id, 'evaluation:run');
    IF customer IS NULL THEN RETURN 'unauthorized'; END IF;
    subscription := gvai_authority.billing_authorized_subscription(customer, p_key_id);
    SELECT paid.* INTO attempt FROM gvai_authority.billing_advisory_attempts AS paid
    JOIN gvai_authority.reservation_idempotency AS idem ON idem.event_id = paid.event_id
    WHERE idem.tenant_ref = customer
      AND idem.request_id_digest = encode(gvai_authority.digest(convert_to(p_request_id, 'UTF8'), 'sha256'), 'hex')
      AND idem.resource_digest = encode(gvai_authority.digest(convert_to(p_resource_id, 'UTF8'), 'sha256'), 'hex')
      AND paid.tenant_ref = customer AND paid.subscription_id = subscription.subscription_id
      AND paid.stripe_account_id = subscription.stripe_account_id
      AND paid.environment = subscription.environment FOR UPDATE OF paid;
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    IF gvai_authority.advisory_customer_v1(
        p_key_id, p_verifier, p_resource_id, 'evaluation:run'
    ) IS DISTINCT FROM customer THEN
        RAISE EXCEPTION 'paid completion credential expired' USING ERRCODE = '42501';
    END IF;
    PERFORM gvai_authority.billing_authorized_subscription(customer, p_key_id);
    target := CASE WHEN p_succeeded THEN 'completed' ELSE 'failed' END;
    IF attempt.state = target THEN RETURN 'replay'; END IF;
    IF attempt.state <> 'reserved' THEN RETURN 'conflict'; END IF;
    UPDATE gvai_authority.billing_advisory_attempts SET state = target WHERE event_id = attempt.event_id;
    RETURN target;
END;
$function$;

CREATE FUNCTION gvai_authority.subscription_advisory_usage_v1(
    p_key_id text, p_verifier bytea, p_resource_id text
)
RETURNS TABLE (allowance bigint, consumed bigint, reserved bigint, completed bigint, failed bigint)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    subscription gvai_authority.billing_subscriptions%ROWTYPE;
    bucket gvai_authority.monthly_usage_buckets%ROWTYPE;
    period date;
    policy_allowance bigint;
BEGIN
    customer := gvai_authority.advisory_customer_v1(p_key_id, p_verifier, p_resource_id, 'usage:read');
    IF customer IS NULL THEN RETURN; END IF;
    subscription := gvai_authority.billing_authorized_subscription(customer, p_key_id);
    SELECT policy.monthly_allowance INTO STRICT policy_allowance
    FROM gvai_authority.current_quota_policies AS current_policy
    JOIN gvai_authority.quota_policies AS policy
      ON (policy.tenant_ref, policy.policy_version) = (current_policy.tenant_ref, current_policy.policy_version)
    WHERE current_policy.tenant_ref = customer FOR SHARE OF current_policy, policy;
    period := date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date;
    SELECT * INTO bucket FROM gvai_authority.monthly_usage_buckets
    WHERE tenant_ref = customer AND period_start = period FOR SHARE;
    IF gvai_authority.advisory_customer_v1(
        p_key_id, p_verifier, p_resource_id, 'usage:read'
    ) IS DISTINCT FROM customer THEN
        RAISE EXCEPTION 'paid usage credential expired' USING ERRCODE = '42501';
    END IF;
    PERFORM gvai_authority.billing_authorized_subscription(customer, p_key_id);
    IF period <> date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC')::date THEN
        RAISE EXCEPTION 'paid usage month changed during authorization';
    END IF;
    RETURN QUERY SELECT coalesce(bucket.allowance, policy_allowance), coalesce(bucket.consumed, 0),
        count(*) FILTER (WHERE paid.state = 'reserved'),
        count(*) FILTER (WHERE paid.state = 'completed'),
        count(*) FILTER (WHERE paid.state = 'failed')
    FROM gvai_authority.billing_advisory_attempts AS paid
    JOIN gvai_authority.reservation_events AS event ON event.event_id = paid.event_id
    WHERE event.tenant_ref = customer AND event.period_start = period;
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.billing_prices FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_customers FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_subscriptions FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_invoices FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_paid_intervals FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_event_inbox FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_reconciliations FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_entitlements FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_advisory_attempts FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_installation FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_valid_time(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_append_only() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_subscription_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_customer_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_price_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_invoice_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_event_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_coverage(text,text,bigint,text,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_projection_guard() FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.enqueue_billing_event_v1(text,text,text,text,text,text,bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.claim_billing_events_v1(integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.begin_billing_reconciliation_v1(text,text,text,text,text,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.apply_billing_reconciliation_v1(text,text,bigint,text,text,text,text,bigint,text,bigint,text,boolean,timestamptz,text,text,text,text,bigint,boolean,timestamptz,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.retry_billing_event_v1(text,text,text,bigint,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.billing_authorized_subscription(bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.reserve_subscription_advisory_v1(text,bytea,text,bigint,text,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.complete_subscription_advisory_v1(text,bytea,text,text,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.subscription_advisory_usage_v1(text,bytea,text) FROM PUBLIC;

INSERT INTO gvai_authority.billing_installation (migration_id, contract_version)
VALUES ('004_subscription_billing_v1', 1);

COMMIT;
