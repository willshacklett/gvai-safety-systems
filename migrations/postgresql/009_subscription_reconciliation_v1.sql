BEGIN;

-- Subscription entitlement reconciliation (Stripe TEST mode, advisory-only).
--
-- Authority model: the only way billing_customers.eligible / verified_until /
-- access_until can become positive is reconcile_apply_v1, which requires a
-- single-use, server-issued fetch ticket and a Stripe-clock observation that is
-- strictly newer than every webhook event and applied snapshot already seen for
-- the tenant. No function here touches credentials, accounts or the usage ledger.

DO $guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS n
        JOIN pg_catalog.pg_roles AS r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user
          AND NOT r.rolsuper AND NOT r.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'reconciliation requires the non-superuser authority owner';
    END IF;
    IF pg_catalog.to_regclass('gvai_authority.customer_accounts') IS NULL
        OR pg_catalog.to_regclass('gvai_authority.billing_customers') IS NULL
        OR pg_catalog.to_regclass('gvai_authority.billing_reconcile_state') IS NOT NULL THEN
        RAISE EXCEPTION 'reconciliation requires baseline 001-004, 007, 008 and no prior install';
    END IF;
END;
$guard$;

ALTER TABLE gvai_authority.billing_customers
    ADD COLUMN subscription_terminal_at timestamptz,
    ADD COLUMN checkout_generation integer NOT NULL DEFAULT 0 CHECK (checkout_generation >= 0),
    ADD COLUMN repin_allowed boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT billing_repin_requires_terminal
        CHECK (NOT repin_allowed OR subscription_terminal_at IS NOT NULL);

-- Immutable subscription history so a terminal customer can resubscribe without
-- orphaning (or rewriting) the paid periods of earlier subscriptions.
CREATE TABLE gvai_authority.billing_subscription_history (
    subscription_id text PRIMARY KEY CHECK (subscription_id ~ '^sub_[A-Za-z0-9_]{1,124}$'),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers (tenant_ref),
    first_seen_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_ref, subscription_id)
);
INSERT INTO gvai_authority.billing_subscription_history (subscription_id, tenant_ref)
SELECT subscription_id, tenant_ref FROM gvai_authority.billing_customers
WHERE subscription_id IS NOT NULL
UNION
SELECT subscription_id, tenant_ref FROM gvai_authority.billing_periods;

DO $repoint$
DECLARE
    old_name text;
BEGIN
    SELECT c.conname INTO STRICT old_name
    FROM pg_catalog.pg_constraint AS c
    WHERE c.conrelid = 'gvai_authority.billing_periods'::regclass AND c.contype = 'f'
      AND c.confrelid = 'gvai_authority.billing_customers'::regclass
      AND c.conkey = ARRAY(
          SELECT a.attnum FROM pg_catalog.pg_attribute AS a
          WHERE a.attrelid = c.conrelid AND a.attname IN ('tenant_ref', 'subscription_id')
          ORDER BY array_position(ARRAY['tenant_ref', 'subscription_id'], a.attname::text))
      AND EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a2 WHERE a2.attrelid = c.confrelid
          AND a2.attnum = c.confkey[2] AND a2.attname = 'subscription_id');
    EXECUTE format('ALTER TABLE gvai_authority.billing_periods DROP CONSTRAINT %I', old_name);
END;
$repoint$;
ALTER TABLE gvai_authority.billing_periods
    ADD CONSTRAINT billing_periods_subscription_history_fk
    FOREIGN KEY (tenant_ref, subscription_id)
    REFERENCES gvai_authority.billing_subscription_history (tenant_ref, subscription_id)
    DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION gvai_authority.billing_subscription_history_guard_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        RAISE EXCEPTION 'subscription history is immutable';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER billing_subscription_history_guard BEFORE UPDATE OR DELETE
    ON gvai_authority.billing_subscription_history FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.billing_subscription_history_guard_v1();

CREATE FUNCTION gvai_authority.billing_subscription_record_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF NEW.subscription_id IS NOT NULL THEN
        INSERT INTO gvai_authority.billing_subscription_history (subscription_id, tenant_ref)
        VALUES (NEW.subscription_id, NEW.tenant_ref) ON CONFLICT DO NOTHING;
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER billing_subscription_record AFTER INSERT OR UPDATE OF subscription_id
    ON gvai_authority.billing_customers FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.billing_subscription_record_v1();

-- Reconciliation schedule and ordering state. Owner-only; never exposed to a runtime role.
CREATE TABLE gvai_authority.billing_reconcile_state (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.billing_customers (tenant_ref),
    phase text NOT NULL DEFAULT 'dormant'
        CHECK (phase IN ('dormant', 'awaiting', 'active', 'terminal', 'needs_operator')),
    next_due_at timestamptz NOT NULL DEFAULT 'infinity',
    claim_ticket bigint,
    claim_until timestamptz NOT NULL DEFAULT '-infinity',
    -- Stripe-clock seconds. A paid snapshot must have been observed strictly after this.
    stripe_floor bigint NOT NULL DEFAULT 0 CHECK (stripe_floor >= 0),
    applied_min bigint NOT NULL DEFAULT 0 CHECK (applied_min >= 0),
    consecutive_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_failures >= 0),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_outcome text NOT NULL DEFAULT 'never' CHECK (last_outcome ~ '^[a-z0-9_]{1,64}$')
);
CREATE INDEX billing_reconcile_due_idx
    ON gvai_authority.billing_reconcile_state (next_due_at, tenant_ref)
    WHERE phase IN ('awaiting', 'active', 'terminal');

CREATE TABLE gvai_authority.billing_reconcile_tickets (
    ticket_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers (tenant_ref),
    started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > started_at),
    claimed boolean NOT NULL,
    event_id text CHECK (event_id ~ '^evt_[A-Za-z0-9_]{1,124}$'),
    event_created bigint,
    payload_hash text CHECK (payload_hash ~ '^[0-9a-f]{64}$'),
    CHECK ((event_id IS NULL) = (event_created IS NULL) AND (event_id IS NULL) = (payload_hash IS NULL))
);
CREATE INDEX billing_reconcile_tickets_expiry_idx
    ON gvai_authority.billing_reconcile_tickets (expires_at);

CREATE FUNCTION gvai_authority.billing_reconcile_phase_v1(
    p_revoked boolean, p_subscription text, p_terminal timestamptz, p_checkout timestamptz,
    p_repin boolean
)
RETURNS text LANGUAGE sql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
    SELECT CASE
        WHEN p_revoked THEN 'terminal'
        WHEN p_subscription IS NOT NULL AND p_terminal IS NULL THEN 'active'
        WHEN p_checkout IS NOT NULL AND p_checkout > pg_catalog.clock_timestamp() - interval '23 hours'
            AND (p_subscription IS NULL OR p_repin) THEN 'awaiting'
        WHEN p_terminal IS NOT NULL THEN 'terminal'
        ELSE 'dormant'
    END
$function$;

CREATE FUNCTION gvai_authority.billing_reconcile_seed_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    INSERT INTO gvai_authority.billing_reconcile_state (tenant_ref, phase, next_due_at)
    VALUES (NEW.tenant_ref, 'dormant', 'infinity') ON CONFLICT DO NOTHING;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER billing_reconcile_seed AFTER INSERT
    ON gvai_authority.billing_customers FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.billing_reconcile_seed_v1();

INSERT INTO gvai_authority.billing_reconcile_state (tenant_ref, phase, next_due_at)
SELECT b.tenant_ref, p.phase, CASE WHEN p.phase = 'dormant' THEN 'infinity'::timestamptz
                                   ELSE pg_catalog.clock_timestamp() END
FROM gvai_authority.billing_customers AS b
CROSS JOIN LATERAL (SELECT gvai_authority.billing_reconcile_phase_v1(
    b.revoked, b.subscription_id, b.subscription_terminal_at, b.checkout_started_at, b.repin_allowed) AS phase) AS p;

-- Starting a Checkout wakes a dormant or terminal tenant so a paid-but-undelivered
-- webhook is still found by polling, without polling every account forever.
CREATE FUNCTION gvai_authority.billing_reconcile_wake_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    UPDATE gvai_authority.billing_reconcile_state
    SET phase = 'awaiting', next_due_at = pg_catalog.clock_timestamp() + interval '5 seconds'
    WHERE tenant_ref = NEW.tenant_ref AND phase IN ('dormant', 'terminal') AND NOT NEW.revoked;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER billing_reconcile_wake AFTER UPDATE OF checkout_started_at
    ON gvai_authority.billing_customers FOR EACH ROW
    WHEN (OLD.checkout_started_at IS NULL AND NEW.checkout_started_at IS NOT NULL)
    EXECUTE FUNCTION gvai_authority.billing_reconcile_wake_v1();

-- Extends the paid-history guard: pinned subscription and checkout identity stay immutable
-- except through the two explicit resubscription transitions of a terminal subscription.
CREATE OR REPLACE FUNCTION gvai_authority.paid_history_guard_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    resubscribe_reset boolean;
    repin boolean;
BEGIN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'paid history is immutable'; END IF;
    IF TG_TABLE_NAME='billing_customers' THEN
        resubscribe_reset := OLD.subscription_terminal_at IS NOT NULL AND NOT OLD.repin_allowed
            AND OLD.subscription_id IS NOT NULL AND NEW.repin_allowed AND NOT NEW.eligible
            AND NEW.checkout_generation = OLD.checkout_generation + 1
            AND NEW.checkout_started_at IS NULL AND NEW.checkout_session_id IS NULL
            AND NEW.checkout_url IS NULL
            AND NEW.subscription_id IS NOT DISTINCT FROM OLD.subscription_id
            AND NEW.subscription_terminal_at IS NOT DISTINCT FROM OLD.subscription_terminal_at;
        repin := OLD.repin_allowed AND OLD.subscription_terminal_at IS NOT NULL
            AND NOT NEW.repin_allowed AND NEW.subscription_id IS NOT NULL
            AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
            AND NEW.checkout_generation = OLD.checkout_generation
            AND NEW.checkout_started_at IS NOT DISTINCT FROM OLD.checkout_started_at
            AND NEW.checkout_session_id IS NOT DISTINCT FROM OLD.checkout_session_id;
        IF NEW.tenant_ref<>OLD.tenant_ref OR NEW.customer_id<>OLD.customer_id
            OR (OLD.revoked AND NOT NEW.revoked)
            OR NEW.checkout_generation < OLD.checkout_generation
            OR (OLD.subscription_id IS NOT NULL AND NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
                AND NOT repin)
            OR (OLD.checkout_started_at IS NOT NULL AND NEW.checkout_started_at IS DISTINCT FROM OLD.checkout_started_at
                AND NOT resubscribe_reset)
            OR (NEW.checkout_generation <> OLD.checkout_generation AND NOT resubscribe_reset)
            OR (NEW.repin_allowed IS DISTINCT FROM OLD.repin_allowed AND NOT (resubscribe_reset OR repin))
            OR (OLD.subscription_terminal_at IS NOT NULL
                AND NEW.subscription_terminal_at IS DISTINCT FROM OLD.subscription_terminal_at
                AND NOT repin) THEN
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

-- Claims due tenants oldest-due-first (starvation-free) with SKIP LOCKED so several
-- reconciler instances never fetch the same tenant at once.
CREATE FUNCTION gvai_authority.reconcile_claim_due_v1(p_limit integer, p_claim_seconds integer)
RETURNS TABLE (
    o_customer text, o_subscription text, o_repin boolean, o_ticket bigint,
    o_started timestamptz, o_phase text, o_lag double precision
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_until timestamptz;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100
        OR p_claim_seconds IS NULL OR p_claim_seconds NOT BETWEEN 10 AND 55 THEN
        RAISE EXCEPTION 'reconcile claim bounds rejected';
    END IF;
    v_until := v_now + pg_catalog.make_interval(secs => p_claim_seconds);
    DELETE FROM gvai_authority.billing_reconcile_tickets WHERE expires_at < v_now - interval '5 minutes';
    RETURN QUERY
    WITH due AS (
        SELECT s.tenant_ref, s.next_due_at
        FROM gvai_authority.billing_reconcile_state AS s
        JOIN gvai_authority.billing_customers AS b ON b.tenant_ref = s.tenant_ref
        WHERE s.phase IN ('awaiting', 'active', 'terminal') AND NOT b.revoked
          AND s.next_due_at <= v_now AND s.claim_until <= v_now
        ORDER BY s.next_due_at, s.tenant_ref
        LIMIT p_limit FOR UPDATE OF s SKIP LOCKED
    ), issued AS (
        INSERT INTO gvai_authority.billing_reconcile_tickets (tenant_ref, started_at, expires_at, claimed)
        SELECT due.tenant_ref, v_now, v_until, true FROM due
        RETURNING ticket_id, tenant_ref
    ), marked AS (
        UPDATE gvai_authority.billing_reconcile_state AS s
        SET claim_ticket = issued.ticket_id, claim_until = v_until, last_attempt_at = v_now
        FROM issued WHERE s.tenant_ref = issued.tenant_ref
        RETURNING s.tenant_ref, s.phase
    )
    SELECT b.customer_id, b.subscription_id, b.repin_allowed, issued.ticket_id, v_now, marked.phase,
           extract(epoch FROM (v_now - due.next_due_at))::double precision
    FROM issued
    JOIN marked ON marked.tenant_ref = issued.tenant_ref
    JOIN due ON due.tenant_ref = issued.tenant_ref
    JOIN gvai_authority.billing_customers AS b ON b.tenant_ref = issued.tenant_ref
    ORDER BY due.next_due_at, issued.tenant_ref;
END;
$function$;

-- Operator-only single-tenant claim (not granted to the reconciler role).
CREATE FUNCTION gvai_authority.reconcile_claim_one_v1(p_customer text, p_claim_seconds integer)
RETURNS TABLE (
    o_customer text, o_subscription text, o_repin boolean, o_ticket bigint,
    o_started timestamptz, o_phase text, o_lag double precision
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    b gvai_authority.billing_customers%ROWTYPE;
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    v_ticket bigint;
BEGIN
    IF p_claim_seconds IS NULL OR p_claim_seconds NOT BETWEEN 10 AND 55 THEN
        RAISE EXCEPTION 'reconcile claim bounds rejected';
    END IF;
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref = b.tenant_ref FOR UPDATE;
    IF s.claim_until > v_now THEN RETURN; END IF;
    INSERT INTO gvai_authority.billing_reconcile_tickets (tenant_ref, started_at, expires_at, claimed)
    VALUES (b.tenant_ref, v_now, v_now + pg_catalog.make_interval(secs => p_claim_seconds), true)
    RETURNING ticket_id INTO v_ticket;
    UPDATE gvai_authority.billing_reconcile_state
    SET claim_ticket = v_ticket, claim_until = v_now + pg_catalog.make_interval(secs => p_claim_seconds),
        last_attempt_at = v_now
    WHERE tenant_ref = b.tenant_ref;
    RETURN QUERY SELECT b.customer_id, b.subscription_id, b.repin_allowed, v_ticket, v_now, s.phase,
                        0::double precision;
END;
$function$;

-- A verified webhook event only raises the Stripe-time floor, optionally suspends on a
-- fresh denial event, and issues a ticket. It can never grant access.
CREATE FUNCTION gvai_authority.reconcile_signal_v1(
    p_customer text, p_event text, p_hash text, p_created bigint, p_denial boolean
)
RETURNS TABLE (
    o_duplicate boolean, o_subscription text, o_repin boolean, o_ticket bigint, o_started timestamptz
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_epoch bigint := pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint;
    b gvai_authority.billing_customers%ROWTYPE;
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    prior record;
    v_ticket bigint;
BEGIN
    IF p_event IS NULL OR p_event !~ '^evt_[A-Za-z0-9_]{1,124}$'
        OR p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$'
        OR p_created IS NULL OR p_created < 1 OR p_created > v_epoch + 300
        OR p_denial IS NULL THEN
        RAISE EXCEPTION 'reconcile signal rejected';
    END IF;
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref = b.tenant_ref FOR UPDATE;
    SELECT e.tenant_ref, e.payload_hash INTO prior FROM gvai_authority.billing_events AS e WHERE e.event_id = p_event;
    IF FOUND THEN
        IF prior.tenant_ref <> b.tenant_ref OR prior.payload_hash <> p_hash THEN
            RAISE EXCEPTION 'event collision rejected';
        END IF;
        RETURN QUERY SELECT true, b.subscription_id, b.repin_allowed, NULL::bigint, v_now;
        RETURN;
    END IF;
    UPDATE gvai_authority.billing_reconcile_state
    SET stripe_floor = GREATEST(stripe_floor, p_created),
        phase = CASE WHEN phase IN ('dormant', 'terminal') AND NOT b.revoked THEN 'awaiting' ELSE phase END,
        next_due_at = CASE WHEN phase IN ('dormant', 'terminal', 'awaiting', 'active')
                           THEN LEAST(next_due_at, v_now) ELSE next_due_at END
    WHERE tenant_ref = b.tenant_ref;
    -- Only a fresh signed denial suspends immediately; retried old events never do.
    IF p_denial AND p_created >= v_epoch - 300 AND b.eligible THEN
        UPDATE gvai_authority.billing_customers
        SET eligible = false, verified_until = '-infinity' WHERE tenant_ref = b.tenant_ref;
    END IF;
    INSERT INTO gvai_authority.billing_reconcile_tickets
        (tenant_ref, started_at, expires_at, claimed, event_id, event_created, payload_hash)
    VALUES (b.tenant_ref, v_now, v_now + interval '45 seconds', false, p_event, p_created, p_hash)
    RETURNING ticket_id INTO v_ticket;
    RETURN QUERY SELECT false, b.subscription_id, b.repin_allowed, v_ticket, v_now;
END;
$function$;

CREATE FUNCTION gvai_authority.reconcile_apply_v1(
    p_customer text, p_ticket bigint, p_observed_min bigint, p_observed_max bigint,
    p_subscription text, p_invoice text, p_start bigint, p_end bigint,
    p_eligible boolean, p_access_until bigint, p_terminal boolean
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    v_epoch bigint := pg_catalog.floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint;
    b gvai_authority.billing_customers%ROWTYPE;
    b2 gvai_authority.billing_customers%ROWTYPE;
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    t gvai_authority.billing_reconcile_tickets%ROWTYPE;
    prior record;
    period record;
    v_reject text;
    v_positive boolean;
    v_repin boolean := false;
    v_terminal_at timestamptz;
    v_phase text;
    v_observed_min bigint := p_observed_min;
    v_observed_max bigint := p_observed_max;
    v_next timestamptz;
BEGIN
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'unmapped_customer'; END IF;
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref = b.tenant_ref FOR UPDATE;
    DELETE FROM gvai_authority.billing_reconcile_tickets
    WHERE ticket_id = p_ticket AND tenant_ref = b.tenant_ref AND expires_at > v_now
    RETURNING * INTO t;
    IF NOT FOUND THEN RETURN 'ticket_invalid'; END IF;

    IF t.event_id IS NOT NULL THEN
        SELECT e.tenant_ref, e.payload_hash INTO prior FROM gvai_authority.billing_events AS e
        WHERE e.event_id = t.event_id;
        IF FOUND THEN
            IF prior.tenant_ref <> b.tenant_ref OR prior.payload_hash <> t.payload_hash THEN
                v_reject := 'event_collision_rejected';
            ELSE
                RETURN 'duplicate_event';
            END IF;
        END IF;
    END IF;

    v_positive := p_eligible IS TRUE AND NOT b.revoked AND s.phase <> 'needs_operator';

    IF v_reject IS NULL AND (p_eligible IS NULL OR p_terminal IS NULL) THEN
        v_reject := 'snapshot_shape_rejected';
    END IF;
    IF v_reject IS NULL AND p_subscription IS NOT NULL AND p_subscription !~ '^sub_[A-Za-z0-9_]{1,124}$' THEN
        v_reject := 'subscription_id_rejected';
    END IF;
    IF v_reject IS NULL AND (p_observed_min IS NOT NULL OR p_observed_max IS NOT NULL) AND (
        p_observed_min IS NULL OR p_observed_max IS NULL OR p_observed_min < 1
        OR p_observed_min > p_observed_max) THEN
        v_reject := 'observation_rejected';
    END IF;
    IF v_reject IS NULL AND b.subscription_id IS NOT NULL
        AND p_subscription IS DISTINCT FROM b.subscription_id THEN
        IF b.repin_allowed AND b.subscription_terminal_at IS NOT NULL AND p_subscription IS NOT NULL THEN
            v_repin := true;
        ELSE
            v_reject := 'subscription_replacement_rejected';
        END IF;
    END IF;
    IF v_reject IS NULL AND p_terminal AND (p_eligible OR p_subscription IS NULL) THEN
        v_reject := 'terminal_shape_rejected';
    END IF;

    IF v_reject IS NULL AND p_eligible THEN
        IF p_invoice IS NULL OR p_invoice !~ '^in_[A-Za-z0-9_]{1,125}$' OR p_subscription IS NULL
            OR p_start IS NULL OR p_end IS NULL OR p_access_until IS NULL
            OR p_start >= p_end OR p_end - p_start > 32 * 86400
            OR p_access_until > p_end OR p_access_until <= p_start THEN
            v_reject := 'paid_period_rejected';
        ELSIF NOT (p_start <= v_epoch AND v_epoch < p_access_until) THEN
            -- A paid state whose window does not contain the database clock is never granted.
            v_positive := false;
        END IF;
    END IF;
    IF v_reject IS NULL AND b.subscription_terminal_at IS NOT NULL AND NOT v_repin AND NOT p_terminal THEN
        v_reject := 'terminal_subscription_reactivated';
    END IF;

    IF v_reject IS NULL AND v_positive THEN
        IF p_observed_min IS NULL THEN
            RETURN gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, 'observation_missing', true);
        END IF;
        IF p_observed_min < pg_catalog.floor(extract(epoch FROM t.started_at))::bigint - 30
            OR p_observed_max > v_epoch + 30 THEN
            RETURN gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, 'clock_skew', true);
        END IF;
        IF v_now - t.started_at > interval '40 seconds' THEN
            RETURN gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, 'stale_snapshot', false);
        END IF;
        IF p_observed_min <= s.stripe_floor THEN
            IF t.event_id IS NOT NULL AND s.applied_min > t.event_created THEN
                INSERT INTO gvai_authority.billing_events (event_id, tenant_ref, payload_hash)
                VALUES (t.event_id, b.tenant_ref, t.payload_hash);
                PERFORM gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, 'covered_by_newer', false);
                RETURN 'covered_by_newer';
            END IF;
            RETURN gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, 'stale_snapshot', false);
        END IF;
    END IF;

    IF v_reject IS NULL AND v_positive THEN
        SELECT 1 AS found INTO period FROM gvai_authority.billing_periods AS p
        WHERE p.tenant_ref = b.tenant_ref
          AND p.invoice_id <> p_invoice
          AND ((p.subscription_id = p_subscription
                AND p.starts_at < pg_catalog.to_timestamp(p_end) AND p.ends_at > pg_catalog.to_timestamp(p_start))
               OR p.starts_at = pg_catalog.to_timestamp(p_start));
        IF FOUND THEN
            v_reject := 'overlapping_period_rejected';
        END IF;
    END IF;

    IF v_reject IS NOT NULL THEN
        UPDATE gvai_authority.billing_customers
        SET eligible = false, verified_until = '-infinity', access_until = '-infinity'
        WHERE tenant_ref = b.tenant_ref;
        UPDATE gvai_authority.billing_reconcile_state
        SET phase = 'needs_operator', last_outcome = LEFT(v_reject, 64), consecutive_failures = consecutive_failures + 1,
            claim_ticket = CASE WHEN claim_ticket = t.ticket_id THEN NULL ELSE claim_ticket END,
            claim_until = CASE WHEN claim_ticket = t.ticket_id THEN '-infinity' ELSE claim_until END,
            next_due_at = 'infinity'
        WHERE tenant_ref = b.tenant_ref;
        RETURN 'rejected_' || v_reject;
    END IF;

    -- Ordering evidence for a denial-only snapshot that carries no Stripe date is the database clock.
    IF v_observed_min IS NULL THEN
        v_observed_min := v_epoch;
        v_observed_max := v_epoch;
    END IF;

    IF p_subscription IS NOT NULL THEN
        v_terminal_at := CASE WHEN p_terminal THEN COALESCE(
            CASE WHEN v_repin THEN NULL ELSE b.subscription_terminal_at END, v_now) ELSE NULL END;
    ELSE
        v_terminal_at := b.subscription_terminal_at;
    END IF;

    IF v_positive THEN
        INSERT INTO gvai_authority.billing_periods (invoice_id, tenant_ref, subscription_id, starts_at, ends_at)
        VALUES (p_invoice, b.tenant_ref, p_subscription, pg_catalog.to_timestamp(p_start), pg_catalog.to_timestamp(p_end))
        ON CONFLICT (invoice_id) DO NOTHING;
        SELECT p.tenant_ref, p.subscription_id, p.starts_at, p.ends_at, p.allowance INTO period
        FROM gvai_authority.billing_periods AS p WHERE p.invoice_id = p_invoice;
        IF NOT FOUND OR period.tenant_ref <> b.tenant_ref OR period.subscription_id <> p_subscription
            OR period.starts_at <> pg_catalog.to_timestamp(p_start) OR period.ends_at <> pg_catalog.to_timestamp(p_end)
            OR period.allowance <> 100000 THEN
            UPDATE gvai_authority.billing_customers
            SET eligible = false, verified_until = '-infinity', access_until = '-infinity'
            WHERE tenant_ref = b.tenant_ref;
            UPDATE gvai_authority.billing_reconcile_state
            SET phase = 'needs_operator', last_outcome = 'invoice_reassignment_rejected',
                consecutive_failures = consecutive_failures + 1, next_due_at = 'infinity',
                claim_ticket = CASE WHEN claim_ticket = t.ticket_id THEN NULL ELSE claim_ticket END,
                claim_until = CASE WHEN claim_ticket = t.ticket_id THEN '-infinity' ELSE claim_until END
            WHERE tenant_ref = b.tenant_ref;
            RETURN 'rejected_invoice_reassignment_rejected';
        END IF;
        UPDATE gvai_authority.billing_customers
        SET subscription_id = p_subscription,
            subscription_terminal_at = v_terminal_at,
            repin_allowed = CASE WHEN v_repin THEN false ELSE repin_allowed END,
            current_invoice = p_invoice, eligible = true,
            verified_until = GREATEST(verified_until, t.started_at + interval '60 seconds'),
            access_until = pg_catalog.to_timestamp(p_access_until)
        WHERE tenant_ref = b.tenant_ref
        RETURNING * INTO b2;
    ELSE
        UPDATE gvai_authority.billing_customers
        SET subscription_id = COALESCE(p_subscription, subscription_id),
            subscription_terminal_at = v_terminal_at,
            repin_allowed = CASE WHEN v_repin THEN false ELSE repin_allowed END,
            current_invoice = NULL, eligible = false,
            verified_until = '-infinity', access_until = '-infinity'
        WHERE tenant_ref = b.tenant_ref
        RETURNING * INTO b2;
    END IF;

    v_phase := CASE WHEN s.phase = 'needs_operator' THEN 'needs_operator'
        ELSE gvai_authority.billing_reconcile_phase_v1(
            b2.revoked, b2.subscription_id, b2.subscription_terminal_at, b2.checkout_started_at, b2.repin_allowed) END;
    v_next := CASE v_phase
        WHEN 'active' THEN t.started_at + interval '20 seconds'
            + pg_catalog.make_interval(secs => pg_catalog.random() * 2)
        WHEN 'awaiting' THEN t.started_at + interval '60 seconds'
        WHEN 'terminal' THEN v_now + interval '900 seconds'
        ELSE 'infinity'::timestamptz END;

    UPDATE gvai_authority.billing_reconcile_state
    SET phase = v_phase, next_due_at = v_next,
        stripe_floor = GREATEST(stripe_floor, v_observed_max),
        applied_min = GREATEST(applied_min, v_observed_min),
        consecutive_failures = 0, last_success_at = v_now,
        last_outcome = CASE WHEN v_positive THEN 'applied_eligible' ELSE 'applied_denied' END,
        claim_ticket = CASE WHEN claim_ticket = t.ticket_id THEN NULL ELSE claim_ticket END,
        claim_until = CASE WHEN claim_ticket = t.ticket_id THEN '-infinity' ELSE claim_until END
    WHERE tenant_ref = b.tenant_ref;

    IF t.event_id IS NOT NULL THEN
        INSERT INTO gvai_authority.billing_events (event_id, tenant_ref, payload_hash)
        VALUES (t.event_id, b.tenant_ref, t.payload_hash);
    END IF;
    RETURN CASE WHEN v_positive THEN 'applied_eligible' ELSE 'applied_denied' END;
END;
$function$;

-- Internal helper: records a non-applied attempt, releases the claim and schedules a retry.
CREATE FUNCTION gvai_authority.reconcile_release_v1(
    p_tenant bigint, p_ticket bigint, p_now timestamptz, p_outcome text, p_failure boolean
)
RETURNS text
LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    v_failures integer;
BEGIN
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref = p_tenant FOR UPDATE;
    v_failures := CASE WHEN p_failure THEN s.consecutive_failures + 1 ELSE s.consecutive_failures END;
    UPDATE gvai_authority.billing_reconcile_state
    SET last_outcome = p_outcome, consecutive_failures = v_failures,
        next_due_at = CASE WHEN s.claim_ticket = p_ticket THEN
            p_now + CASE WHEN p_failure
                THEN pg_catalog.make_interval(secs => LEAST(60, 5 * pg_catalog.power(2, LEAST(v_failures - 1, 4))))
                ELSE interval '2 seconds' END
            ELSE next_due_at END,
        claim_ticket = CASE WHEN claim_ticket = p_ticket THEN NULL ELSE claim_ticket END,
        claim_until = CASE WHEN claim_ticket = p_ticket THEN '-infinity' ELSE claim_until END
    WHERE tenant_ref = p_tenant;
    RETURN p_outcome;
END;
$function$;

CREATE FUNCTION gvai_authority.reconcile_fail_v1(
    p_customer text, p_ticket bigint, p_class text, p_code text
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
    b gvai_authority.billing_customers%ROWTYPE;
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    t gvai_authority.billing_reconcile_tickets%ROWTYPE;
BEGIN
    IF p_class IS NULL OR p_class NOT IN ('transient', 'integrity')
        OR p_code IS NULL OR p_code !~ '^[a-z0-9_]{1,64}$' THEN
        RAISE EXCEPTION 'reconcile failure rejected';
    END IF;
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'unmapped_customer'; END IF;
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref = b.tenant_ref FOR UPDATE;
    DELETE FROM gvai_authority.billing_reconcile_tickets
    WHERE ticket_id = p_ticket AND tenant_ref = b.tenant_ref AND expires_at > v_now
    RETURNING * INTO t;
    IF NOT FOUND THEN RETURN 'ticket_invalid'; END IF;
    IF p_class = 'transient' THEN
        -- The existing verified lease is deliberately left untouched; it expires on its own.
        RETURN gvai_authority.reconcile_release_v1(b.tenant_ref, t.ticket_id, v_now, p_code, true);
    END IF;
    UPDATE gvai_authority.billing_customers
    SET eligible = false, verified_until = '-infinity', access_until = '-infinity'
    WHERE tenant_ref = b.tenant_ref;
    UPDATE gvai_authority.billing_reconcile_state
    SET phase = 'needs_operator', last_outcome = p_code, consecutive_failures = consecutive_failures + 1,
        next_due_at = 'infinity',
        claim_ticket = CASE WHEN claim_ticket = t.ticket_id THEN NULL ELSE claim_ticket END,
        claim_until = CASE WHEN claim_ticket = t.ticket_id THEN '-infinity' ELSE claim_until END
    WHERE tenant_ref = b.tenant_ref;
    RETURN 'suspended';
END;
$function$;

-- Aggregate, identifier-free health for monitoring.
CREATE FUNCTION gvai_authority.reconcile_status_v1()
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
    RETURN pg_catalog.jsonb_build_object(
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

-- Operator-only transitions.
CREATE FUNCTION gvai_authority.reconcile_resume_v1(p_customer text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    b gvai_authority.billing_customers%ROWTYPE;
BEGIN
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE gvai_authority.billing_reconcile_state
    SET phase = gvai_authority.billing_reconcile_phase_v1(
            b.revoked, b.subscription_id, b.subscription_terminal_at, b.checkout_started_at, b.repin_allowed),
        next_due_at = CASE WHEN b.revoked THEN 'infinity'::timestamptz ELSE pg_catalog.clock_timestamp() END,
        consecutive_failures = 0, last_outcome = 'resumed'
    WHERE tenant_ref = b.tenant_ref AND phase = 'needs_operator';
    RETURN FOUND;
END;
$function$;

CREATE FUNCTION gvai_authority.reconcile_begin_resubscribe_v1(p_customer text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    b gvai_authority.billing_customers%ROWTYPE;
BEGIN
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id = p_customer FOR UPDATE;
    IF NOT FOUND OR b.revoked THEN RAISE EXCEPTION 'resubscription rejected'; END IF;
    IF b.subscription_terminal_at IS NULL OR b.repin_allowed THEN
        RETURN b.checkout_generation;
    END IF;
    UPDATE gvai_authority.billing_customers
    SET checkout_generation = checkout_generation + 1, checkout_started_at = NULL,
        checkout_session_id = NULL, checkout_url = NULL, repin_allowed = true,
        eligible = false, verified_until = '-infinity', access_until = '-infinity', current_invoice = NULL
    WHERE tenant_ref = b.tenant_ref
    RETURNING checkout_generation INTO b.checkout_generation;
    RETURN b.checkout_generation;
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.billing_reconcile_state FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_reconcile_tickets FROM PUBLIC;
REVOKE ALL ON TABLE gvai_authority.billing_subscription_history FROM PUBLIC;
REVOKE ALL ON FUNCTION
    gvai_authority.billing_subscription_history_guard_v1(),
    gvai_authority.billing_subscription_record_v1(),
    gvai_authority.billing_reconcile_phase_v1(boolean, text, timestamptz, timestamptz, boolean),
    gvai_authority.billing_reconcile_seed_v1(),
    gvai_authority.billing_reconcile_wake_v1(),
    gvai_authority.reconcile_claim_due_v1(integer, integer),
    gvai_authority.reconcile_claim_one_v1(text, integer),
    gvai_authority.reconcile_signal_v1(text, text, text, bigint, boolean),
    gvai_authority.reconcile_apply_v1(text, bigint, bigint, bigint, text, text, bigint, bigint, boolean, bigint, boolean),
    gvai_authority.reconcile_release_v1(bigint, bigint, timestamptz, text, boolean),
    gvai_authority.reconcile_fail_v1(text, bigint, text, text),
    gvai_authority.reconcile_status_v1(),
    gvai_authority.reconcile_resume_v1(text),
    gvai_authority.reconcile_begin_resubscribe_v1(text)
FROM PUBLIC;

-- Grants are deliberately not part of the migration. The operator grants EXECUTE on exactly:
--   reconcile_claim_due_v1, reconcile_signal_v1, reconcile_apply_v1,
--   reconcile_fail_v1, reconcile_status_v1
-- to the dedicated reconciler role, and nothing else (see docs/subscription_reconciliation_v1.md).

COMMIT;
