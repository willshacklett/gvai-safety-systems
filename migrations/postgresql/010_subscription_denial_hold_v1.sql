BEGIN;
-- Forward-only denial hold. Existing 009 routines retain their ACLs on replacement.
DO $guard$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user
        AND NOT r.rolsuper AND NOT r.rolbypassrls) THEN
        RAISE EXCEPTION 'requires non-superuser authority owner';
    END IF;
END;
$guard$;
CREATE TABLE gvai_authority.billing_denials (
    event_id text PRIMARY KEY,
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers(tenant_ref),
    payload_hash text NOT NULL,
    event_created bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE gvai_authority.billing_reconcile_state ADD COLUMN denial_event text
    REFERENCES gvai_authority.billing_denials(event_id);
ALTER TABLE gvai_authority.billing_reconcile_state ADD COLUMN denial_held_since timestamptz;
CREATE TABLE gvai_authority.billing_denial_recoveries (
    recovery_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers(tenant_ref),
    denial_event text NOT NULL REFERENCES gvai_authority.billing_denials(event_id),
    payment_event text NOT NULL UNIQUE CHECK(payment_event ~ '^evt_[A-Za-z0-9_]{1,124}$'),
    evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[0-9a-f]{64}$'),
    payment_created bigint NOT NULL,
    subscription_id text NOT NULL,
    invoice_id text NOT NULL,
    operator_name text NOT NULL DEFAULT session_user,
    reason text NOT NULL CHECK(length(reason) BETWEEN 8 AND 500),
    recovered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER billing_denials_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_denials FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
CREATE TRIGGER billing_denial_recoveries_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_denial_recoveries FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();
REVOKE ALL ON gvai_authority.billing_denials, gvai_authority.billing_denial_recoveries FROM PUBLIC;

-- Unmatched transaction evidence is retained without suspending unrelated entitlements.
-- It becomes protective if a later grant attempts to use that exact entitlement.
CREATE TABLE gvai_authority.billing_scoped_denials (
    event_id text PRIMARY KEY,
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.billing_customers(tenant_ref),
    payload_hash text NOT NULL,
    event_created bigint NOT NULL,
    subscription_id text NOT NULL,
    invoice_id text,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON gvai_authority.billing_scoped_denials FROM PUBLIC;
CREATE TRIGGER billing_scoped_denials_immutable BEFORE UPDATE OR DELETE
ON gvai_authority.billing_scoped_denials FOR EACH ROW EXECUTE FUNCTION gvai_authority.paid_history_guard_v1();

CREATE OR REPLACE FUNCTION gvai_authority.reconcile_signal_v1(
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
    SELECT d.tenant_ref, d.payload_hash INTO prior
    FROM gvai_authority.billing_denials d WHERE d.event_id=p_event;
    IF FOUND THEN
        IF prior.tenant_ref <> b.tenant_ref OR prior.payload_hash <> p_hash THEN
            RAISE EXCEPTION 'event collision rejected';
        END IF;
        RETURN QUERY SELECT true, b.subscription_id, b.repin_allowed, NULL::bigint, v_now;
        RETURN;
    END IF;
    SELECT d.tenant_ref, d.payload_hash INTO prior
    FROM gvai_authority.billing_scoped_denials d WHERE d.event_id=p_event;
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
    -- Delivery age is not evidence of recovery. Record all unseen authenticated denials.
    IF p_denial THEN
        INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created)
        VALUES(p_event,b.tenant_ref,p_hash,p_created);
        IF NOT EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries
            WHERE tenant_ref=b.tenant_ref AND payment_created > p_created) THEN
            UPDATE gvai_authority.billing_reconcile_state SET denial_event=p_event,
                denial_held_since=COALESCE(denial_held_since,v_now)
            WHERE tenant_ref=b.tenant_ref;
            UPDATE gvai_authority.billing_customers
            SET eligible = false, verified_until = '-infinity', access_until = '-infinity'
            WHERE tenant_ref = b.tenant_ref;
        END IF;
    END IF;
    INSERT INTO gvai_authority.billing_reconcile_tickets
        (tenant_ref, started_at, expires_at, claimed, event_id, event_created, payload_hash)
    VALUES (b.tenant_ref, v_now, v_now + interval '45 seconds', false, p_event, p_created, p_hash)
    RETURNING ticket_id INTO v_ticket;
    RETURN QUERY SELECT false, b.subscription_id, b.repin_allowed, v_ticket, v_now;
END;
$function$;

CREATE OR REPLACE FUNCTION gvai_authority.reconcile_apply_v1(
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
    scoped_denial gvai_authority.billing_scoped_denials%ROWTYPE;
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

    -- A definitive negative returned by the verified provider chain is durable too.
    -- Failed provider requests go through reconcile_fail_v1 and never reach here.
    IF v_reject IS NULL AND NOT p_eligible AND s.denial_event IS NULL AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.billing_denial_recoveries
        WHERE tenant_ref=b.tenant_ref AND recovered_at > t.started_at
    ) THEN
        INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created)
        VALUES('evt_poll_' || t.ticket_id::text, b.tenant_ref,
            repeat(md5('poll:' || t.ticket_id::text),2),
            GREATEST(COALESCE(p_observed_max,v_epoch),s.stripe_floor));
        IF s.denial_event IS NULL THEN
            UPDATE gvai_authority.billing_reconcile_state
            SET denial_event='evt_poll_' || t.ticket_id::text,
                denial_held_since=COALESCE(denial_held_since,v_now) WHERE tenant_ref=b.tenant_ref;
            s.denial_event := 'evt_poll_' || t.ticket_id::text;
        END IF;
    ELSIF v_reject IS NULL AND NOT p_eligible AND s.denial_event IS NULL THEN
        RETURN gvai_authority.reconcile_release_v1(b.tenant_ref,t.ticket_id,v_now,'covered_by_newer',false);
    END IF;
    IF v_reject IS NULL AND v_positive AND s.denial_event IS NULL THEN
        SELECT * INTO scoped_denial FROM gvai_authority.billing_scoped_denials d
        WHERE d.tenant_ref=b.tenant_ref AND d.subscription_id=p_subscription
            AND (d.invoice_id IS NULL OR d.invoice_id=p_invoice)
            AND NOT EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries r
                WHERE r.tenant_ref=b.tenant_ref AND r.payment_created>d.event_created)
        ORDER BY d.event_created DESC, d.event_id LIMIT 1;
        IF FOUND THEN
            INSERT INTO gvai_authority.billing_denials(event_id,tenant_ref,payload_hash,event_created)
            VALUES(scoped_denial.event_id,b.tenant_ref,scoped_denial.payload_hash,scoped_denial.event_created)
            ON CONFLICT(event_id) DO NOTHING;
            UPDATE gvai_authority.billing_reconcile_state
            SET denial_event=scoped_denial.event_id,denial_held_since=COALESCE(denial_held_since,v_now)
            WHERE tenant_ref=b.tenant_ref;
            s.denial_event := scoped_denial.event_id;
        END IF;
    END IF;
    IF s.denial_event IS NOT NULL THEN
        v_positive := false;
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

-- Owner-only verified-evidence attestation boundary, never grant to runtime/reconciler.
-- Caller must verify the signed invoice.paid evidence and refetch the full paid chain.
CREATE FUNCTION gvai_authority.reconcile_recover_denial_v1(
    p_customer text, p_denial text, p_event text, p_hash text, p_paid bigint, p_reason text,
    p_ticket bigint, p_min bigint, p_max bigint, p_sub text, p_invoice text,
    p_start bigint, p_end bigint, p_access bigint
) RETURNS text LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    b gvai_authority.billing_customers%ROWTYPE;
    s gvai_authority.billing_reconcile_state%ROWTYPE;
    d gvai_authority.billing_denials%ROWTYPE;
    result text;
BEGIN
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id=p_customer FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'recovery rejected'; END IF;
    SELECT * INTO s FROM gvai_authority.billing_reconcile_state WHERE tenant_ref=b.tenant_ref FOR UPDATE;
    SELECT * INTO d FROM gvai_authority.billing_denials WHERE event_id=s.denial_event;
    IF s.denial_event IS NULL OR p_denial IS DISTINCT FROM s.denial_event
        OR b.revoked OR s.phase='needs_operator'
        OR (b.subscription_terminal_at IS NOT NULL AND NOT b.repin_allowed)
        OR p_paid IS NULL OR p_paid <= d.event_created
        OR p_paid <= (SELECT max(event_created) FROM gvai_authority.billing_denials
                      WHERE tenant_ref=b.tenant_ref)
        OR p_paid <= (SELECT max(event_created) FROM gvai_authority.billing_scoped_denials
            WHERE tenant_ref=b.tenant_ref AND subscription_id=p_sub AND (invoice_id IS NULL OR invoice_id=p_invoice))
        OR p_paid > floor(extract(epoch FROM clock_timestamp()))::bigint
        OR p_min IS NULL OR p_paid > p_min
        OR p_sub IS NULL OR p_invoice IS NULL
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_events WHERE event_id=p_event
            AND (tenant_ref<>b.tenant_ref OR payload_hash<>p_hash))
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_denials WHERE event_id=p_event)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_scoped_denials WHERE event_id=p_event)
        OR EXISTS (SELECT 1 FROM gvai_authority.billing_denial_recoveries WHERE payment_event=p_event)
    THEN RAISE EXCEPTION 'recovery rejected'; END IF;
    -- A new denial invalidates this compare-and-clear under the same customer/state locks.
    UPDATE gvai_authority.billing_reconcile_state SET denial_event=NULL, denial_held_since=NULL WHERE tenant_ref=b.tenant_ref;
    INSERT INTO gvai_authority.billing_denial_recoveries
        (tenant_ref,denial_event,payment_event,evidence_hash,payment_created,subscription_id,invoice_id,reason)
    VALUES(b.tenant_ref,p_denial,p_event,p_hash,p_paid,p_sub,p_invoice,p_reason);
    result := gvai_authority.reconcile_apply_v1(p_customer,p_ticket,p_min,p_max,p_sub,p_invoice,
        p_start,p_end,true,p_access,false);
    IF result <> 'applied_eligible' THEN RAISE EXCEPTION 'recovery snapshot rejected'; END IF;
    -- No pre-recovery read may renew the recovered entitlement.
    DELETE FROM gvai_authority.billing_reconcile_tickets WHERE tenant_ref=b.tenant_ref;
    RETURN 'recovered';
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.reconcile_recover_denial_v1(
    text,text,text,text,bigint,text,bigint,bigint,bigint,text,text,bigint,bigint,bigint) FROM PUBLIC;
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

-- Transaction-specific ingress resolves scope in the same lock as the denial signal.
CREATE FUNCTION gvai_authority.reconcile_signal_v1(
    p_customer text, p_event text, p_hash text, p_created bigint, p_denial boolean,
    p_subscription text, p_invoice text
) RETURNS TABLE (
    o_duplicate boolean, o_subscription text, o_repin boolean, o_ticket bigint, o_started timestamptz
) LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE b gvai_authority.billing_customers%ROWTYPE;
BEGIN
    IF p_subscription IS NULL OR p_subscription !~ '^sub_[A-Za-z0-9_]{1,124}$'
        OR (p_invoice IS NOT NULL AND p_invoice !~ '^in_[A-Za-z0-9_]{1,125}$') THEN
        RAISE EXCEPTION 'denial scope rejected';
    END IF;
    SELECT * INTO b FROM gvai_authority.billing_customers WHERE customer_id=p_customer FOR UPDATE;
    -- An unrelated transaction is an ordinary wakeup; it cannot impose a hold.
    RETURN QUERY SELECT * FROM gvai_authority.reconcile_signal_v1(
        p_customer,p_event,p_hash,p_created,
        p_denial AND b.subscription_id IS NOT DISTINCT FROM p_subscription
            AND (p_invoice IS NULL OR b.current_invoice IS NOT DISTINCT FROM p_invoice
                OR (b.current_invoice IS NULL AND EXISTS (
                    SELECT 1 FROM gvai_authority.billing_periods period
                    WHERE period.tenant_ref=b.tenant_ref AND period.subscription_id=p_subscription
                        AND period.invoice_id=p_invoice AND NOT EXISTS (
                            SELECT 1 FROM gvai_authority.billing_periods later
                            WHERE later.tenant_ref=b.tenant_ref AND later.starts_at>period.starts_at)))));
    IF p_denial AND b.tenant_ref IS NOT NULL THEN
        INSERT INTO gvai_authority.billing_scoped_denials
            (event_id,tenant_ref,payload_hash,event_created,subscription_id,invoice_id)
        VALUES(p_event,b.tenant_ref,p_hash,p_created,p_subscription,p_invoice)
        ON CONFLICT(event_id) DO NOTHING;
        IF NOT EXISTS (SELECT 1 FROM gvai_authority.billing_scoped_denials
            WHERE event_id=p_event AND tenant_ref=b.tenant_ref AND payload_hash=p_hash
                AND subscription_id=p_subscription AND invoice_id IS NOT DISTINCT FROM p_invoice) THEN
            RAISE EXCEPTION 'event collision rejected';
        END IF;
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION gvai_authority.reconcile_signal_v1(text,text,text,bigint,boolean,text,text) FROM PUBLIC;
-- Inherit only existing signal EXECUTE grants, including upgrades with custom role names.
DO $acl$
DECLARE entry record;
BEGIN
    FOR entry IN SELECT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='gvai_authority.reconcile_signal_v1(text,text,text,bigint,boolean)'::regprocedure
        AND a.privilege_type='EXECUTE' AND a.grantee<>p.proowner
    LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION gvai_authority.reconcile_signal_v1(text,text,text,bigint,boolean,text,text) TO %I',entry.rolname);
    END LOOP;
END;
$acl$;

COMMIT;
