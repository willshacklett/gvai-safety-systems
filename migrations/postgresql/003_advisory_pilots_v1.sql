BEGIN;

DO $owner_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS role ON role.oid = namespace.nspowner
        WHERE namespace.nspname = 'gvai_authority'
          AND role.rolname = current_user AND NOT role.rolsuper
    ) THEN
        RAISE EXCEPTION 'advisory migration requires the non-superuser authority owner';
    END IF;
END;
$owner_guard$;

CREATE TABLE gvai_authority.advisory_pilots (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.tenants (tenant_ref),
    starts_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > starts_at),
    allowance bigint NOT NULL CHECK (allowance BETWEEN 0 AND 9223372036854775807),
    consumed bigint NOT NULL DEFAULT 0 CHECK (consumed BETWEEN 0 AND allowance),
    active boolean NOT NULL DEFAULT true
);

CREATE TABLE gvai_authority.advisory_attempts (
    event_id text PRIMARY KEY REFERENCES gvai_authority.reservation_events (event_id),
    state text NOT NULL CHECK (state IN ('reserved', 'completed', 'failed'))
);

-- Private helper: lock and derive customer identity from current database rows.
CREATE FUNCTION gvai_authority.advisory_customer_v1(
    p_key_id text, p_verifier bytea, p_resource_id text, p_capability text
)
RETURNS bigint
LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    credential_row gvai_authority.customer_credentials%ROWTYPE;
    tenant_row gvai_authority.tenants%ROWTYPE;
    membership_row gvai_authority.tenant_memberships%ROWTYPE;
    ownership_row gvai_authority.resource_ownerships%ROWTYPE;
BEGIN
    IF p_key_id IS NULL OR p_key_id !~ '^[0-9a-f]{32}$'
        OR p_verifier IS NULL OR pg_catalog.octet_length(p_verifier) <> 32
        OR p_resource_id IS NULL
        OR p_resource_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_capability IS NULL
        OR p_capability NOT IN ('evaluation:run', 'usage:read') THEN
        RETURN NULL;
    END IF;
    SELECT * INTO credential_row
    FROM gvai_authority.customer_credentials AS credential
    WHERE credential.key_id = p_key_id FOR UPDATE;
    IF NOT FOUND OR credential_row.status <> 'active'
        OR credential_row.revoked_at IS NOT NULL
        OR credential_row.created_at > pg_catalog.clock_timestamp()
        OR credential_row.expires_at <= pg_catalog.clock_timestamp()
        OR NOT (credential_row.capabilities @> ARRAY[p_capability]::text[])
        OR NOT gvai_authority.constant_time_verifier_equal(
            credential_row.credential_verifier, p_verifier
        ) THEN
        RETURN NULL;
    END IF;
    SELECT * INTO tenant_row FROM gvai_authority.tenants AS tenant
    WHERE tenant.tenant_ref = credential_row.tenant_ref FOR UPDATE;
    IF NOT FOUND OR tenant_row.status <> 'active' THEN RETURN NULL; END IF;
    SELECT * INTO membership_row FROM gvai_authority.tenant_memberships AS membership
    WHERE membership.tenant_ref = tenant_row.tenant_ref
      AND membership.membership_ref = credential_row.membership_ref FOR UPDATE;
    IF NOT FOUND OR membership_row.status <> 'active' THEN RETURN NULL; END IF;
    SELECT * INTO ownership_row FROM gvai_authority.resource_ownerships AS ownership
    WHERE ownership.resource_id = p_resource_id AND ownership.status = 'active'
    FOR UPDATE;
    IF NOT FOUND OR ownership_row.tenant_ref <> tenant_row.tenant_ref
        OR ownership_row.resource_kind <> 'evaluation' THEN
        RETURN NULL;
    END IF;
    RETURN tenant_row.tenant_ref;
END;
$function$;

CREATE FUNCTION gvai_authority.reserve_advisory_v1(
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
    pilot gvai_authority.advisory_pilots%ROWTYPE;
    result record;
    credential_expires_at timestamptz;
    authorization_time timestamptz;
BEGIN
    customer := gvai_authority.advisory_customer_v1(
        p_key_id, p_credential_verifier, p_resource_id, 'evaluation:run'
    );
    IF customer IS NULL THEN
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO pilot FROM gvai_authority.advisory_pilots AS entitlement
    WHERE entitlement.tenant_ref = customer FOR UPDATE;
    IF NOT FOUND OR NOT pilot.active
        OR pilot.starts_at > pg_catalog.clock_timestamp()
        OR pilot.expires_at <= pg_catalog.clock_timestamp() THEN
        outcome := 'unauthorized'; RETURN NEXT; RETURN;
    END IF;
    IF pilot.consumed >= pilot.allowance AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.reservation_idempotency AS existing
        WHERE existing.authority_id = p_expected_authority_id
          AND existing.tenant_ref = customer
          AND existing.request_id_digest = pg_catalog.encode(
              gvai_authority.digest(pg_catalog.convert_to(p_request_id, 'UTF8'), 'sha256'), 'hex'
          )
    ) THEN
        outcome := 'quota_exceeded'; RETURN NEXT; RETURN;
    END IF;
    SELECT * INTO STRICT result FROM gvai_authority.reserve_v1(
        p_key_id, p_credential_verifier,
        p_expected_authority_id, p_expected_epoch, p_expected_trust_domain,
        p_request_id, p_resource_id, p_payload_digest
    );
    IF result.outcome IN ('reserved', 'replay') THEN
        -- reserve_v1 may wait on policy, authority or bucket locks after initial checks.
        IF gvai_authority.advisory_customer_v1(
            p_key_id, p_credential_verifier, p_resource_id, 'evaluation:run'
        ) IS DISTINCT FROM customer THEN
            RAISE EXCEPTION 'advisory authorization expired during reservation'
                USING ERRCODE = '42501';
        END IF;
        SELECT credential.expires_at INTO STRICT credential_expires_at
        FROM gvai_authority.customer_credentials AS credential WHERE credential.key_id = p_key_id;
        authorization_time := pg_catalog.clock_timestamp();
        IF credential_expires_at <= authorization_time OR NOT pilot.active
            OR pilot.starts_at > authorization_time OR pilot.expires_at <= authorization_time THEN
            RAISE EXCEPTION 'advisory authorization expired during reservation'
                USING ERRCODE = '42501';
        END IF;
    END IF;
    IF result.outcome = 'reserved' THEN
        UPDATE gvai_authority.advisory_pilots AS entitlement
        SET consumed = entitlement.consumed + 1 WHERE entitlement.tenant_ref = customer;
        INSERT INTO gvai_authority.advisory_attempts VALUES (result.event_id, 'reserved');
    ELSIF result.outcome = 'replay' AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.advisory_attempts AS attempt
        WHERE attempt.event_id = result.event_id
    ) THEN
        RAISE EXCEPTION 'reservation lacks advisory attempt evidence';
    END IF;
    RETURN QUERY SELECT result.outcome, result.authority_id, result.authority_epoch,
        result.trust_domain, result.sequence, result.event_id, result.previous_event_hash,
        result.event_hash, result.tenant_digest, result.principal_digest,
        result.resource_digest, result.request_id_digest, result.request_digest,
        result.period_start, result.policy_version, result.units, result.contract_version;
END;
$function$;

CREATE FUNCTION gvai_authority.complete_advisory_v1(
    p_key_id text, p_verifier bytea, p_resource_id text,
    p_request_id text, p_succeeded boolean
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    event_identifier text;
    prior_state text;
    target_state text;
BEGIN
    customer := gvai_authority.advisory_customer_v1(
        p_key_id, p_verifier, p_resource_id, 'evaluation:run'
    );
    IF customer IS NULL THEN RETURN 'unauthorized'; END IF;
    IF p_request_id IS NULL
        OR p_request_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_succeeded IS NULL THEN RETURN 'invalid_input'; END IF;
    SELECT existing.event_id INTO event_identifier
    FROM gvai_authority.reservation_idempotency AS existing
    WHERE existing.tenant_ref = customer
      AND existing.request_id_digest = pg_catalog.encode(
          gvai_authority.digest(pg_catalog.convert_to(p_request_id, 'UTF8'), 'sha256'), 'hex'
      )
      AND existing.resource_digest = pg_catalog.encode(
          gvai_authority.digest(pg_catalog.convert_to(p_resource_id, 'UTF8'), 'sha256'), 'hex'
      );
    IF NOT FOUND THEN RETURN 'not_found'; END IF;
    SELECT attempt.state INTO prior_state FROM gvai_authority.advisory_attempts AS attempt
    WHERE attempt.event_id = event_identifier FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'advisory completion evidence missing'; END IF;
    target_state := CASE WHEN p_succeeded THEN 'completed' ELSE 'failed' END;
    IF prior_state = target_state THEN RETURN 'replay'; END IF;
    IF prior_state <> 'reserved' THEN RETURN 'conflict'; END IF;
    UPDATE gvai_authority.advisory_attempts AS attempt SET state = target_state
    WHERE attempt.event_id = event_identifier;
    RETURN target_state;
END;
$function$;

CREATE FUNCTION gvai_authority.advisory_usage_v1(
    p_key_id text, p_verifier bytea, p_resource_id text
)
RETURNS TABLE (
    allowance bigint, consumed bigint, reserved bigint, completed bigint, failed bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    customer bigint;
    pilot gvai_authority.advisory_pilots%ROWTYPE;
BEGIN
    customer := gvai_authority.advisory_customer_v1(
        p_key_id, p_verifier, p_resource_id, 'usage:read'
    );
    IF customer IS NULL THEN RETURN; END IF;
    SELECT * INTO pilot FROM gvai_authority.advisory_pilots AS entitlement
    WHERE entitlement.tenant_ref = customer FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    RETURN QUERY SELECT pilot.allowance, pilot.consumed,
        count(*) FILTER (WHERE attempt.state = 'reserved'),
        count(*) FILTER (WHERE attempt.state = 'completed'),
        count(*) FILTER (WHERE attempt.state = 'failed')
    FROM gvai_authority.advisory_attempts AS attempt
    JOIN gvai_authority.reservation_events AS event ON event.event_id = attempt.event_id
    WHERE event.tenant_ref = customer;
END;
$function$;

REVOKE ALL ON TABLE gvai_authority.advisory_pilots, gvai_authority.advisory_attempts FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.advisory_customer_v1(text, bytea, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.reserve_advisory_v1(
    text, bytea, text, bigint, text, text, text, text
) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.complete_advisory_v1(text, bytea, text, text, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.advisory_usage_v1(text, bytea, text) FROM PUBLIC;

COMMIT;
