BEGIN;

DO $owner_guard$
DECLARE
    migration_is_superuser boolean;
BEGIN
    SELECT role.rolsuper
    INTO migration_is_superuser
    FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = current_user;

    IF migration_is_superuser IS DISTINCT FROM false THEN
        RAISE EXCEPTION 'reservation routine migration requires a non-superuser owner';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_namespace AS namespace
        WHERE namespace.nspname = 'gvai_authority'
          AND namespace.nspowner = (
              SELECT role.oid
              FROM pg_catalog.pg_roles AS role
              WHERE role.rolname = current_user
          )
    ) THEN
        RAISE EXCEPTION 'reservation routine migration must run as authority schema owner';
    END IF;
END;
$owner_guard$;

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA gvai_authority;

DO $extension_guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_extension AS extension
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = extension.extnamespace
        WHERE extension.extname = 'pgcrypto'
          AND namespace.nspname = 'gvai_authority'
    ) THEN
        RAISE EXCEPTION 'pgcrypto must be installed in gvai_authority';
    END IF;
END;
$extension_guard$;

CREATE FUNCTION gvai_authority.constant_time_verifier_equal(
    stored_verifier bytea,
    candidate_verifier bytea
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    difference integer := 0;
    byte_index integer;
BEGIN
    IF pg_catalog.octet_length(stored_verifier) <> 32
        OR pg_catalog.octet_length(candidate_verifier) <> 32 THEN
        RETURN false;
    END IF;

    FOR byte_index IN 0..31 LOOP
        difference := difference
            | (
                pg_catalog.get_byte(stored_verifier, byte_index)
                # pg_catalog.get_byte(candidate_verifier, byte_index)
            );
    END LOOP;

    RETURN difference = 0;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.constant_time_verifier_equal(bytea, bytea)
    FROM PUBLIC;

CREATE FUNCTION gvai_authority.reservation_event_hash_v1(
    event_row gvai_authority.reservation_events
)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
    SELECT pg_catalog.encode(
        gvai_authority.digest(
            pg_catalog.convert_to('gvai-reservation-event-v1', 'UTF8')
                || pg_catalog.decode('00', 'hex')
                || pg_catalog.convert_to(
                    '{"authority_epoch":' || ($1).authority_epoch::text
                    || ',"authority_id":"' || ($1).authority_id
                    || '","contract_version":' || ($1).contract_version::text
                    || ',"event_id":"' || ($1).event_id
                    || '","period":"' || pg_catalog.to_char(($1).period_start, 'YYYY-MM')
                    || '","policy_version":"' || ($1).policy_version
                    || '","previous_event_hash":"' || ($1).previous_event_hash
                    || '","principal_digest":"' || ($1).principal_digest
                    || '","request_digest":"' || ($1).request_digest
                    || '","request_id_digest":"' || ($1).request_id_digest
                    || '","resource_digest":"' || ($1).resource_digest
                    || '","sequence":' || ($1).sequence::text
                    || ',"tenant_digest":"' || ($1).tenant_digest
                    || '","trust_domain":"' || ($1).trust_domain
                    || '","units":' || ($1).units::text || '}',
                    'UTF8'
                ),
            'sha256'
        ),
        'hex'
    );
$function$;

REVOKE ALL ON FUNCTION gvai_authority.reservation_event_hash_v1(
    gvai_authority.reservation_events
) FROM PUBLIC;

CREATE FUNCTION gvai_authority.reserve_v1(
    p_key_id text,
    p_credential_verifier bytea,
    p_expected_authority_id text,
    p_expected_epoch bigint,
    p_expected_trust_domain text,
    p_request_id text,
    p_resource_id text,
    p_payload_digest text
)
RETURNS TABLE (
    outcome text,
    authority_id text,
    authority_epoch bigint,
    trust_domain text,
    sequence bigint,
    event_id text,
    previous_event_hash text,
    event_hash text,
    tenant_digest text,
    principal_digest text,
    resource_digest text,
    request_id_digest text,
    request_digest text,
    period_start date,
    policy_version text,
    units smallint,
    contract_version smallint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
DECLARE
    credential_row gvai_authority.customer_credentials%ROWTYPE;
    tenant_row gvai_authority.tenants%ROWTYPE;
    membership_row gvai_authority.tenant_memberships%ROWTYPE;
    ownership_row gvai_authority.resource_ownerships%ROWTYPE;
    policy_row gvai_authority.quota_policies%ROWTYPE;
    authority_row gvai_authority.authority_state%ROWTYPE;
    bucket_row gvai_authority.monthly_usage_buckets%ROWTYPE;
    idempotency_row gvai_authority.reservation_idempotency%ROWTYPE;
    event_row gvai_authority.reservation_events%ROWTYPE;
    canonical_request text;
    affected_rows bigint;
    v_request_id_digest text;
    v_resource_digest text;
    v_request_digest text;
    v_period_start date;
BEGIN
    IF p_key_id IS NULL
        OR p_key_id !~ '^[0-9a-f]{32}$'
        OR p_credential_verifier IS NULL
        OR pg_catalog.octet_length(p_credential_verifier) <> 32
        OR p_expected_authority_id IS NULL
        OR p_expected_authority_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_expected_epoch IS NULL
        OR p_expected_epoch < 1
        OR p_expected_trust_domain IS NULL
        OR p_expected_trust_domain !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_request_id IS NULL
        OR p_request_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_resource_id IS NULL
        OR p_resource_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR p_payload_digest IS NULL
        OR p_payload_digest !~ '^[0-9a-f]{64}$' THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT *
    INTO credential_row
    FROM gvai_authority.customer_credentials AS credential
    WHERE credential.key_id = p_key_id
    FOR UPDATE;

    IF NOT FOUND
        OR NOT gvai_authority.constant_time_verifier_equal(
            credential_row.credential_verifier, p_credential_verifier
        )
        OR credential_row.status <> 'active'
        OR credential_row.revoked_at IS NOT NULL
        OR credential_row.created_at > pg_catalog.clock_timestamp()
        OR credential_row.expires_at <= pg_catalog.clock_timestamp()
        OR NOT (credential_row.capabilities @> ARRAY['evaluation:run']::text[]) THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT *
    INTO tenant_row
    FROM gvai_authority.tenants AS tenant
    WHERE tenant.tenant_ref = credential_row.tenant_ref
    FOR UPDATE;

    IF NOT FOUND OR tenant_row.status <> 'active'
        OR tenant_row.tenant_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT *
    INTO membership_row
    FROM gvai_authority.tenant_memberships AS membership
    WHERE membership.tenant_ref = credential_row.tenant_ref
      AND membership.membership_ref = credential_row.membership_ref
    FOR UPDATE;

    IF NOT FOUND OR membership_row.status <> 'active'
        OR membership_row.principal_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT *
    INTO ownership_row
    FROM gvai_authority.resource_ownerships AS ownership
    WHERE ownership.resource_id = p_resource_id
      AND ownership.status = 'active'
    FOR UPDATE;

    IF NOT FOUND
        OR ownership_row.tenant_ref <> credential_row.tenant_ref
        OR ownership_row.resource_kind <> 'evaluation'
        OR ownership_row.status <> 'active' THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT policy.*
    INTO policy_row
    FROM gvai_authority.current_quota_policies AS current_policy
    JOIN gvai_authority.quota_policies AS policy
      ON policy.tenant_ref = current_policy.tenant_ref
     AND policy.policy_version = current_policy.policy_version
    WHERE current_policy.tenant_ref = credential_row.tenant_ref
    FOR UPDATE OF current_policy, policy;

    IF NOT FOUND
        OR policy_row.policy_version !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$' THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    SELECT *
    INTO authority_row
    FROM gvai_authority.authority_state AS authority
    WHERE authority.singleton_id = 1
    FOR UPDATE;

    IF NOT FOUND THEN
        outcome := 'authority_unavailable';
        RETURN NEXT;
        RETURN;
    END IF;

    IF authority_row.authority_id <> p_expected_authority_id
        OR authority_row.epoch <> p_expected_epoch
        OR authority_row.trust_domain <> p_expected_trust_domain THEN
        outcome := 'unauthorized';
        RETURN NEXT;
        RETURN;
    END IF;

    canonical_request := '{"payload_digest":"' || p_payload_digest
        || '","request_id":"' || p_request_id
        || '","resource_id":"' || p_resource_id
        || '","version":1}';
    v_request_id_digest := pg_catalog.encode(
        gvai_authority.digest(pg_catalog.convert_to(p_request_id, 'UTF8'), 'sha256'),
        'hex'
    );
    v_resource_digest := pg_catalog.encode(
        gvai_authority.digest(pg_catalog.convert_to(p_resource_id, 'UTF8'), 'sha256'),
        'hex'
    );
    v_request_digest := pg_catalog.encode(
        gvai_authority.digest(
            pg_catalog.convert_to('gvai-reservation-request-v1', 'UTF8')
                || pg_catalog.decode('00', 'hex')
                || pg_catalog.convert_to(canonical_request, 'UTF8'),
            'sha256'
        ),
        'hex'
    );

    SELECT *
    INTO idempotency_row
    FROM gvai_authority.reservation_idempotency AS idempotency
    WHERE idempotency.authority_id = authority_row.authority_id
      AND idempotency.tenant_ref = credential_row.tenant_ref
            AND idempotency.request_id_digest = v_request_id_digest;

    IF FOUND THEN
                IF idempotency_row.request_digest <> v_request_digest
                        OR idempotency_row.resource_digest <> v_resource_digest THEN
            outcome := 'conflict';
            RETURN NEXT;
            RETURN;
        END IF;

        SELECT *
        INTO event_row
        FROM gvai_authority.reservation_events AS event
        WHERE event.authority_id = authority_row.authority_id
          AND event.event_id = idempotency_row.event_id
          AND event.tenant_ref = credential_row.tenant_ref;

        IF NOT FOUND
            OR event_row.request_id_digest <> v_request_id_digest
            OR event_row.request_digest <> v_request_digest
            OR event_row.resource_digest <> v_resource_digest
            OR gvai_authority.reservation_event_hash_v1(event_row) <> event_row.event_hash THEN
            RAISE EXCEPTION 'stored reservation event failed canonical V1 verification';
        END IF;

        outcome := 'replay';
        authority_id := event_row.authority_id;
        authority_epoch := event_row.authority_epoch;
        trust_domain := event_row.trust_domain;
        sequence := event_row.sequence;
        event_id := event_row.event_id;
        previous_event_hash := event_row.previous_event_hash;
        event_hash := event_row.event_hash;
        tenant_digest := event_row.tenant_digest;
        principal_digest := event_row.principal_digest;
        resource_digest := event_row.resource_digest;
        request_id_digest := event_row.request_id_digest;
        request_digest := event_row.request_digest;
        period_start := event_row.period_start;
        policy_version := event_row.policy_version;
        units := event_row.units;
        contract_version := event_row.contract_version;
        RETURN NEXT;
        RETURN;
    END IF;

    v_period_start := pg_catalog.date_trunc(
        'month', pg_catalog.clock_timestamp() AT TIME ZONE 'UTC'
    )::date;

    INSERT INTO gvai_authority.monthly_usage_buckets (
        tenant_ref, period_start, policy_version, allowance
    ) VALUES (
        credential_row.tenant_ref, v_period_start,
        policy_row.policy_version, policy_row.monthly_allowance
    )
    ON CONFLICT ON CONSTRAINT monthly_usage_buckets_pkey DO NOTHING;

    SELECT *
    INTO bucket_row
    FROM gvai_authority.monthly_usage_buckets AS bucket
    WHERE bucket.tenant_ref = credential_row.tenant_ref
    AND bucket.period_start = v_period_start
    FOR UPDATE;

    IF NOT FOUND
        OR bucket_row.policy_version <> policy_row.policy_version
        OR bucket_row.allowance <> policy_row.monthly_allowance THEN
        outcome := 'authority_unavailable';
        RETURN NEXT;
        RETURN;
    END IF;

    IF bucket_row.consumed >= bucket_row.allowance THEN
        outcome := 'quota_exceeded';
        RETURN NEXT;
        RETURN;
    END IF;

    event_row.event_id := pg_catalog.gen_random_uuid()::text;
    event_row.authority_id := authority_row.authority_id;
    event_row.authority_epoch := authority_row.epoch;
    event_row.trust_domain := authority_row.trust_domain;
    event_row.contract_version := 1;
    event_row.sequence := authority_row.last_sequence + 1;
    event_row.previous_event_hash := authority_row.last_event_hash;
    event_row.tenant_ref := credential_row.tenant_ref;
    event_row.tenant_digest := pg_catalog.encode(
        gvai_authority.digest(pg_catalog.convert_to(tenant_row.tenant_id, 'UTF8'), 'sha256'),
        'hex'
    );
    event_row.membership_ref := credential_row.membership_ref;
    event_row.principal_digest := pg_catalog.encode(
        gvai_authority.digest(
            pg_catalog.convert_to(membership_row.principal_id, 'UTF8'), 'sha256'
        ),
        'hex'
    );
    event_row.ownership_ref := ownership_row.ownership_ref;
    event_row.request_id_digest := v_request_id_digest;
    event_row.request_digest := v_request_digest;
    event_row.resource_digest := v_resource_digest;
    event_row.period_start := v_period_start;
    event_row.policy_version := policy_row.policy_version;
    event_row.units := 1;
    event_row.event_hash := gvai_authority.reservation_event_hash_v1(event_row);

    INSERT INTO gvai_authority.reservation_events (
        event_id, authority_id, authority_epoch, trust_domain,
        contract_version, sequence, previous_event_hash, event_hash,
        tenant_ref, tenant_digest, membership_ref, principal_digest,
        ownership_ref, request_id_digest, request_digest, resource_digest,
        period_start, policy_version, units
    ) VALUES (
        event_row.event_id, event_row.authority_id, event_row.authority_epoch,
        event_row.trust_domain, event_row.contract_version, event_row.sequence,
        event_row.previous_event_hash, event_row.event_hash, event_row.tenant_ref,
        event_row.tenant_digest, event_row.membership_ref, event_row.principal_digest,
        event_row.ownership_ref, event_row.request_id_digest, event_row.request_digest,
        event_row.resource_digest, event_row.period_start, event_row.policy_version,
        event_row.units
    ) RETURNING * INTO event_row;

    INSERT INTO gvai_authority.reservation_idempotency (
        authority_id, tenant_ref, request_id_digest,
        request_digest, resource_digest, event_id
    ) VALUES (
        event_row.authority_id, event_row.tenant_ref, event_row.request_id_digest,
        event_row.request_digest, event_row.resource_digest, event_row.event_id
    );

    UPDATE gvai_authority.authority_state AS authority
    SET last_sequence = event_row.sequence,
        last_event_hash = event_row.event_hash
    WHERE authority.singleton_id = 1
      AND authority.authority_id = event_row.authority_id
      AND authority.epoch = event_row.authority_epoch
      AND authority.last_sequence = event_row.sequence - 1
      AND authority.last_event_hash = event_row.previous_event_hash;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION 'authority head did not advance exactly once';
    END IF;

    outcome := 'reserved';
    authority_id := event_row.authority_id;
    authority_epoch := event_row.authority_epoch;
    trust_domain := event_row.trust_domain;
    sequence := event_row.sequence;
    event_id := event_row.event_id;
    previous_event_hash := event_row.previous_event_hash;
    event_hash := event_row.event_hash;
    tenant_digest := event_row.tenant_digest;
    principal_digest := event_row.principal_digest;
    resource_digest := event_row.resource_digest;
    request_id_digest := event_row.request_id_digest;
    request_digest := event_row.request_digest;
    period_start := event_row.period_start;
    policy_version := event_row.policy_version;
    units := event_row.units;
    contract_version := event_row.contract_version;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.reserve_v1(
    text, bytea, text, bigint, text, text, text, text
) FROM PUBLIC;

CREATE TABLE gvai_authority.reservation_routine_installation (
    singleton_id smallint PRIMARY KEY CHECK (singleton_id = 1),
    version integer NOT NULL CHECK (version = 1),
    migration_id text NOT NULL CHECK (
        migration_id = '002_restricted_reservation_routine_v1'
    ),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO gvai_authority.reservation_routine_installation (
    singleton_id, version, migration_id
)
VALUES (1, 1, '002_restricted_reservation_routine_v1');

REVOKE ALL PRIVILEGES ON TABLE gvai_authority.reservation_routine_installation FROM PUBLIC;

COMMIT;
