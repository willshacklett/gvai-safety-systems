BEGIN;

CREATE SCHEMA gvai_authority;

CREATE TABLE gvai_authority.schema_version (
    singleton_id smallint PRIMARY KEY CHECK (singleton_id = 1),
    version integer NOT NULL CHECK (version = 1),
    migration_id text NOT NULL CHECK (migration_id = '001_reservation_authority_v1'),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

INSERT INTO gvai_authority.schema_version (singleton_id, version, migration_id)
VALUES (1, 1, '001_reservation_authority_v1');

CREATE TABLE gvai_authority.tenants (
    tenant_ref bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE gvai_authority.tenant_memberships (
    membership_ref bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    principal_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_ref, principal_id),
    UNIQUE (tenant_ref, membership_ref)
);

CREATE TABLE gvai_authority.customer_credentials (
    key_id text PRIMARY KEY
        CHECK (key_id ~ '^[0-9a-f]{32}$'),
    tenant_ref bigint NOT NULL,
    membership_ref bigint NOT NULL,
    credential_verifier bytea NOT NULL
        CHECK (octet_length(credential_verifier) = 32),
    capabilities text[] NOT NULL DEFAULT ARRAY[]::text[]
        CHECK (capabilities <@ ARRAY['evaluation:run', 'usage:read']::text[]),
    status text NOT NULL CHECK (status IN ('active', 'revoked', 'disabled')),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL)
        OR (status <> 'revoked' AND revoked_at IS NULL)
    ),
    FOREIGN KEY (tenant_ref, membership_ref)
        REFERENCES gvai_authority.tenant_memberships (tenant_ref, membership_ref)
);

CREATE TABLE gvai_authority.resource_ownerships (
    ownership_ref bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    resource_id text NOT NULL,
    ownership_version bigint NOT NULL CHECK (ownership_version > 0),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    resource_kind text NOT NULL CHECK (resource_kind IN ('evaluation')),
    status text NOT NULL CHECK (status IN ('active', 'disabled', 'reassigned')),
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reassigned_at timestamptz,
    CHECK (
        (status = 'reassigned' AND reassigned_at IS NOT NULL)
        OR (status <> 'reassigned' AND reassigned_at IS NULL)
    ),
    UNIQUE (resource_id, ownership_version),
    UNIQUE (tenant_ref, ownership_ref)
);

CREATE UNIQUE INDEX resource_ownerships_one_active_owner
    ON gvai_authority.resource_ownerships (resource_id)
    WHERE status = 'active';

CREATE TABLE gvai_authority.quota_policies (
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    policy_version text NOT NULL,
    monthly_allowance bigint NOT NULL CHECK (
        monthly_allowance BETWEEN 0 AND 9223372036854775807
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_ref, policy_version),
    UNIQUE (tenant_ref, policy_version, monthly_allowance)
);

CREATE TABLE gvai_authority.current_quota_policies (
    tenant_ref bigint PRIMARY KEY REFERENCES gvai_authority.tenants (tenant_ref),
    policy_version text NOT NULL,
    FOREIGN KEY (tenant_ref, policy_version)
        REFERENCES gvai_authority.quota_policies (tenant_ref, policy_version)
);

CREATE TABLE gvai_authority.monthly_usage_buckets (
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    period_start date NOT NULL CHECK (
        period_start = date_trunc('month', period_start)::date
    ),
    policy_version text NOT NULL,
    allowance bigint NOT NULL CHECK (
        allowance BETWEEN 0 AND 9223372036854775807
    ),
    consumed bigint NOT NULL DEFAULT 0 CHECK (
        consumed BETWEEN 0 AND 9223372036854775807
        AND consumed <= allowance
    ),
    PRIMARY KEY (tenant_ref, period_start),
    UNIQUE (tenant_ref, period_start, policy_version),
    FOREIGN KEY (tenant_ref, policy_version, allowance)
        REFERENCES gvai_authority.quota_policies (
            tenant_ref,
            policy_version,
            monthly_allowance
        )
);

CREATE TABLE gvai_authority.authority_state (
    singleton_id smallint PRIMARY KEY CHECK (singleton_id = 1),
    authority_id text NOT NULL UNIQUE,
    epoch bigint NOT NULL CHECK (epoch > 0),
    trust_domain text NOT NULL,
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (
        last_sequence BETWEEN 0 AND 9223372036854775807
    ),
    last_event_hash text NOT NULL DEFAULT
        '0000000000000000000000000000000000000000000000000000000000000000'
        CHECK (last_event_hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE gvai_authority.reservation_events (
    event_id text PRIMARY KEY,
    authority_id text NOT NULL REFERENCES gvai_authority.authority_state (authority_id),
    authority_epoch bigint NOT NULL CHECK (authority_epoch > 0),
    trust_domain text NOT NULL,
    contract_version smallint NOT NULL CHECK (contract_version = 1),
    sequence bigint NOT NULL CHECK (
        sequence BETWEEN 1 AND 9223372036854775807
    ),
    previous_event_hash text NOT NULL CHECK (
        previous_event_hash ~ '^[0-9a-f]{64}$'
    ),
    event_hash text NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    tenant_digest text NOT NULL CHECK (tenant_digest ~ '^[0-9a-f]{64}$'),
    membership_ref bigint NOT NULL,
    principal_digest text NOT NULL CHECK (principal_digest ~ '^[0-9a-f]{64}$'),
    ownership_ref bigint NOT NULL,
    request_id_digest text NOT NULL CHECK (
        request_id_digest ~ '^[0-9a-f]{64}$'
    ),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    resource_digest text NOT NULL CHECK (resource_digest ~ '^[0-9a-f]{64}$'),
    period_start date NOT NULL CHECK (
        period_start = date_trunc('month', period_start)::date
    ),
    policy_version text NOT NULL,
    units smallint NOT NULL DEFAULT 1 CHECK (units = 1),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (authority_id, sequence),
    UNIQUE (authority_id, event_id),
    UNIQUE (
        authority_id,
        event_id,
        tenant_ref,
        request_id_digest,
        request_digest,
        resource_digest
    ),
    FOREIGN KEY (tenant_ref, membership_ref)
        REFERENCES gvai_authority.tenant_memberships (tenant_ref, membership_ref),
    FOREIGN KEY (tenant_ref, ownership_ref)
        REFERENCES gvai_authority.resource_ownerships (tenant_ref, ownership_ref),
    FOREIGN KEY (tenant_ref, policy_version)
        REFERENCES gvai_authority.quota_policies (tenant_ref, policy_version),
    FOREIGN KEY (tenant_ref, period_start, policy_version)
        REFERENCES gvai_authority.monthly_usage_buckets (
            tenant_ref,
            period_start,
            policy_version
        )
);

CREATE TABLE gvai_authority.reservation_idempotency (
    authority_id text NOT NULL REFERENCES gvai_authority.authority_state (authority_id),
    tenant_ref bigint NOT NULL REFERENCES gvai_authority.tenants (tenant_ref),
    request_id_digest text NOT NULL CHECK (
        request_id_digest ~ '^[0-9a-f]{64}$'
    ),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    resource_digest text NOT NULL CHECK (resource_digest ~ '^[0-9a-f]{64}$'),
    event_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (authority_id, tenant_ref, request_id_digest),
    FOREIGN KEY (
        authority_id,
        event_id,
        tenant_ref,
        request_id_digest,
        request_digest,
        resource_digest
    )
        REFERENCES gvai_authority.reservation_events (
            authority_id,
            event_id,
            tenant_ref,
            request_id_digest,
            request_digest,
            resource_digest
        )
);

CREATE INDEX reservation_events_by_tenant_period
    ON gvai_authority.reservation_events (tenant_ref, period_start);

CREATE INDEX customer_credentials_by_tenant_principal
    ON gvai_authority.customer_credentials (tenant_ref, membership_ref);

CREATE FUNCTION gvai_authority.reject_reservation_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'reservation events are append-only';
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.reject_reservation_event_mutation()
    FROM PUBLIC;

CREATE TRIGGER reservation_events_append_only
    BEFORE UPDATE OR DELETE ON gvai_authority.reservation_events
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.reject_reservation_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE
    ON gvai_authority.reservation_events FROM PUBLIC;

CREATE FUNCTION gvai_authority.reject_idempotency_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    RAISE EXCEPTION 'reservation idempotency records are append-only';
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.reject_idempotency_mutation()
    FROM PUBLIC;

CREATE TRIGGER reservation_idempotency_append_only
    BEFORE UPDATE OR DELETE ON gvai_authority.reservation_idempotency
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.reject_idempotency_mutation();

REVOKE UPDATE, DELETE, TRUNCATE
    ON gvai_authority.reservation_idempotency FROM PUBLIC;

CREATE FUNCTION gvai_authority.enforce_authority_head_continuity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.singleton_id IS DISTINCT FROM OLD.singleton_id
        OR NEW.authority_id IS DISTINCT FROM OLD.authority_id
        OR NEW.epoch IS DISTINCT FROM OLD.epoch
        OR NEW.trust_domain IS DISTINCT FROM OLD.trust_domain THEN
        RAISE EXCEPTION 'authority identity is immutable';
    END IF;

    IF NEW.last_sequence <> OLD.last_sequence + 1 THEN
        RAISE EXCEPTION 'authority sequence must advance by exactly one';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM gvai_authority.reservation_events AS event
        WHERE event.authority_id = OLD.authority_id
          AND event.authority_epoch = OLD.epoch
          AND event.sequence = NEW.last_sequence
          AND event.previous_event_hash = OLD.last_event_hash
          AND event.event_hash = NEW.last_event_hash
    ) THEN
        RAISE EXCEPTION 'authority head must match the next chained event';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.enforce_authority_head_continuity()
    FROM PUBLIC;

CREATE TRIGGER authority_head_continuity
    BEFORE UPDATE ON gvai_authority.authority_state
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.enforce_authority_head_continuity();

REVOKE UPDATE ON gvai_authority.authority_state FROM PUBLIC;

CREATE FUNCTION gvai_authority.prevent_credential_revocation_rollback()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'customer credential records cannot be deleted';
    END IF;

    IF NEW.key_id IS DISTINCT FROM OLD.key_id
        OR NEW.tenant_ref IS DISTINCT FROM OLD.tenant_ref
        OR NEW.membership_ref IS DISTINCT FROM OLD.membership_ref
        OR NEW.credential_verifier IS DISTINCT FROM OLD.credential_verifier
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        RAISE EXCEPTION 'customer credential identity is immutable';
    END IF;

    IF OLD.status = 'revoked'
        AND (
            NEW.status IS DISTINCT FROM OLD.status
            OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
        ) THEN
        RAISE EXCEPTION 'credential revocation is irreversible';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.prevent_credential_revocation_rollback()
    FROM PUBLIC;

CREATE TRIGGER customer_credentials_revocation_monotonic
    BEFORE UPDATE OR DELETE ON gvai_authority.customer_credentials
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.prevent_credential_revocation_rollback();

REVOKE DELETE, TRUNCATE
    ON gvai_authority.customer_credentials FROM PUBLIC;

CREATE FUNCTION gvai_authority.enforce_event_sequence_continuity()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority
AS $function$
DECLARE
    current_authority gvai_authority.authority_state%ROWTYPE;
    bucket gvai_authority.monthly_usage_buckets%ROWTYPE;
BEGIN
    SELECT *
    INTO current_authority
    FROM gvai_authority.authority_state
    WHERE singleton_id = 1
    FOR UPDATE;

    IF NOT FOUND
        OR NEW.authority_id IS DISTINCT FROM current_authority.authority_id
        OR NEW.authority_epoch IS DISTINCT FROM current_authority.epoch
        OR NEW.trust_domain IS DISTINCT FROM current_authority.trust_domain
        OR NEW.sequence <> current_authority.last_sequence + 1
        OR NEW.previous_event_hash IS DISTINCT FROM current_authority.last_event_hash THEN
        RAISE EXCEPTION 'reservation event does not extend the authority head';
    END IF;

    SELECT *
    INTO bucket
    FROM gvai_authority.monthly_usage_buckets
    WHERE tenant_ref = NEW.tenant_ref
      AND period_start = NEW.period_start
      AND policy_version = NEW.policy_version
    FOR UPDATE;

    IF NOT FOUND OR bucket.consumed >= bucket.allowance THEN
        RAISE EXCEPTION 'monthly reservation quota is unavailable';
    END IF;

    UPDATE gvai_authority.monthly_usage_buckets
    SET consumed = bucket.consumed + NEW.units
    WHERE tenant_ref = NEW.tenant_ref
      AND period_start = NEW.period_start
      AND policy_version = NEW.policy_version;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.enforce_event_sequence_continuity()
    FROM PUBLIC;

CREATE TRIGGER reservation_events_sequence_continuity
    BEFORE INSERT ON gvai_authority.reservation_events
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.enforce_event_sequence_continuity();

CREATE FUNCTION gvai_authority.verify_reservation_commit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority
AS $function$
BEGIN
    IF (
        SELECT count(*)
        FROM gvai_authority.reservation_idempotency AS idem
        WHERE idem.authority_id = NEW.authority_id
          AND idem.event_id = NEW.event_id
          AND idem.tenant_ref = NEW.tenant_ref
          AND idem.request_id_digest = NEW.request_id_digest
          AND idem.request_digest = NEW.request_digest
          AND idem.resource_digest = NEW.resource_digest
    ) <> 1 THEN
        RAISE EXCEPTION 'reservation event requires one matching idempotency record';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM gvai_authority.authority_state AS authority
        WHERE authority.singleton_id = 1
          AND authority.authority_id = NEW.authority_id
          AND authority.epoch = NEW.authority_epoch
          AND authority.trust_domain = NEW.trust_domain
          AND authority.last_sequence = NEW.sequence
          AND authority.last_event_hash = NEW.event_hash
    ) THEN
        RAISE EXCEPTION 'reservation event requires a matching advanced authority head';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM gvai_authority.monthly_usage_buckets AS bucket
        WHERE bucket.tenant_ref = NEW.tenant_ref
          AND bucket.period_start = NEW.period_start
          AND bucket.policy_version = NEW.policy_version
          AND bucket.consumed = (
              SELECT count(*)
              FROM gvai_authority.reservation_events AS events
              WHERE events.tenant_ref = NEW.tenant_ref
                AND events.period_start = NEW.period_start
          )
    ) THEN
        RAISE EXCEPTION 'reservation event and quota bucket are inconsistent';
    END IF;

    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.verify_reservation_commit()
    FROM PUBLIC;

CREATE CONSTRAINT TRIGGER reservation_events_complete_at_commit
    AFTER INSERT ON gvai_authority.reservation_events
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.verify_reservation_commit();

CREATE FUNCTION gvai_authority.verify_usage_bucket_commit()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, gvai_authority
AS $function$
DECLARE
    bucket_tenant_ref bigint;
    bucket_period_start date;
    bucket_consumed bigint;
BEGIN
    bucket_tenant_ref := NEW.tenant_ref;
    bucket_period_start := NEW.period_start;

    SELECT consumed
    INTO bucket_consumed
    FROM gvai_authority.monthly_usage_buckets
    WHERE tenant_ref = bucket_tenant_ref
      AND period_start = bucket_period_start;

    IF NOT FOUND OR bucket_consumed <> (
        SELECT count(*)
        FROM gvai_authority.reservation_events AS events
        WHERE events.tenant_ref = bucket_tenant_ref
          AND events.period_start = bucket_period_start
    ) THEN
        RAISE EXCEPTION 'monthly usage bucket must equal committed event count';
    END IF;

    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.verify_usage_bucket_commit()
    FROM PUBLIC;

CREATE CONSTRAINT TRIGGER monthly_usage_buckets_match_events_at_commit
    AFTER INSERT OR UPDATE ON gvai_authority.monthly_usage_buckets
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.verify_usage_bucket_commit();

CREATE FUNCTION gvai_authority.prevent_usage_bucket_rollback()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'monthly usage buckets cannot be deleted';
    END IF;

    IF NEW.tenant_ref IS DISTINCT FROM OLD.tenant_ref
        OR NEW.period_start IS DISTINCT FROM OLD.period_start
        OR NEW.policy_version IS DISTINCT FROM OLD.policy_version
        OR NEW.allowance IS DISTINCT FROM OLD.allowance
        OR NEW.consumed <> OLD.consumed + 1 THEN
        RAISE EXCEPTION 'monthly usage bucket can only advance by one unit';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.prevent_usage_bucket_rollback()
    FROM PUBLIC;

CREATE TRIGGER monthly_usage_buckets_monotonic
    BEFORE UPDATE OR DELETE ON gvai_authority.monthly_usage_buckets
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.prevent_usage_bucket_rollback();

REVOKE UPDATE, DELETE, TRUNCATE
    ON gvai_authority.monthly_usage_buckets FROM PUBLIC;

CREATE FUNCTION gvai_authority.prevent_ownership_history_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'resource ownership history cannot be deleted';
    END IF;

    IF OLD.status <> 'active'
        OR NEW.ownership_ref IS DISTINCT FROM OLD.ownership_ref
        OR NEW.resource_id IS DISTINCT FROM OLD.resource_id
        OR NEW.ownership_version IS DISTINCT FROM OLD.ownership_version
        OR NEW.tenant_ref IS DISTINCT FROM OLD.tenant_ref
        OR NEW.resource_kind IS DISTINCT FROM OLD.resource_kind
        OR NEW.assigned_at IS DISTINCT FROM OLD.assigned_at
        OR NEW.status NOT IN ('reassigned', 'disabled') THEN
        RAISE EXCEPTION 'resource ownership history is immutable';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.prevent_ownership_history_rewrite()
    FROM PUBLIC;

CREATE TRIGGER resource_ownership_history_append_only
    BEFORE UPDATE OR DELETE ON gvai_authority.resource_ownerships
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.prevent_ownership_history_rewrite();

REVOKE DELETE, TRUNCATE
    ON gvai_authority.resource_ownerships FROM PUBLIC;

CREATE FUNCTION gvai_authority.enforce_ownership_version_sequence()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    prior_version bigint;
    prior_status text;
BEGIN
    SELECT ownership_version, status
    INTO prior_version, prior_status
    FROM gvai_authority.resource_ownerships
    WHERE resource_id = NEW.resource_id
    ORDER BY ownership_version DESC
    LIMIT 1
    FOR UPDATE;

    IF NOT FOUND THEN
        IF NEW.ownership_version <> 1 THEN
            RAISE EXCEPTION 'initial resource ownership version must be one';
        END IF;
    ELSIF prior_status = 'active'
        OR NEW.ownership_version <> prior_version + 1 THEN
        RAISE EXCEPTION 'resource ownership version must advance in order';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION gvai_authority.enforce_ownership_version_sequence()
    FROM PUBLIC;

CREATE TRIGGER resource_ownership_version_sequence
    BEFORE INSERT ON gvai_authority.resource_ownerships
    FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.enforce_ownership_version_sequence();

REVOKE ALL PRIVILEGES ON SCHEMA gvai_authority FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA gvai_authority FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA gvai_authority FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA gvai_authority FROM PUBLIC;

COMMIT;
