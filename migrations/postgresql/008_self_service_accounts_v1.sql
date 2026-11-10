BEGIN;

DO $guard$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_namespace AS n
        JOIN pg_catalog.pg_roles AS r ON r.oid=n.nspowner
        WHERE n.nspname='gvai_authority' AND r.rolname=current_user
          AND NOT r.rolsuper AND NOT r.rolbypassrls
    ) THEN
        RAISE EXCEPTION 'self-service accounts require the non-superuser authority owner';
    END IF;
    IF pg_catalog.to_regclass('gvai_authority.billing_customers') IS NULL
        OR pg_catalog.to_regprocedure(
            'gvai_authority.reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)'
        ) IS NULL
        OR pg_catalog.to_regclass('gvai_authority.customer_accounts') IS NOT NULL THEN
        RAISE EXCEPTION 'self-service accounts require baseline 001-004 and no prior install';
    END IF;
    IF (
        SELECT count(*) FROM pg_catalog.pg_attribute AS a
        WHERE a.attrelid='gvai_authority.billing_customers'::regclass AND NOT a.attisdropped
          AND a.attname IN ('checkout_started_at','checkout_session_id','checkout_url')
    ) <> 3 THEN
        RAISE EXCEPTION 'self-service accounts require checkout migration 007';
    END IF;
END;
$guard$;

-- Owner-only control plane. Stores only an HMAC verifier of the account token;
-- the evaluation runtime role receives no privilege on this table.
CREATE TABLE gvai_authority.customer_accounts (
    account_ref bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_ref bigint NOT NULL UNIQUE
        REFERENCES gvai_authority.billing_customers (tenant_ref),
    token_verifier bytea NOT NULL UNIQUE CHECK (octet_length(token_verifier) = 32),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    key_id text UNIQUE REFERENCES gvai_authority.customer_credentials (key_id),
    key_claimed_at timestamptz,
    CHECK ((key_id IS NULL) = (key_claimed_at IS NULL))
);

-- The one-time key claim is a one-way latch: it can be set once and never cleared.
CREATE FUNCTION gvai_authority.customer_account_guard_v1()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, gvai_authority, pg_temp
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'customer account history is immutable';
    END IF;
    IF NEW.key_id IS NOT NULL AND (TG_OP = 'INSERT' OR OLD.key_id IS NULL) AND NOT EXISTS (
        SELECT 1 FROM gvai_authority.customer_credentials AS c
        WHERE c.key_id = NEW.key_id AND c.tenant_ref = NEW.tenant_ref
    ) THEN
        RAISE EXCEPTION 'account key must belong to the account tenant';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF NEW.account_ref <> OLD.account_ref OR NEW.tenant_ref <> OLD.tenant_ref
        OR NEW.token_verifier <> OLD.token_verifier OR NEW.created_at <> OLD.created_at
        OR (OLD.key_id IS NOT NULL AND (
            NEW.key_id IS DISTINCT FROM OLD.key_id
            OR NEW.key_claimed_at IS DISTINCT FROM OLD.key_claimed_at))
        OR (OLD.status = 'disabled' AND NEW.status <> 'disabled') THEN
        RAISE EXCEPTION 'customer account rewrite rejected';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER customer_account_guard BEFORE INSERT OR UPDATE OR DELETE
    ON gvai_authority.customer_accounts FOR EACH ROW
    EXECUTE FUNCTION gvai_authority.customer_account_guard_v1();

REVOKE ALL ON TABLE gvai_authority.customer_accounts FROM PUBLIC;
REVOKE ALL ON FUNCTION gvai_authority.customer_account_guard_v1() FROM PUBLIC;

COMMIT;
