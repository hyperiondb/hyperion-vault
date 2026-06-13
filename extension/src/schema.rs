use pgrx::prelude::*;

extension_sql!(
    r#"
CREATE SCHEMA IF NOT EXISTS vault;

DO $bootstrap$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_type t
        JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = 'secret_kind' AND n.nspname = 'vault'
    ) THEN
        CREATE TYPE vault.secret_kind AS ENUM ('manual', 'automatic');
    END IF;
END
$bootstrap$;

CREATE TABLE IF NOT EXISTS vault.admin_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    token_sha256  bytea NOT NULL UNIQUE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    CONSTRAINT admin_tokens_fingerprint_len CHECK (octet_length(token_sha256) = 32)
);

CREATE TABLE IF NOT EXISTS vault.secrets (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name               text NOT NULL UNIQUE,
    kind               vault.secret_kind NOT NULL,
    description        text,
    rotation_interval  interval,
    grace_period       interval NOT NULL DEFAULT '0 seconds',
    current_version    integer NOT NULL DEFAULT 0,
    next_rotation_at   timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT secrets_automatic_needs_interval
        CHECK (kind <> 'automatic' OR rotation_interval IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS vault.secret_versions (
    secret_id    uuid NOT NULL REFERENCES vault.secrets(id) ON DELETE CASCADE,
    version      integer NOT NULL,
    kms_key_id   text NOT NULL,
    wrapped_dek  bytea NOT NULL,
    nonce        bytea NOT NULL,
    ciphertext   bytea NOT NULL,
    aad          bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    PRIMARY KEY (secret_id, version)
);

CREATE INDEX IF NOT EXISTS secret_versions_active_idx
    ON vault.secret_versions (secret_id) WHERE expires_at IS NULL;

CREATE TABLE IF NOT EXISTS vault.rotation_jobs (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    secret_id    uuid NOT NULL REFERENCES vault.secrets(id) ON DELETE CASCADE,
    enqueued_at  timestamptz NOT NULL DEFAULT now(),
    claimed_at   timestamptz,
    claimed_by   text,
    completed_at timestamptz,
    error        text
);

CREATE INDEX IF NOT EXISTS rotation_jobs_open_idx
    ON vault.rotation_jobs (secret_id) WHERE completed_at IS NULL;

CREATE TABLE IF NOT EXISTS vault.audit_log (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT now(),
    actor        text,
    client_ip    inet,
    action       text NOT NULL,
    secret_name  text,
    outcome      text NOT NULL,
    detail       jsonb
);

CREATE INDEX IF NOT EXISTS audit_log_at_idx ON vault.audit_log (at DESC);

REVOKE ALL ON SCHEMA vault FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA vault FROM PUBLIC;

ALTER TABLE vault.admin_tokens     ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.admin_tokens     FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.secrets          ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.secrets          FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.secret_versions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.secret_versions  FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.rotation_jobs    ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.rotation_jobs    FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.audit_log        ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.audit_log        FORCE  ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION vault.grant_service_role(role_name text)
RETURNS void LANGUAGE plpgsql AS $grant$
DECLARE
    tbl text;
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA vault TO %I', role_name);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA vault TO %I', role_name);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA vault TO %I', role_name);
    EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vault TO %I', role_name);
    FOREACH tbl IN ARRAY ARRAY['secrets', 'secret_versions', 'admin_tokens', 'rotation_jobs', 'audit_log']
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS vault_service_rw ON vault.%I', tbl);
        EXECUTE format(
            'CREATE POLICY vault_service_rw ON vault.%I FOR ALL TO %I USING (true) WITH CHECK (true)',
            tbl, role_name);
    END LOOP;
END
$grant$;

CREATE OR REPLACE FUNCTION vault.enqueue_due_rotations()
RETURNS integer LANGUAGE sql AS $enqueue$
    WITH inserted AS (
        INSERT INTO vault.rotation_jobs (secret_id)
        SELECT s.id
        FROM vault.secrets s
        WHERE s.kind = 'automatic'
          AND s.next_rotation_at IS NOT NULL
          AND s.next_rotation_at <= now()
          AND NOT EXISTS (
              SELECT 1 FROM vault.rotation_jobs j
              WHERE j.secret_id = s.id AND j.completed_at IS NULL)
        RETURNING 1)
    SELECT count(*)::integer FROM inserted;
$enqueue$;

CREATE OR REPLACE FUNCTION vault.expire_grace_versions()
RETURNS integer LANGUAGE sql AS $expire$
    WITH deleted AS (
        DELETE FROM vault.secret_versions
        WHERE expires_at IS NOT NULL AND expires_at <= now()
        RETURNING 1)
    SELECT count(*)::integer FROM deleted;
$expire$;

CREATE OR REPLACE FUNCTION vault.status()
RETURNS jsonb LANGUAGE sql AS $status$
    SELECT jsonb_build_object(
        'in_recovery',        pg_is_in_recovery(),
        'secrets',            (SELECT count(*) FROM vault.secrets),
        'automatic',          (SELECT count(*) FROM vault.secrets WHERE kind = 'automatic'),
        'open_rotation_jobs', (SELECT count(*) FROM vault.rotation_jobs WHERE completed_at IS NULL),
        'active_versions',    (SELECT count(*) FROM vault.secret_versions WHERE expires_at IS NULL),
        'grace_versions',     (SELECT count(*) FROM vault.secret_versions WHERE expires_at IS NOT NULL)
    );
$status$;
"#,
    name = "vault_bootstrap",
);
