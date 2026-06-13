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

CREATE TABLE IF NOT EXISTS vault.roles (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text NOT NULL UNIQUE,
    description text,
    is_admin    boolean NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO vault.roles (name, description, is_admin)
VALUES ('admin', 'Full superuser: manage roles/tokens and all secrets', true)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS vault.admin_tokens (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name          text NOT NULL UNIQUE,
    role_id       uuid REFERENCES vault.roles(id) ON DELETE RESTRICT,
    token_sha256  bytea NOT NULL UNIQUE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,
    revoked_at    timestamptz,
    CONSTRAINT admin_tokens_fingerprint_len CHECK (octet_length(token_sha256) = 32)
);

CREATE TABLE IF NOT EXISTS vault.role_permissions (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_id      uuid NOT NULL REFERENCES vault.roles(id) ON DELETE CASCADE,
    action       text NOT NULL CHECK (action IN ('create', 'update', 'delete', 'rotate', '*')),
    path_pattern text NOT NULL
);

CREATE INDEX IF NOT EXISTS role_permissions_role_idx ON vault.role_permissions (role_id);

CREATE TABLE IF NOT EXISTS vault.auth_lockouts (
    client_ip    inet PRIMARY KEY,
    failures     integer NOT NULL DEFAULT 0,
    window_start timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz
);

CREATE TABLE IF NOT EXISTS vault.secrets (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name               text NOT NULL UNIQUE,
    kind               vault.secret_kind NOT NULL,
    format             text NOT NULL DEFAULT 'opaque' CHECK (format IN ('opaque', 'userpass')),
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

ALTER TABLE vault.roles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.roles            FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.role_permissions FORCE  ROW LEVEL SECURITY;
ALTER TABLE vault.auth_lockouts    ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault.auth_lockouts    FORCE  ROW LEVEL SECURITY;
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
    FOREACH tbl IN ARRAY ARRAY['secrets', 'secret_versions', 'admin_tokens', 'rotation_jobs', 'audit_log', 'roles', 'role_permissions', 'auth_lockouts']
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

CREATE OR REPLACE FUNCTION vault.add_token(p_name text, p_role text, p_sha256 bytea)
RETURNS void LANGUAGE plpgsql AS $addtok$
DECLARE
    rid uuid;
BEGIN
    SELECT id INTO rid FROM vault.roles WHERE name = p_role;
    IF rid IS NULL THEN
        RAISE EXCEPTION 'role % does not exist', p_role;
    END IF;
    INSERT INTO vault.admin_tokens (name, role_id, token_sha256)
    VALUES (p_name, rid, p_sha256);
END
$addtok$;

CREATE OR REPLACE FUNCTION vault.record_auth_failure(
    p_ip inet, p_max integer, p_window_secs bigint, p_lockout_secs bigint)
RETURNS void LANGUAGE plpgsql AS $rec$
DECLARE
    cur_failures integer;
    cur_window   timestamptz;
    new_failures integer;
BEGIN
    SELECT failures, window_start INTO cur_failures, cur_window
    FROM vault.auth_lockouts WHERE client_ip = p_ip FOR UPDATE;

    IF NOT FOUND THEN
        INSERT INTO vault.auth_lockouts (client_ip, failures, window_start, locked_until)
        VALUES (p_ip, 1, now(),
            CASE WHEN 1 >= p_max THEN now() + make_interval(secs => p_lockout_secs) ELSE NULL END);
        RETURN;
    END IF;

    IF cur_window < now() - make_interval(secs => p_window_secs) THEN
        UPDATE vault.auth_lockouts
        SET failures = 1, window_start = now(),
            locked_until = CASE WHEN 1 >= p_max
                THEN now() + make_interval(secs => p_lockout_secs) ELSE NULL END
        WHERE client_ip = p_ip;
    ELSE
        new_failures := cur_failures + 1;
        UPDATE vault.auth_lockouts
        SET failures = new_failures,
            locked_until = CASE WHEN new_failures >= p_max
                THEN now() + make_interval(secs => p_lockout_secs) ELSE locked_until END
        WHERE client_ip = p_ip;
    END IF;
END
$rec$;
"#,
    name = "vault_bootstrap",
);
