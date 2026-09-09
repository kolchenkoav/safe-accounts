-- Task-02: начальная схема БД (PostgreSQL 16).
-- Все индексы и ограничения заданы явно. Секретов в комментариях нет.
-- Схема полностью совпадает с tasks/Task-02.md.

CREATE TABLE users (
    id              uuid PRIMARY KEY,
    username        text        NOT NULL,
    password_hash   text        NOT NULL,
    role            text        NOT NULL DEFAULT 'ROLE_USER',
    enabled         boolean     NOT NULL DEFAULT true,
    failed_attempts integer     NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    dek_wrapped     text        NOT NULL,
    dek_iv          text        NOT NULL,
    dek_kek_id      text        NOT NULL,
    created_at      timestamptz,
    updated_at      timestamptz,
    version         bigint,
    CONSTRAINT uk_users_username UNIQUE (username)
);

CREATE TABLE auth_tokens (
    id           uuid PRIMARY KEY,
    user_id      uuid        NOT NULL,
    token_hash   text        NOT NULL,
    token_hint   text        NOT NULL,
    user_agent   text,
    ip_address   text,
    created_at   timestamptz,
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz,
    version      bigint,
    CONSTRAINT fk_auth_tokens_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT uk_auth_tokens_token_hash UNIQUE (token_hash)
);
CREATE INDEX idx_auth_tokens_user_id ON auth_tokens (user_id);

CREATE TABLE vault_entries (
    id           uuid PRIMARY KEY,
    user_id      uuid        NOT NULL,
    site_enc     text        NOT NULL,
    login_enc    text        NOT NULL,
    password_enc text        NOT NULL,
    notes_enc    text,
    created_at   timestamptz,
    updated_at   timestamptz,
    version      bigint,
    CONSTRAINT fk_vault_entries_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE
);
CREATE INDEX idx_vault_entries_user_id ON vault_entries (user_id);

CREATE TABLE audit_events (
    id          uuid PRIMARY KEY,
    user_id     uuid,
    token_id    uuid,
    type        text        NOT NULL,
    object_type text,
    object_id   text,
    ip_address  text,
    user_agent  text,
    details_json jsonb,
    created_at  timestamptz,
    CONSTRAINT fk_audit_events_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE SET NULL
);
CREATE INDEX idx_audit_events_user_id ON audit_events (user_id);
CREATE INDEX idx_audit_events_created_at ON audit_events (created_at);
