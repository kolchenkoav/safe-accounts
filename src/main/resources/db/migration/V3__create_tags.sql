-- Task-feat-name-tags: теги (tags) и связь с записями сейфа (vault_entry_tags).
-- Теги хранятся в открытом виде, per-user unique по name_lower.
-- Удаление пользователя и записи сейфа каскадно чистит связанные строки.
-- Удаление тега при наличии ссылок обрабатывается на уровне API (Task-tag-api).

CREATE TABLE tags (
    id          uuid PRIMARY KEY,
    user_id     uuid        NOT NULL,
    name        text        NOT NULL,
    name_lower  text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT fk_tags_user FOREIGN KEY (user_id)
        REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT ck_tags_name_len CHECK (char_length(name) BETWEEN 1 AND 64),
    CONSTRAINT ck_tags_name_lower_len CHECK (char_length(name_lower) BETWEEN 1 AND 64),
    CONSTRAINT ck_tags_name_format CHECK (name_lower = lower(name))
);
CREATE UNIQUE INDEX idx_tags_user_name_lower ON tags (user_id, name_lower);
CREATE INDEX idx_tags_user_id ON tags (user_id);

CREATE TABLE vault_entry_tags (
    vault_entry_id uuid NOT NULL,
    tag_id         uuid NOT NULL,
    PRIMARY KEY (vault_entry_id, tag_id),
    CONSTRAINT fk_vet_entry FOREIGN KEY (vault_entry_id)
        REFERENCES vault_entries (id) ON DELETE CASCADE,
    CONSTRAINT fk_vet_tag FOREIGN KEY (tag_id)
        REFERENCES tags (id) ON DELETE CASCADE
);
CREATE INDEX idx_vet_entry ON vault_entry_tags (vault_entry_id);
CREATE INDEX idx_vet_tag   ON vault_entry_tags (tag_id);