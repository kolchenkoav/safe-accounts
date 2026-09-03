# Task-02: Flyway, схема БД и persistence layer

## Цель
Создать структуру базы данных и слой доступа к данным.

## Результат
- Есть миграции Flyway
- Есть JPA-сущности
- Есть репозитории
- Есть базовые интеграционные тесты на PostgreSQL через Testcontainers

## Требования к схеме
Создать таблицы:

### `users`
- `id uuid` PK
- `username text` unique not null
- `password_hash text` not null
- `role text` not null default `ROLE_USER`
- `enabled boolean` not null default true
- `failed_attempts int` not null default 0
- `locked_until timestamptz`
- `dek_wrapped text` not null
- `dek_iv text` not null
- `dek_kek_id text` not null
- `created_at timestamptz`
- `updated_at timestamptz`
- `version bigint`

### `auth_tokens`
- `id uuid` PK
- `user_id uuid` FK to users, on delete cascade
- `token_hash text` unique not null
- `token_hint text` not null
- `user_agent text`
- `ip_address text`
- `created_at timestamptz`
- `expires_at timestamptz`
- `last_used_at timestamptz`
- `revoked_at timestamptz`
- `version bigint`

### `vault_entries`
- `id uuid` PK
- `user_id uuid` FK to users, on delete cascade
- `site_enc text` not null
- `login_enc text` not null
- `password_enc text` not null
- `notes_enc text`
- `created_at timestamptz`
- `updated_at timestamptz`
- `version bigint`

### `audit_events`
- `id uuid` PK
- `user_id uuid` nullable FK to users
- `token_id uuid` nullable
- `type text` not null
- `object_type text`
- `object_id text`
- `ip_address text`
- `user_agent text`
- `details_json jsonb`
- `created_at timestamptz`

## Обязательные индексы
- `vault_entries(user_id)`
- `audit_events(user_id)`
- `audit_events(created_at)`
- `auth_tokens(user_id)`

## Требования к коду
1. Создать сущности:
    - `User`
    - `AuthToken`
    - `VaultEntry`
    - `AuditEvent`
2. Создать репозитории:
    - `UserRepository`
    - `AuthTokenRepository`
    - `VaultEntryRepository`
    - `AuditEventRepository`
3. Использовать `UUID` как идентификатор.
4. Включить оптимистичную блокировку через `@Version` там, где нужно.
5. Настроить `spring.jpa.hibernate.ddl-auto=validate`.
6. Flyway должен быть единственным источником схемы.

## Тесты
- Поднять PostgreSQL через Testcontainers.
- Проверить применение миграций.
- Проверить сохранение и чтение сущностей.
- Проверить ограничения уникальности и внешние ключи.

## Критерии приемки
1. `flyway migrate` проходит успешно.
2. Hibernate валидирует схему без ошибок.
3. Интеграционные тесты проходят.
4. В миграциях нет реальных секретов.
5. Схема соответствует требованиям безопасности.