# Безопасность

Политика безопасности, актуальные риски и планы по их устранению.

## Текущие меры

| Область | Реализация |
|---|---|
| Хранение учетных записей | `domain.User` — только Argon2id-хэш (`password_hash`), DEK в wrapped-виде (`dek_wrapped`, `dek_iv`, `dek_kek_id`) |
| Токены доступа | `domain.AuthToken` — в БД только `token_hash` (unique) + `token_hint`; методы `isRevoked()` / `isExpired(now)` |
| Записи сейфа | `domain.VaultEntry` — `site_enc`, `login_enc`, `password_enc`, `notes_enc` (шифротекст) |
| Аудит | `domain.AuditEvent` — `details_json` только с нечувствительными метаданными |
| Схема БД | Flyway-миграция `db/migration/V1__init_schema.sql` (единственный источник схемы) |
| Конфигурация | `ddl-auto=validate`, секреты только из env (Task-01) |

## Реализованные меры защиты схемы (Task-02)

- Ограничения уникальности: `uk_users_username`, `uk_auth_tokens_token_hash`.
- FK: `fk_auth_tokens_user`, `fk_vault_entries_user` (ON DELETE CASCADE),
  `fk_audit_events_user` (nullable, ON DELETE SET NULL).
- Индексы: `idx_vault_entries_user_id`, `idx_audit_events_user_id`,
  `idx_audit_events_created_at`, `idx_auth_tokens_user_id`.
- Тесты проверяют схему и persistence-поведение
  (`FlywayMigrationIT`, `RepositoryIT`).

## Известные риски

### Secret Spraying (учтено в дизайне схемы)

Схема БД сознательно не позволяет получить какие-либо данные в открытом виде:
`site_enc` / `login_enc` / `password_enc` / `notes_enc` — шифротексты,
`password_hash` — Argon2id-хэш, `token_hash` — SHA-256 хэш.
Расшифровка возможна только в коде приложения при наличии DEK.

## Планируемые улучшения

- Ротация мастер-ключа (KEK) — Task-07.
- Хэширование токенов и revocation-механика — Task-03/04.
- Аудит-сервис поверх `AuditEventRepository` — Task-05.
