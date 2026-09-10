# Чек-лист безопасности safe-accounts

> Версия: Task-10. Дата актуализации — см. git-историю. Чек-лист подтверждается
> автоматизированными тестами (`src/test/java/com/example/safeaccounts/it/`),
> ссылки на тесты указаны в каждом пункте. Соответствие требованиям `AGENTS.md`.

## 1. Секреты не в коде

- [x] Мастер-ключ (KEK) задается только через переменные окружения / файлы секретов
      (`secrets/`, `docker-compose.secrets.yml`, `scripts/generate-master-key.sh`).
- [x] В отсутствие мастер-ключа в профиле, отличном от тестового, приложение
      падает на старте (проверка в `CryptoProperties`/`KeyManager`).
- [x] Тестовые фиксированные KEK существуют только в профиле `it`
      (`src/test/resources/application-it.yaml`), синтетические значения.
- [x] Пароль БД передается через секреты Docker (`docker-compose.secrets.yml`).
- [x] В репозитории нет секретов: `.env.example` содержит только шаблоны.
- [x] В миграциях Flyway нет секретных значений (`V1__init_schema.sql` — только схема).

## 2. Секреты не в логах

- [x] Логирование не включает: пароли пользователей, мастер-ключ, DEK,
      Bearer-токены, расшифрованные пароли записей (`AGENTS.md` §8).
- [x] `SensitiveDataMasker` маскирует секреты в сообщениях об ошибках
      (`ApiExceptionHandler`); unit-тесты `SensitiveDataMaskerTest`.
- [x] Аудит не пишет расшифрованные секреты — проверяется в `VaultApiIT.vaultEventsAreAuditedWithoutSecrets`.

## 3. Токены только в виде хэшей

- [x] В `auth_tokens` хранится только SHA-256 хэш (`token_hash`), сырой токен
      не хранится. Тест: `SecurityChecksIT.authTokensTableHasNoRawTokens`.
- [x] Токен показывается клиенту один раз при выпуске (`TokenResponse`).
- [x] Поддержаны ревокация (logout) и отзыв всех токенов пользователя
      (смена пароля). Тесты: `SecurityChecksIT.revokedTokenDoesNotWork`,
      `AuthFlowIT.passwordChangeRevokesOtherTokensButKeepsCurrent`.

## 4. Секреты в БД только зашифрованы

- [x] Шифрование AES-256-GCM, случайный IV через `SecureRandom` на каждую
      операцию; deterministic/ECB не используются
      (unit-тесты `AesGcmCryptoServiceTest`, `KeyManagerTest`).
- [x] `vault_entries` — все чувствительные поля (сайт, логин, пароль, примечание)
      в шифротексте; plaintext отсутствует.
      Тесты: `SecurityChecksIT.vaultEntriesTableHasNoPlaintextValues`,
      `SecurityChecksIT.noPlaintextAfterUpdateAndAcrossMultipleEntries`,
      `VaultApiIT.databaseStoresOnlyCiphertexts`.
- [x] `users` — пароль только Argon2id-хэш, DEK только wrapped KEK-ом.
      Тест: `SecurityChecksIT.usersTableHasNoPlaintextPasswordOrDek`.
- [x] DEK уникален для каждого пользователя; DEK хранится только wrapped.

## 5. Доступ к чужим данным невозможен

- [x] Все операции над записями проверяют владельца (owner-scoping в
      `VaultService`); чужая запись неотличима от несуществующей (единый 404).
- [x] E2E-изоляция: второй пользователь не имеет доступа к записям первого.
      Тесты: `E2eFlowIT.secondUserHasNoAccessToFirstUsersEntries`,
      `E2eFlowIT.tokensAreBoundToTheirOwnUserOnly`,
      `VaultApiIT.foreignEntryIsInaccessibleAndIndistinguishableFromMissing`.
- [x] Ошибки авторизации не раскрывают лишнего: 404/403/401 без стектрейсов и
      без данных чужой записи. Тест: `SecurityChecksIT.authorizationErrorsDoNotLeakInformation`.
- [x] Административные операции — только роль `ADMIN`
      (`SecurityConfig`, `/api/admin/**` → `hasRole("ADMIN")`).
      Тест: `SecurityChecksIT.userRoleCannotAccessAdminEndpoints`.
- [x] Списки записей не возвращают пароли по умолчанию; reveal — только в
      детальном запросе владельцу (`VaultApiIT.listDoesNotContainPasswordsOrNotes`).

## 6. Аудит

- [x] Аудит фиксирует: вход, неудачный вход, выпуск токена, отзыв токена,
      создание/изменение/удаление записи сейфа, административные действия,
      ротацию ключей (`AuditService`; типы `LOGIN_*`, `TOKEN_*`, `USER_*`,
      `SECRET_*`, `KEY_ROTATION_*`).
- [x] В аудит не пишутся расшифрованные секреты.
- [x] Аудит доступен для анализа через админ-API с фильтрами (`/api/admin/audit`).

## 7. Резервные копии

- [x] Скрипты `scripts/backup.sh` и `scripts/restore.sh`.
- [x] Инструкция по резервному копированию и восстановлению: `docs/backup-restore.md`.
- [x] Рекомендация: шифровать бэкапы и хранить KEK отдельно от бэкапа БД
      (утечка бэкапа без KEK не раскрывает данные).

## 8. Ротация ключей

- [x] Поддержка нескольких KEK: старый ключ неактивен (только расшифровка),
      новый активен (шифрование) — `CryptoProperties` (`keys[n].active`).
- [x] Перепаковка DEK пользователей под новый ключ:
      `POST /api/admin/crypto/rewrap-deks` (Task-06, только ADMIN).
- [x] Тесты перешифрования: `CryptoIntegrationIT`, `AdminApiIT`.
- [x] Процедура ротации задокументирована (см. `Plan.md`, Task-06/12).

## 9. Прочие контуры

- [x] Rate limiting по IP для login/register (`RateLimiter`, `RateLimitFilter`, 429 RFC 7807).
- [x] Security headers (`SecurityHeadersFilter`).
- [x] Actuator: наружу только health/info/prometheus; остальное denyAll
      (`SecurityChecksIT` + `ObservabilitySecurityIT`).
- [x] Swagger/OpenAPI только в dev-профиле (`ProdApiDocsGuard`).
- [x] Ошибки в формате RFC 7807 ProblemDetail, без стектрейсов клиенту.
- [x] Валидация входящих данных через `jakarta.validation`.
- [x] Контейнер работает от непривилегированного пользователя; образ многоэтапный.

## 10. Веб-интерфейс (Task-11)

- [x] Веб-часть отделена от API: отдельные filter chain в `SecurityConfig`
      (API — stateless Bearer, веб — серверная сессия).
- [x] CSRF-защита включена для всех веб-форм; POST без токена отклоняется (403).
      Тест: `WebUiIT.postWithoutCsrfTokenIsRejected`.
- [x] Токены доступа не хранятся в браузере: Bearer-токены в веб-сессию не
      выдаются, сессия — HttpOnly cookie.
- [x] Список записей не показывает пароль; пароль — только по явному действию
      пользователя (POST `/web/entries/{id}/reveal`, факт — в аудите).
      Тест: `WebUiIT.fullCrudCycleThroughWeb`.
- [x] Старый пароль не выносится в HTML при редактировании (вводится заново).
- [x] Чужие записи недоступны из веба (единые owner-scoped правила `VaultService`).
      Тест: `WebUiIT.otherUsersEntriesNotAccessible`.
- [x] Пароли форм не логируются (в `WebLoginController`/`WebVaultController`
      логируется только факт операции, без значений).
- [x] Веб-интерфейс не ломает API. Тест: `WebUiIT.apiStillWorksWithBearerTokenWhileWebUsesSession`.

## Соответствие критериям приемки Task-10

| Критерий | Статус |
|---|---|
| Все сквозные тесты проходят | ✅ `E2eFlowIT`, `SecurityChecksIT` (см. `mvn verify`) |
| Подтверждена изоляция пользователей | ✅ `E2eFlowIT.secondUserHasNoAccessToFirstUsersEntries` и др. |
| Подтверждено отсутствие plaintext-секретов в БД | ✅ `SecurityChecksIT.vaultEntriesTableHasNoPlaintextValues`, `usersTableHasNoPlaintextPasswordOrDek`, `authTokensTableHasNoRawTokens` |
| Чек-лист безопасности заполнен и актуален | ✅ этот документ |

## Соответствие критериям приемки Task-11

| Критерий | Статус |
|---|---|
| Можно войти через браузер | ✅ `WebUiIT.loginSuccessCreatesSessionAndRedirectsToEntries`, `WebUiIT.loginFailureShowsNeutralError` |
| Можно создать/посмотреть/изменить/удалить запись | ✅ `WebUiIT.fullCrudCycleThroughWeb` |
| Чужие записи недоступны | ✅ `WebUiIT.otherUsersEntriesNotAccessible` |
| CSRF защита работает | ✅ `WebUiIT.postWithoutCsrfTokenIsRejected` |
| Веб-интерфейс не ломает API | ✅ `WebUiIT.apiStillWorksWithBearerTokenWhileWebUsesSession` |
