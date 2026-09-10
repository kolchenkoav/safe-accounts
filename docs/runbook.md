# Runbook безопасных счетов (safe-accounts)

Операционная шпаргалка дежурного/администратора. Подробности — в
`docs/deployment.md`, `docs/security.md`, `docs/key-rotation.md`,
`docs/backup-restore.md`.

## 1. Как посмотреть здоровье

```bash
# Общее состояние (liveness/readiness для оркестратора):
curl -fsS http://localhost:8080/actuator/health
# {"status":"UP"}
curl -fsS http://localhost:8080/actuator/health/liveness
curl -fsS http://localhost:8080/actuator/health/readiness

# Состояние контейнеров compose:
docker compose ps

# Метрики Prometheus (только агрегаты, без секретов):
curl -fsS http://localhost:8080/actuator/prometheus | head
```

Compose-healthcheck приложения уже построен на `/actuator/health`.
Остальные actuator-эндпоинты (`env`, `beans`, `mappings`, ...) закрыты
(denyAll), `show-details: never` — наружу ничего лишнего.

Если `status: DOWN` — проверьте, что контейнер БД здоров (`docker compose ps`,
healthcheck `pg_isready`) и что KEK доступен (приложение падает на старте без
мастер-ключа — это ожидаемое поведение).

## 2. Как посмотреть логи

```bash
docker compose logs app --tail=200 -f
docker compose logs db  --tail=100
```

Что можно и чего нельзя ожидать в логах (зафиксировано тестами и
`SensitiveDataMasker`):

- Разрешено: имена пользователей, key id и усеченный fingerprint KEK,
  счетчики rewrap, коды ошибок, IP (rate limiter).
- Запрещено и отсутствует: пароли, мастер-ключ, DEK, Bearer-токены,
  расшифрованные секреты; тела запросов не логируются.

Журнал аудита (бизнес-события) смотрите не в логах, а в БД/через API:

```bash
curl -s "http://localhost:8080/api/admin/audit?type=LOGIN_FAILURE&page=0&size=50" \
  -H "Authorization: Bearer $admin_token"
```

## 3. Как сделать бэкап

```bash
./scripts/backup.sh
# backups/safe_accounts_<db>_<YYYYMMDD>_<HHMMSS>.dump (pg_dump -Fc, права 0600)
```

Переменные: `COMPOSE_PROJECT_NAME`, `BACKUP_DIR`, `POSTGRES_DB`,
`POSTGRES_USER`. Полная инструкция, шифрование дампов (`age`/`gpg`) и правила
хранения KEK отдельно от дампов — `docs/backup-restore.md`.

## 4. Как восстановиться

```bash
# Приложение скрипт остановит сам на время восстановления:
./scripts/restore.sh backups/<файл>.dump          # с подтверждением
./scripts/restore.sh backups/<файл>.dump --force  # для автоматизации
```

Требования: тот же KEK (`VAULT_MASTER_KEY_BASE64`), тот же compose-проект.
**Обязательная проверка после восстановления**: прочитать контрольную запись
сейфа через API (`GET /api/vault/<id>?reveal=true`) или UI («Показать пароль»)
— механический успех `pg_restore` не считается успехом. Полный DR-сценарий на
чистой машине — `docs/backup-restore.md` §2.

## 5. Как отозвать токены

**Один пользователь отзывает свой текущий токен** (logout):

```bash
curl -X POST http://localhost:8080/api/auth/logout -H "Authorization: Bearer $token"
```

**Все токены пользователя** (при подозрении на кражу): администратор делает
сброс пароля — он отзывает все токены пользователя:

```bash
curl -X POST http://localhost:8080/api/admin/users/<userId>/reset-password \
  -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' \
  -d '{"newPassword":"<новый пароль ≥12 символов>"}'
```

Пользователь может сам отозвать остальные свои токены сменой пароля
(`POST /api/me/password` — текущий токен сохраняется, остальные отзываются).
Аудит: `TOKEN_REVOKED` / `USER_RESET_PASSWORD`.

## 6. Как создать администратора

**Вариант A — bootstrap при пустой БД** (первый запуск): задайте
`APP_ADMIN_USERNAME` и `APP_ADMIN_PASSWORD` в окружении; при старте на пустой
БД будет создан первый администратор с ролью `ROLE_ADMIN`. Повторный запуск
ничего не перезаписывает. Пароль не логируется.

**Вариант B — через админ-API** (уже есть администратор):

```bash
curl -X POST http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer $admin_token" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Str0ng-Passw0rd!","role":"ADMIN"}'
```

Доступ к `/api/admin/**` — только роль `ADMIN` (SecurityConfig +
`@PreAuthorize` + проверка в сервисе). Обычная регистрация
(`POST /api/auth/register`) всегда создает пользователя без админ-прав.

## 7. Как ротировать ключ

Кратко (полный процесс с проверками — `docs/key-rotation.md`):

1. `./scripts/generate-master-key.sh` — новый KEK.
2. Добавить в конфигурацию как активный
   (`APP_CRYPTO_KEYS_<N>_ID/SECRET_BASE64/ACTIVE=true`), **старый ключ
   не удалять** (`ACTIVE=false`).
3. `docker compose restart app`.
4. `POST /api/admin/crypto/rewrap-deks` (Bearer-токен администратора) —
   идемпотентно, повторный вызов возвращает `rewrappedUsers: 0`.
5. Проверить чтение контрольных записей (`reveal=true`).
6. Старый ключ удалить только после завершения перехода **и** истечения срока
   старых бэкапов.

Аудит ротации: `KEY_ROTATION_STARTED` / `KEY_ROTATION_COMPLETED` /
`KEY_ROTATION_FAILED` (только key id и счетчики).

## Быстрая справка по инцидентам

| Симптом | Действие | Раздел |
|---|---|---|
| Приложение не стартует | Проверить KEK (`VAULT_MASTER_KEY_*` / `APP_CRYPTO_KEYS_*`) и БД | §1, `deployment.md` |
| 429 на login/register | Ожидаемо: rate limit; проверить источник в аудите | §2, `threat-model.md` |
| Подозрение на кражу токена | Сброс пароля пользователя (отзывает все токены) | §5 |
| Подозрение на компрометацию KEK | Аварийная ротация ключа + отзыв токенов | §7, `key-rotation.md`, `security.md` |
| Потеря KEK | Восстановление из бэкапа ключа (отдельное хранилище) | `backup-restore.md` §3 |
