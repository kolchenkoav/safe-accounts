# safe-accounts

Серверное приложение-сейф для надёжного хранения учётных записей (сайт, логин,
пароль, примечание) на **Java 21 / Spring Boot 3.3.x / PostgreSQL 16 / Flyway**.

Безопасность: AES-256-GCM для секретов, Argon2id для паролей, Bearer-токены
(в БД только хэш), шифрование DEK мастер-ключом KEK, аудит операций.

## Требования

- JDK 21+
- Docker / Docker Compose (для локального PostgreSQL или полного запуска)
- `openssl` (для генерации мастер-ключа)

## Быстрый старт

1. Скопируйте пример окружения и заполните значения:

   ```bash
   cp .env.example .env
   ```

2. Сгенерируйте мастер-ключ (KEK):

   ```bash
   ./scripts/generate-master-key.sh
   ```

   Вставьте полученное значение в `VAULT_MASTER_KEY_BASE64` в `.env`.
   Приложение не стартует без мастер-ключа — это сделано намеренно.

3. Соберите и запустите:

   ```bash
   ./mvnw spring-boot:run
   ```

4. Проверка здоровья:

   ```bash
   curl http://localhost:8080/actuator/health
   # {"status":"UP"}
   ```

## Конфигурация

Все секреты читаются только из переменных окружения или файлов секретов
(никогда — из кода, репозитория или логов).

| Переменная | Описание |
|---|---|
| `POSTGRES_HOST` | Хост PostgreSQL (по умолчанию `localhost`) |
| `POSTGRES_PORT` | Порт PostgreSQL (по умолчанию `5432`) |
| `POSTGRES_DB` | Имя БД (по умолчанию `safe_accounts`) |
| `POSTGRES_USER` | Пользователь БД (обязателен) |
| `POSTGRES_PASSWORD` | Пароль БД (обязателен) |
| `VAULT_MASTER_KEY_BASE64` | Мастер-ключ KEK в base64 (32 байта; алиас `APP_CRYPTO_MASTER_KEY_BASE64`) |
| `VAULT_MASTER_KEY_FILE` | Либо путь к файлу с ключом base64 |
| `APP_CRYPTO_KEYS_N_ID` | Ротация: идентификатор KEK N (не секрет) |
| `APP_CRYPTO_KEYS_N_SECRET_BASE64` | Ротация: материал KEK N в base64 |
| `APP_CRYPTO_KEYS_N_ACTIVE` | Ротация: активный KEK ровно один (`true`/`false`) |
| `APP_ADMIN_USERNAME` | Bootstrap: имя первого администратора (создается только на пустой БД) |
| `APP_ADMIN_PASSWORD` | Bootstrap: пароль первого администратора (не логируется) |
| `SERVER_PORT` | Порт приложения (по умолчанию `8080`) |
| `SPRING_PROFILES_ACTIVE` | Профиль: `default` или `docker` |

Требуется ровно один источник мастер-ключа (`VAULT_MASTER_KEY_BASE64` **или**
`VAULT_MASTER_KEY_FILE`); при отсутствии обоих приложение падает на старте.

### Криптомодуль (KEK/DEK)

- Каждому пользователю генерируется собственный DEK (AES-256).
- DEK хранится в БД только в wrapped-виде (`users.dek_wrapped`, `dek_iv`,
  `dek_kek_id`), обернутый мастер-ключом KEK (AES-256-GCM).
- Секреты сейфа шифруются DEK пользователя: `base64(iv \|\| ciphertext \|\| tag)`,
  IV — 12 байт, `SecureRandom`, уникальный на каждую операцию.
- Поддерживается ротация KEK: в логах — только key id и усеченный SHA-256
  fingerprint; материал ключей никогда не логируется.
- В логах запрещены материал ключей и расшифрованные секреты; ошибки
  расшифровки возвращают нейтральное сообщение без деталей.

## Профили

- `default` — локальный запуск (PostgreSQL на `localhost`).
- `docker` — запуск в контейнерах (PostgreSQL на сервисе `postgres`).

## Docker Compose

```bash
docker compose up -d
```

Состав: приложение, PostgreSQL 16 (volume для данных), секреты БД и
мастер-ключ передаются через переменные окружения из `.env`.

## Полезные команды

| Команда | Описание |
|---|---|
| `./mvnw clean compile` | Компиляция |
| `./mvnw test` | Unit- и интеграционные тесты |
| `./mvnw verify` | Полная сборка с проверками |
| `./mvnw spring-boot:run` | Локальный запуск приложения |
| `./scripts/generate-master-key.sh` | Генерация нового мастер-ключа |

## API

- OpenAPI: `http://localhost:8080/api-docs`
- Swagger UI: `http://localhost:8080/swagger-ui.html`
- Health: `http://localhost:8080/actuator/health` (остальные actuator-эндпоинты закрыты)

### Аутентификация (Task-04)

| Метод | Путь | Описание |
|---|---|---|
| `POST` | `/api/auth/register` | Регистрация (имя 3–64 `[a-z0-9._-]`, пароль ≥ 12 символов) |
| `POST` | `/api/auth/login` | Логин; возвращает Bearer-токен (показывается один раз) |
| `POST` | `/api/auth/logout` | Отзыв текущего Bearer-токена |
| `GET` | `/api/me` | Данные текущего пользователя |
| `POST` | `/api/me/password` | Смена пароля (все токены, кроме текущего, отзываются) |

Пример:

```bash
token=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Str0ng-Passw0rd!"}' | jq -r .accessToken)
curl http://localhost:8080/api/me -H "Authorization: Bearer $token"
```

- Токен: `sat_` + base64url, ≥ 256 бит энтропии (`SecureRandom`); срок жизни 24 ч.
- В БД хранится только SHA-256 хэш токена; пароли — Argon2id (m=64МиБ, t=3, p=1).
- Защита от перебора: после 5 неудачных входов аккаунт блокируется на 15 минут.
- Аудит: LOGIN_SUCCESS/LOGIN_FAILURE, TOKEN_ISSUED/TOKEN_REVOKED,
  USER_CREATED/USER_DISABLED/USER_ENABLED, PASSWORD_CHANGED (без секретов).
- Ошибки — RFC 7807 ProblemDetail без стектрейсов.

### Сейф (Task-05)

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/vault?page=0&size=20` | Пагинированный список записей (сайт, логин, метаданные; БЕЗ пароля и примечания) |
| `POST` | `/api/vault` | Создание записи: `site`, `login`, `password`, `notes?` |
| `GET` | `/api/vault/{id}` | Детальный просмотр (без пароля) |
| `GET` | `/api/vault/{id}?reveal=true` | Детальный просмотр с расшифрованным паролем (факт reveal пишется в аудит) |
| `PUT` | `/api/vault/{id}` | Обновление записи (все поля перешифровываются) |
| `DELETE` | `/api/vault/{id}` | Удаление записи |

Пример:

```bash
curl -X POST http://localhost:8080/api/vault \
  -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"site":"https://example.com","login":"alice","password":"Entry-Pass-123!","notes":"work"}'
curl "http://localhost:8080/api/vault/<id>?reveal=true" -H "Authorization: Bearer $token"
```

- Все чувствительные поля (site, login, password, notes) шифруются AES-256-GCM
  персональным DEK владельца; в БД (`vault_entries.*_enc`) plaintext отсутствует.
- Доступ только владельцу: чужая запись неотличима от несуществующей (единый 404).
- Валидация: site/login ≤ 2048, password ≤ 4096, notes ≤ 8192 символов.
- Аудит: SECRET_CREATED / SECRET_UPDATED / SECRET_DELETED / SECRET_REVEALED
  (только идентификаторы записей, без секретов).
- Ошибка расшифровки возвращает нейтральный ProblemDetail без деталей.

## Безопасность

Полные правила проекта см. в `AGENTS.md`. Ключевые моменты:

- Секреты запрещено хранить в коде, репозитории, логах, миграциях, артефактах сборки.
- В логи запрещено писать пароли, мастер-ключ, DEK, токены, расшифрованные пароли.
- `.env` добавлен в `.gitignore`; в репозитории — только `.env.example` с плейсхолдерами.
- `spring.jpa.hibernate.ddl-auto=validate` — схема меняется только миграциями Flyway.
- Списки записей не возвращают пароли; расшифровка — только в явном детальном запросе.
