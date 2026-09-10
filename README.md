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

5. Веб-интерфейс (Task-11): откройте `http://localhost:8080/` — войдите
   пользователем, созданным через `POST /api/auth/register` (или через
   админ-API). Работа с сейфом: список/создание/просмотр/изменение/удаление
   записей; пароль отображается только по кнопке «Показать пароль».

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
| `POSTGRES_PASSWORD_FILE` | Альтернатива: файл с паролем БД (Docker secrets, читает entrypoint) |
| `VAULT_MASTER_KEY_BASE64` | Мастер-ключ KEK в base64 (32 байта; алиас `APP_CRYPTO_MASTER_KEY_BASE64`) |
| `VAULT_MASTER_KEY_FILE` | Либо путь к файлу с ключом base64 |
| `APP_CRYPTO_KEYS_N_ID` | Ротация: идентификатор KEK N (не секрет) |
| `APP_CRYPTO_KEYS_N_SECRET_BASE64` | Ротация: материал KEK N в base64 |
| `APP_CRYPTO_KEYS_N_ACTIVE` | Ротация: активный KEK ровно один (`true`/`false`) |
| `APP_ADMIN_USERNAME` | Bootstrap: имя первого администратора (создается только на пустой БД) |
| `APP_ADMIN_PASSWORD` | Bootstrap: пароль первого администратора (не логируется) |
| `SERVER_PORT` | Порт приложения (по умолчанию `8080`) |
| `SPRING_PROFILES_ACTIVE` | Профиль: `default`, `docker` или `dev` |
| `APP_RATE_LIMIT_WINDOW_SECONDS` | Task-09: окно rate limiter'а в секундах (по умолчанию `60`) |
| `APP_RATE_LIMIT_MAX_REQUESTS` | Task-09: максимум запросов на IP за окно (по умолчанию `10`) |
| `APP_HSTS_ENABLED` | Task-09: Strict-Transport-Security (`true` за TLS-терминацией) |
| `APP_API_DOCS_ENABLED` | Task-09: Swagger/OpenAPI (`true` только в dev) |
| `APP_DEV_PROFILE` | Task-09: dev-профиль (открывает Swagger; в проде — запрещено) |

Требуется ровно один источник мастер-ключа (`VAULT_MASTER_KEY_BASE64` **или**
`VAULT_MASTER_KEY_FILE`); при отсутствии обоих приложение падает на старте.

### Веб-интерфейс (Task-11, опциональный)

Встроенный минимальный веб-интерфейс: `http://localhost:8080/` (редирект на
`/web/login`), страницы:

| Путь | Описание |
|---|---|
| `/web/login` | Вход (GET форма, POST обработка) |
| `/web/entries` | Список записей (без паролей) |
| `/web/entries/new` | Создание записи |
| `/web/entries/{id}` | Просмотр (пароль — только по кнопке «Показать пароль») |
| `/web/entries/{id}/edit` | Изменение записи |
| POST `/web/entries/{id}/delete` | Удаление записи |
| `/logout` | Выход (инвалидация сессии) |

Безопасность:
- Аутентификация — серверная HTTP-сессия (HttpOnly cookie); Bearer-токены
  в браузер не выдаются и в `localStorage` не хранятся.
- CSRF-защита включена для всех веб-форм (Spring Security CSRF).
- Тот же сервисный слой и те же правила доступа, что у API: чужая запись
  неотличима от несуществующей; reveal пароля фиксируется в аудите
  (SECRET_REVEALED).
- В списках и формах пароль не отображается; при редактировании пароль
  вводится заново (старый не выносится в HTML).
- Неудачный вход — нейтральное сообщение; rate limiting по IP действует
  и на веб-логин (Task-09).
- Веб-часть изолирована в отдельных filter chain и не меняет поведение API
  (Bearer-аутентификация, stateless, RFC 7807 — без изменений).

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
- `dev` — локальная разработка: открывает Swagger UI/OpenAPI (Task-09).

## Наблюдаемость и защита поверхности (Task-09)

- **Actuator**: наружу только `health`, `info` и `prometheus`;
  остальные эндпоинты (`env`, `beans`, `mappings`, `metrics`, ...) закрыты
  (denyAll). `/actuator/health` не раскрывает деталей (`show-details: never`).
- **Probes**: readiness/liveness (`/actuator/health/readiness`,
  `/actuator/health/liveness`) включены для оркестраторов.
- **Метрики**: Prometheus-экспорт на `/actuator/prometheus` (только агрегаты).
- **Rate limiting**: in-memory лимитер по IP (скользящее окно) на
  `POST /api/auth/login` и `POST /api/auth/register`;
  по умолчанию 10 запросов/60 с на IP; превышение — `429` в формате
  RFC 7807 ProblemDetail с заголовком `Retry-After`. При горизонтальном
  масштабировании требуется распределенный лимитер (например, Redis) —
  текущая реализация действует на каждый инстанс отдельно.
- **Безопасные заголовки**: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store` на всех ответах;
  `Strict-Transport-Security` включается флагом `APP_HSTS_ENABLED=true`
  при работе за TLS-терминацией.
- **Маскирование**: типовые чувствительные поля (`password`, `token`,
  `secret`, `authorization`) маскируются (`SensitiveDataMasker`) — «последний
  рубеж» против утечки секретов в логи и ответы; тела запросов никогда
  не логируются.
- **Swagger/OpenAPI**: закрыт по умолчанию; включается только в dev-профиле
  (`APP_API_DOCS_ENABLED=true` + `APP_DEV_PROFILE=true`). В prod — отключен.

## Docker Compose

### Режим 1 — простой локальный (dev), секреты через `.env`

```bash
cp .env.example .env   # заполните POSTGRES_USER/PASSWORD и VAULT_MASTER_KEY_BASE64
docker compose up -d --build
curl http://localhost:8080/actuator/health   # {"status":"UP"}
```

Compose автоматически подхватывает `.env` (в git не попадает). Состав:
приложение (сборка из `Dockerfile`), PostgreSQL 16 с volume и healthcheck
`pg_isready`; `app` стартует после готовности БД (`depends_on: condition:
service_healthy`) и сам проверяется по `/actuator/health`.

### Режим 2 — Docker secrets (рекомендуется для прод-подобного запуска)

1. Положите файлы в каталог `secrets/` (он в `.gitignore`):
   - `secrets/db_password.txt` — пароль БД;
   - `secrets/master_key.txt` — мастер-ключ KEK (base64, первая строка).
2. Запустите с override-файлом:

```bash
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

В этом режиме пароль БД передается приложению через файл
(`/run/secrets/db_password`): entrypoint `scripts/docker-entrypoint.sh` читает
`POSTGRES_PASSWORD_FILE` и экспортирует `SPRING_DATASOURCE_PASSWORD`; содержимое
файла никогда не логируется. Мастер-ключ читается приложением через
`VAULT_MASTER_KEY_FILE=/run/secrets/master_key`.

В финальный образ не попадают ни `.env`, ни секреты, ни исходники (см.
`.dockerignore`); контейнер работает от непривилегированного пользователя
`vault` (не root), порт `8080` объявлен через `EXPOSE`.

## Полезные команды

| Команда | Описание |
|---|---|
| `./mvnw clean compile` | Компиляция |
| `./mvnw test` | Unit- и интеграционные тесты |
| `./mvnw verify` | Полная сборка с проверками |
| `./mvnw spring-boot:run` | Локальный запуск приложения |
| `./scripts/generate-master-key.sh` | Генерация нового мастер-ключа |

## API

- OpenAPI: `http://localhost:8080/api-docs` (только в dev-профиле, Task-09)
- Swagger UI: `http://localhost:8080/swagger-ui.html` (только в dev-профиле, Task-09)
- Health: `http://localhost:8080/actuator/health`;
  метрики: `/actuator/prometheus` (остальные actuator-эндпоинты закрыты, Task-09)
- Rate limiting: 429 ProblemDetail при превышении лимита запросов на IP (Task-09)

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

### Администрирование (Task-06)

Все эндпоинты требуют роль `ADMIN` (`/api/admin/**` закрыт на уровне
SecurityConfig + `@PreAuthorize` + проверка в сервисе — defense in depth).

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/admin/users?page=0&size=20` | Список пользователей (без хэшей паролей и wrapped DEK) |
| `POST` | `/api/admin/users` | Создание пользователя (`username`, `password`, `role`) |
| `POST` | `/api/admin/users/{id}/enable` | Включение учетной записи |
| `POST` | `/api/admin/users/{id}/disable` | Отключение учетной записи |
| `POST` | `/api/admin/users/{id}/reset-password` | Сброс пароля (`newPassword`) + отзыв всех токенов пользователя |
| `GET` | `/api/admin/audit` | Просмотр аудита: пагинация, фильтры `type`, `userId`, `from`, `to` |
| `POST` | `/api/admin/crypto/rewrap-deks` | Ротация KEK: перепаковка DEK всех пользователей активным ключом |

- Ротация идемпотентна: пользователи уже на активном KEK пропускаются;
  повторный запуск безопасен. Если старый ключ недоступен — понятная ошибка
  (409 ProblemDetail), уже перепакованные пользователи сохраняются.
- Аудит ротации: `KEY_ROTATION_STARTED` / `KEY_ROTATION_COMPLETED` /
  `KEY_ROTATION_FAILED`; в деталях — только нечувствительные key id и счетчики.
- Аудит админ-действий: `USER_CREATED_BY_ADMIN`, `USER_RESET_PASSWORD`,
  `USER_DISABLED`, `USER_ENABLED` (без паролей и секретов).

## Безопасность

Полные правила проекта см. в `AGENTS.md`. Ключевые моменты:

- Секреты запрещено хранить в коде, репозитории, логах, миграциях, артефактах сборки.
- В логи запрещено писать пароли, мастер-ключ, DEK, токены, расшифрованные пароли.
- `.env` добавлен в `.gitignore`; в репозитории — только `.env.example` с плейсхолдерами.
- `spring.jpa.hibernate.ddl-auto=validate` — схема меняется только миграциями Flyway.
- Списки записей не возвращают пароли; расшифровка — только в явном детальном запросе.
