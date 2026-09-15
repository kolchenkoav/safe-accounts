# safe-accounts

Серверное приложение-сейф для надёжного хранения учётных записей (сайт, логин,
пароль, примечание) на **Java 21 / Spring Boot 3.3.x / PostgreSQL 16 / Flyway**.

Безопасность: AES-256-GCM для секретов, Argon2id для паролей, Bearer-токены
(в БД только хэш), шифрование DEK мастер-ключом KEK, аудит операций.

## Стек

| Слой | Технология |
|---|---|
| Язык / рантайм | Java 21 |
| Фреймворк | Spring Boot 3.3.x (Web, Security, Data JPA, Actuator, Validation) |
| БД | PostgreSQL 16 |
| Миграции | Flyway (схема меняется только миграциями, `ddl-auto=validate`) |
| Криптография | AES-256-GCM (KEK/DEK), Argon2id, SHA-256 (хэш токенов) |
| Тесты | JUnit 5, Testcontainers (PostgreSQL), MockMvc |
| Эксплуатация | Docker (многоэтапный образ, non-root), Docker Compose + secrets |

## Документация

| Документ | Содержание |
|---|---|
| [`docs/deployment.md`](docs/deployment.md) | развертывание: окружение, переменные, секреты, Docker, TLS/reverse proxy, бэкапы |
| [`docs/deployment-synology.md`](docs/deployment-synology.md) | пошаговое развертывание на Synology NAS: Container Manager/SSH, автозапуск после ребута, бэкапы по расписанию |
| [`docs/security.md`](docs/security.md) | как защищены пароли/токены/записи; действия при утечке и компрометации KEK |
| [`docs/key-rotation.md`](docs/key-rotation.md) | процесс ротации мастер-ключа (7 шагов + аварийная) |
| [`docs/backup-restore.md`](docs/backup-restore.md) | бэкап/восстановление, хранение KEK, DR-сценарий |
| [`docs/threat-model.md`](docs/threat-model.md) | модель угроз: утечка БД/логов, кража токена/KEK, брутфорс, потеря ключа, DR |
| [`docs/runbook.md`](docs/runbook.md) | операционная шпаргалка: здоровье, логи, бэкап, отзыв токенов, админ, ротация |
| [`docs/security-checklist.md`](docs/security-checklist.md) | чек-лист безопасности со ссылками на тесты |
| [`AGENTS.md`](AGENTS.md) | обязательные правила проекта |

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

5. Веб-интерфейс: откройте `http://localhost:8080/` — войдите
   пользователем, созданным через `POST /api/auth/register` (или через
   админ-API). Работа с сейфом: список/создание/просмотр/изменение/удаление
   записей; пароль отображается только по кнопке «Показать пароль».

Первый администратор: при пустой БД задайте `APP_ADMIN_USERNAME` /
`APP_ADMIN_PASSWORD` — bootstrap создаст его при старте.

## Как запустить в Docker

```bash
cp .env.example .env    # заполните POSTGRES_USER/PASSWORD и VAULT_MASTER_KEY_BASE64
# порт БД 5432 публикуется на хост только в dev-оверрайде (docker-compose.dev.yml)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
curl http://localhost:8080/actuator/health
```

Compose поднимает `db` (postgres:16-alpine, volume `pgdata`, healthcheck
`pg_isready`) и `app` (сборка из `Dockerfile`; multi-stage; non-root
пользователь `vault`; healthcheck по `/actuator/health`; стартует после
готовности БД). Рекомендуемый прод-подобный режим — Docker secrets:

```bash
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

Подробности, TLS/reverse proxy и чек-лист после развертывания —
`docs/deployment.md`.

## Как прогнать тесты

```bash
./mvnw test     # unit + интеграционные (Testcontainers: нужен Docker)
./mvnw verify   # полная сборка с проверками
```

- Unit-тесты: криптография (AES-256-GCM, KEK/DEK), маскирование секретов,
  сервисные правила.
- Интеграционные: Flyway/JPA против реального PostgreSQL (Testcontainers),
  security-тесты авторизации, e2e-потоки API, проверки отсутствия plaintext
  в БД.
- Внешние сервисы не требуются; тестовый мастер-ключ — фиксированный, только
  в тестовом профиле, синтетические значения.

## Где лежат скрипты

| Скрипт | Назначение |
|---|---|
| `scripts/generate-master-key.sh` | генерация мастер-ключа KEK (base64, 32 байта) |
| `scripts/backup.sh` | логический дамп БД (`pg_dump -Fc` внутри контейнера БД) в `backups/` |
| `scripts/restore.sh` | восстановление дампа (останавливает app, идемпотентно, с проверками) |
| `scripts/docker-entrypoint.sh` | entrypoint контейнера: читает `POSTGRES_PASSWORD_FILE` (Docker secrets), не логируя |

Инструкции: `docs/backup-restore.md` (бэкап/восстановление/DR),
`docs/key-rotation.md` (ротация ключа), `docs/runbook.md` (шпаргалка).

## Конфигурация

Все секреты читаются только из переменных окружения или файлов секретов
(никогда — из кода, репозитория или логов).

| Переменная | Описание |
|---|---|
| `POSTGRES_HOST` | Хост PostgreSQL (по умолчанию `localhost`) |
| `POSTGRES_PORT` | Порт PostgreSQL (по умолчанию `5432`); публикация на хост — только в dev-режиме (docker-compose.dev.yml) |
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
| `APP_PORT` | Хост-порт для Docker Compose (по умолчанию `8080`; внутренний порт контейнера всегда `8080`) |
| `SERVER_PORT` | Порт приложения при локальном запуске без Docker (по умолчанию `8080`) |
| `SPRING_PROFILES_ACTIVE` | Профиль: `default`, `docker` или `dev` |
| `APP_RATE_LIMIT_WINDOW_SECONDS` | Окно rate limiter'а в секундах (по умолчанию `60`) |
| `APP_RATE_LIMIT_MAX_REQUESTS` | Максимум запросов на IP за окно (по умолчанию `10`) |
| `app.vault.import.rate-limit.window-seconds` | Окно rate-limit'а импорта в секундах (по умолчанию `60`) |
| `app.vault.import.rate-limit.max-requests` | Максимум импортов на IP за окно (по умолчанию `3`) |
| `APP_HSTS_ENABLED` | Strict-Transport-Security (`true` за TLS-терминацией) |
| `APP_API_DOCS_ENABLED` | Swagger/OpenAPI (`true` только в dev) |
| `APP_DEV_PROFILE` | dev-профиль (открывает Swagger; в проде — запрещено) |

Требуется ровно один источник мастер-ключа (`VAULT_MASTER_KEY_BASE64` **или**
`VAULT_MASTER_KEY_FILE`); при отсутствии обоих приложение падает на старте.

### Веб-интерфейс

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
| `/logout` | Выход: POST-форма с CSRF-токеном (GET также поддержан), инвалидация сессии, редирект на `/web/login` |

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
  и на веб-логин.
- Веб-часть изолирована в отдельных filter chain и не меняет поведение API
  (Bearer-аутентификация, stateless, RFC 7807 — без изменений).

Темы оформления:
- По умолчанию — тёмная тема (`:root` и `data-theme="dark"` в `style.css`);
  применяется даже без JavaScript. Светлая — по кнопке-переключателю
  (присутствует на всех страницах, включая логин).
- Выбор темы хранится в браузере (`localStorage`, ключ `theme`); переключение
  выполняет статический `static/web/theme.js`, подключаемый в `<head>` без
  `defer` — защита от мигания (FOUC). Inline-скрипты в HTML не используются.
- Тема — исключительно клиентская настройка: сервер не хранит её, а
  `Cache-Control: no-store` для статики не мешает (localStorage — на клиенте).

### Веб-раздел администратора (Task-12)

Страницы `/web/admin/**` доступны только роли `ROLE_ADMIN`:
неаутентифицированный перенаправляется на `/web/login`, аутентифицированный
без роли получает 403. В навигации ссылка «Админка» видна только админам.

| Путь | Описание |
|---|---|
| `/web/admin/users` | Пользователи: создание, включение/отключение, смена роли, сброс пароля |
| `/web/admin/audit` | Журнал аудита: фильтры (type, userId, from, to), пагинация |
| `/web/admin/crypto` | Ротация ключей: кнопка «Rewrap DEKs», результат — flash-сообщение |

Все мутирующие действия — POST-формы с CSRF-токеном. Пароли никогда не
возвращаются в HTML и не логируются. Смена собственной роли запрещена
(защита от потери последнего администратора); смена роли пишется в аудит
как `USER_ROLE_CHANGED`. REST-эндпоинты при этом не изменены.

### Криптомодуль (KEK/DEK)

- Каждому пользователю генерируется собственный DEK (AES-256).
- DEK хранится в БД только в wrapped-виде (`users.dek_wrapped`, `dek_iv`,
  `dek_kek_id`), обернутый мастер-ключом KEK (AES-256-GCM).
- Секреты сейфа шифруются DEK пользователя: `base64(iv || ciphertext || tag)`,
  IV — 12 байт, `SecureRandom`, уникальный на каждую операцию.
- Поддерживается ротация KEK: в логах — только key id и усеченный SHA-256
  fingerprint; материал ключей никогда не логируется.
- В логах запрещены материал ключей и расшифрованные секреты; ошибки
  расшифровки возвращают нейтральное сообщение без деталей.

## Профили

- `default` — локальный запуск (PostgreSQL на `localhost`).
- `docker` — запуск в контейнерах (PostgreSQL на сервисе `postgres`).
- `dev` — локальная разработка: открывает Swagger UI/OpenAPI.

## Наблюдаемость и защита поверхности

- **Actuator**: наружу только `health`, `info` и `prometheus`;
  остальные эндпоинты (`env`, `beans`, `mappings`, `metrics`, ...) закрыты
  (denyAll). `/actuator/health` не раскрывает деталей (`show-details: never`).
- **Probes**: readiness/liveness (`/actuator/health/readiness`,
  `/actuator/health/liveness`) включены для оркестраторов.
- **Метрики**: Prometheus-экспорт на `/actuator/prometheus` (только агрегаты).
- **Rate limiting**: in-memory лимитер по IP (скользящее окно) на
  `POST /api/auth/login` и `POST /api/auth/register`;
  по умолчанию 10 запросов/60 с на IP; превышение — `429` в формате
  RFC 7807 ProblemDetail с заголовком `Retry-After`. На
  `POST /api/vault/import` действует отдельный, более строгий лимит:
  3 запроса/60 с на IP (`app.vault.import.rate-limit.{window-seconds:60,
  max-requests:3}`) — импорт дороже обычных операций и обращается с
  большим числом записей сразу. При горизонтальном масштабировании
  требуется распределенный лимитер (например, Redis) — текущая
  реализация действует на каждый инстанс отдельно.
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
# порт БД 5432 публикуется на хост только в dev-оверрайде (docker-compose.dev.yml)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
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

- OpenAPI: `http://localhost:8080/api-docs` (только в dev-профиле)
- Swagger UI: `http://localhost:8080/swagger-ui.html` (только в dev-профиле)
- Health: `http://localhost:8080/actuator/health`;
  метрики: `/actuator/prometheus` (остальные actuator-эндпоинты закрыты)
- Rate limiting: 429 ProblemDetail при превышении лимита запросов на IP

### Аутентификация

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

### Сейф

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

#### Сейф — CSV Export/Import

Импорт/экспорт в формате Chrome Password Manager CSV
(`name,url,username,password,note`, 5 колонок, RFC 4180) для миграции между
`safe-accounts` и браузером/другим сейфом. Теги в CSV **не входят** —
формат Chrome их не поддерживает; управление тегами — отдельный контур
(`/api/tags`, `/api/vault/{id}/tags`, см. ниже).

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/api/vault/export?bom=true\|false` | Свои записи в CSV; `text/csv; charset=utf-8`; ответ содержит заголовок `X-Vault-Export-Warning: csv-contains-plaintext-passwords` |
| `POST` | `/api/vault/import` | multipart `file` + поле `conflictStrategy` (`skip` \| `upsert`); query-параметры `dryRun=true\|false`, `failFast=true\|false` |
| `GET` | `/api/admin/users/{id}/vault/export` | ADMIN: CSV-экспорт записей произвольного пользователя |
| `POST` | `/api/admin/users/{id}/vault/import` | ADMIN: импорт CSV в чужой аккаунт (параметры — как у `/api/vault/import`) |

> ⚠️ **CSV содержит пароли в открытом виде.** Относитесь к экспортированному
> файлу как к **резервной копии сейфа**: не передавайте по незащищённым
> каналам, не храните в открытом виде, удаляйте сразу после миграции в
> целевую систему. Заголовок `X-Vault-Export-Warning: csv-contains-plaintext-passwords`
> ставится на каждый export-ответ — интеграторы и мониторинг могут ловить
> его и алертить.

Лимиты и поведение:

- Записей в экспорте — не более `MAX_EXPORT_ROWS` (по умолчанию 10 000);
  размер CSV — не более `MAX_CSV_BYTES` (по умолчанию 10 МиБ); превышение —
  `413`/`422` ProblemDetail.
- Импорт имеет **rate-limit** на IP: 3 запроса в минуту (60 с)
  (`app.vault.import.rate-limit.{window-seconds:60, max-requests:3}`);
  превышение — `429` ProblemDetail с заголовком `Retry-After`.
- Конфликт по `name+url` (нормализация Chrome): `skip` (по умолчанию) —
  существующая запись остаётся, импортируемая пропускается;
  `upsert` — существующая запись перезаписывается (поля `password` и `note`
  перешифровываются).
- `dryRun=true` — отчёт о том, что произойдёт, без реальных изменений
  (поля `wouldCreate`, `wouldUpdate`, `skipped`, `failed`, `errors[]`).
- `failFast=false` (по умолчанию) — ошибки валидации отдельных строк
  собираются в `errors[]`, импорт не прерывается на первой ошибке;
  `failFast=true` — остановка на первой ошибке строки.
- Аудит: `VAULT_EXPORTED` и `VAULT_IMPORTED` (actor, target, стратегия,
  счётчики, `csvSha256`; **без секретов** в details) — для расследования
  инцидентов.
- BOM: `?bom=true` дописывает UTF-8 BOM (`0xEF 0xBB 0xBF`) — нужно для
  корректного открытия в Excel на Windows; по умолчанию BOM отсутствует.

Примеры curl (плейсхолдеры `<token>`, `<adminToken>`, `<userId>`):

```bash
# Экспорт своих записей (файл vault.csv, без BOM)
curl -OJ -H "Authorization: Bearer <token>" \
  "http://localhost:8080/api/vault/export?bom=false"

# Импорт (по умолчанию conflictStrategy=skip, failFast=false)
curl -X POST -H "Authorization: Bearer <token>" \
  -F file=@vault.csv -F conflictStrategy=skip \
  "http://localhost:8080/api/vault/import"

# Импорт с dryRun: покажет, что произойдёт, без реальных изменений
curl -X POST -H "Authorization: Bearer <token>" \
  -F file=@vault.csv -F conflictStrategy=upsert \
  "http://localhost:8080/api/vault/import?dryRun=true"

# ADMIN: экспорт записей произвольного пользователя
curl -OJ -H "Authorization: Bearer <adminToken>" \
  "http://localhost:8080/api/admin/users/<userId>/vault/export"
```

Теги: импорт/экспорт CSV теги **не затрагивает** — формат Chrome их не
поддерживает. Управление тегами — через `/api/tags` (CRUD над словарём
тегов) и `/api/vault/{id}/tags` (привязка/отвязка тегов к записи). Полное
дерево записей с тегами для миграции между экземплярами `safe-accounts`
планируется как JSON-экспорт (`vault-export.json`) — отдельная фича
в будущем (TODO).

### Администрирование

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
- Как защищены пароли/токены/записи и что делать при инцидентах — `docs/security.md`;
  модель угроз — `docs/threat-model.md`.
