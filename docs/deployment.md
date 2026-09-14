# Развертывание safe-accounts

Инструкция по эксплуатации в Docker и на «голом» хосте. Родственные
документы: `docs/security.md`, `docs/key-rotation.md`, `docs/backup-restore.md`,
`docs/runbook.md`, `docs/threat-model.md`.

## 1. Требования к окружению

| Компонент | Требование |
|---|---|
| Java (запуск без Docker) | JDK / JRE 21+ |
| БД | PostgreSQL 16 (схема только через Flyway, `ddl-auto=validate`) |
| Docker | Docker Engine + Docker Compose v2 (многоэтапная сборка, non-root пользователь `vault`) |
| Утилиты | `openssl` для генерации ключа (`scripts/generate-master-key.sh`); `pg_dump/pg_restore` не нужны на хосте — дампы выполняются внутри контейнера БД |
| Оборудование | ≥ 512 МиБ RAM для приложения (Argon2id: m=64 МиБ на операцию хэширования) |

Сеть: приложение слушает `8080` (`SERVER_PORT`); наружу рекомендуется
выставлять только reverse proxy с TLS, приложение оставить во внутренней сети.

## 2. Переменные окружения

Секреты читаются **только** из переменных окружения или файлов секретов —
никогда из кода, репозитория или логов.

| Переменная | Обязательна | Описание |
|---|---|---|
| `POSTGRES_HOST` / `POSTGRES_PORT` / `POSTGRES_DB` | нет | хост/порт/имя БД (по умолчанию `localhost`/`5432`/`safe_accounts`) (порт на хост публикуется только через docker-compose.dev.yml) |
| `POSTGRES_USER` | да | пользователь БД |
| `POSTGRES_PASSWORD` | да* | пароль БД (*или `POSTGRES_PASSWORD_FILE`) |
| `POSTGRES_PASSWORD_FILE` | да* | файл с паролем БД (Docker secrets; entrypoint экспортирует `SPRING_DATASOURCE_PASSWORD`) |
| `VAULT_MASTER_KEY_BASE64` | да** | мастер-ключ KEK, base64 (32 байта) |
| `VAULT_MASTER_KEY_FILE` | да** | либо путь к файлу с ключом (первая строка — base64) |
| `APP_CRYPTO_KEYS_N_ID` / `_SECRET_BASE64` / `_ACTIVE` | нет | мультиключевой режим (ротация): активный ровно один |
| `APP_ADMIN_USERNAME` / `APP_ADMIN_PASSWORD` | нет | bootstrap первого администратора (только на пустой БД) |
| `SERVER_PORT` | нет | порт (по умолчанию 8080) |
| `SPRING_PROFILES_ACTIVE` | нет | `default` \| `docker` \| `dev` |
| `APP_RATE_LIMIT_WINDOW_SECONDS` / `APP_RATE_LIMIT_MAX_REQUESTS` | нет | rate limiting login/register (60 / 10) |
| `APP_HSTS_ENABLED` | нет | HSTS — включать только за TLS-терминацией |
| `APP_API_DOCS_ENABLED` / `APP_DEV_PROFILE` | нет | Swagger/OpenAPI — **запрещено в проде** |

\*\* Ровно один источник KEK; при отсутствии обоих приложение **падает на
старте** — намеренно (`AGENTS.md`).

Шаблон для заполнения: `.env.example` (в `.env` — реальные значения; `.env`
в `.gitignore` и не попадает в репозиторий/образ).

## 3. Секреты

- **Мастер-ключ (KEK)**: генерируется `./scripts/generate-master-key.sh`
  (base64, 32 байта). В проде храните в KMS/Vault/менеджере секретов либо в
  файле на отдельном томе с правами `0600` (`VAULT_MASTER_KEY_FILE`).
  KEK никогда не хранится в БД, коде, логах и рядом с дампами
  (см. `docs/backup-restore.md` §3).
- **Пароль БД**: переменная окружения или Docker secrets
  (`docker-compose.secrets.yml`: файл `secrets/db_password.txt` монтируется
  в `/run/secrets/db_password`; entrypoint читает файл, не логируя).
- **Bootstrap-пароль администратора** (`APP_ADMIN_PASSWORD`): задается через
  окружение/файл секретов, после первого старта переменную рекомендуется
  убрать из окружения (администратор уже создан).
- Правила: секреты не логируются (запрещено и подтверждено тестами,
  `SensitiveDataMasker` маскирует как последний рубеж); в git-репозитории
  только шаблоны (`.env.example`); в финальный Docker-образ не попадают
  ни `.env`, ни `secrets/`, ни исходники (`.dockerignore`).

Каталог `secrets/` (для режима Docker secrets) — в `.gitignore`:

```
secrets/
├── db_password.txt    # пароль БД
└── master_key.txt     # KEK base64 в первой строке
```

## 4. Запуск в Docker

### Режим 1 — простой локальный (dev)

```bash
cp .env.example .env    # заполнить POSTGRES_USER/PASSWORD, VAULT_MASTER_KEY_BASE64
# порт БД 5432 публикуется на хост только в dev-оверрайде (docker-compose.dev.yml)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
curl -fsS http://localhost:8080/actuator/health
```

### Режим 2 — Docker secrets (рекомендуется для прод-подобного запуска)

```bash
mkdir -p secrets && chmod 700 secrets
echo -n '<пароль БД>'  > secrets/db_password.txt
./scripts/generate-master-key.sh > secrets/master_key.txt
chmod 600 secrets/*
docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

Состав: сервис `db` (postgres:16-alpine, volume `pgdata`, healthcheck
`pg_isready`) и сервис `app` (сборка из `Dockerfile`; non-root пользователь
`vault`; healthcheck `/actuator/health`; стартует после готовности БД).

Миграции Flyway применяются автоматически при старте приложения; схема
меняется только миграциями (`ddl-auto=validate`).

Проверка: `curl http://localhost:8080/actuator/health` → `{"status":"UP"}`.

### Обновление версии

```bash
git pull && docker compose up -d --build app   # БД не пересоздается (volume)
```

Примененные миграции Flyway не редактируются; новые версии добавляются
файлами `V<n>__description.sql`.

## 5. Reverse proxy / TLS

Приложение работает по HTTP — **терминируйте TLS на reverse proxy**
(nginx/Caddy/traefik). Рекомендации:

```nginx
server {
    listen 443 ssl;
    http2 on;
    ssl_certificate     /etc/letsencrypt/live/vault.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vault.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Только необходимые методы и пути; проксируем приложение целиком:
    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
        client_max_body_size 1m;   # тела записей сейфа малы; лимит против DoS
    }
}
server {
    listen 80;
    return 301 https://$host$request_uri;   # весь HTTP -> HTTPS
}
```

- На стороне приложения включите `APP_HSTS_ENABLED=true` (заголовок
  `Strict-Transport-Security`), только когда трафик действительно идет по
  HTTPS.
- Приложение уже отдает `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Cache-Control: no-store` — дублировать на proxy
  не обязательно.
- Rate limiting работает по IP клиента: при проксировании обеспечьте
  корректный `X-Forwarded-For` (доверенный proxy), иначе лимитер будет
  считать IP proxy общим для всех клиентов.
- Порт `db` (5432) в базовом docker-compose.yml не публикуется вовсе; для локального доступа из инструментов используйте docker-compose.dev.yml (только для dev-окружения).
- Swagger/OpenAPI в проде закрыт — не включайте `APP_API_DOCS_ENABLED` /
  `APP_DEV_PROFILE`.

## 6. Рекомендации по бэкапам

Полная инструкция — `docs/backup-restore.md`. Кратко:

```bash
./scripts/backup.sh    # daily; pg_dump -Fc внутрь backups/, права 0600
```

- Расписание: cron/systemd timer, например ежедневно ночью; хранить ≥ 2
  поколений (день/неделя/месяц) на отдельном носителе + off-site копия.
- Дампы содержат только шифротекст, но обращайтесь с ними как с
  конфиденциальными данными; опционально шифруйте `age`/`gpg`.
- **Мастер-ключ бэкапится отдельно от дампов** и хранится в другом месте;
  наличие копии KEK регулярно проверяется (тестовое восстановление +
  расшифровка контрольной записи, раз в квартал).
- Потеря KEK = необратимая потеря данных — см. `docs/threat-model.md` §6.
- Репетиция восстановления на чистой машине — обязательная часть
  эксплуатации (`docs/backup-restore.md` §2, §4).
- При ротации KEK не удаляйте старый ключ, пока живы бэкапы, снятые до
  ротации (`docs/key-rotation.md`, шаг 7).

## 7. Чек-лист после развертывания

1. `curl -fsS http://localhost:8080/actuator/health` → `UP`.
2. Создан администратор (bootstrap или API) и пароль ≥ 12 символов.
3. TLS работает, `APP_HSTS_ENABLED=true` за терминацией, HTTP редиректит.
4. `db` не доступна снаружи.
5. Бэкап настроен, первый дамп снят и проверен восстановлением.
6. KEK хранится отдельно от дампов, есть проверенная копия.
7. Веб-интерфейс и API открываются, чужие записи недоступны.
8. Аудит пишется (`GET /api/admin/audit` возвращает события).
