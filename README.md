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
| `VAULT_MASTER_KEY_BASE64` | Мастер-ключ KEK в base64 (32 байта) |
| `VAULT_MASTER_KEY_FILE` | Либо путь к файлу с ключом base64 |
| `SERVER_PORT` | Порт приложения (по умолчанию `8080`) |
| `SPRING_PROFILES_ACTIVE` | Профиль: `default` или `docker` |

Требуется ровно один источник мастер-ключа (`VAULT_MASTER_KEY_BASE64` **или**
`VAULT_MASTER_KEY_FILE`); при отсутствии обоих приложение падает на старте.

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

## Безопасность

Полные правила проекта см. в `AGENTS.md`. Ключевые моменты:

- Секреты запрещено хранить в коде, репозитории, логах, миграциях, артефактах сборки.
- В логи запрещено писать пароли, мастер-ключ, DEK, токены, расшифрованные пароли.
- `.env` добавлен в `.gitignore`; в репозитории — только `.env.example` с плейсхолдерами.
- `spring.jpa.hibernate.ddl-auto=validate` — схема меняется только миграциями Flyway.
- Списки записей не возвращают пароли; расшифровка — только в явном детальном запросе.
