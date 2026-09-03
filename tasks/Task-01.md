# Task-01: Каркас проекта и базовая конфигурация

## Цель
Создать пустое, но корректное приложение на Java 21 + Spring Boot 3.3.x с базовой конфигурацией, проверкой сборки и стартом.

## Результат
- Есть `pom.xml`
- Есть основной класс приложения
- Есть `application.yaml`
- Есть actuator health endpoint
- Есть `.env.example`
- Есть скрипт генерации мастер-ключа
- Приложение запускается и отвечает на `/actuator/health`

## Требования
1. Использовать:
   - Java 21
   - Spring Boot 3.3.x
   - Maven Wrapper
2. Включить зависимости:
   - `spring-boot-starter-web`
   - `spring-boot-starter-security`
   - `spring-boot-starter-data-jpa`
   - `spring-boot-starter-validation`
   - `spring-boot-starter-actuator`
   - `springdoc-openapi-starter-webmvc-ui`
   - `postgresql`
   - `flyway-core`
3. Настроить профили:
   - `default`
   - `docker`
4. В `application.yaml` использовать переменные окружения:
   - `POSTGRES_HOST`
   - `POSTGRES_PORT`
   - `POSTGRES_DB`
   - `POSTGRES_USER`
   - `POSTGRES_PASSWORD`
   - `VAULT_MASTER_KEY_BASE64`
   - `VAULT_MASTER_KEY_FILE`
5. Добавить:
   - `.gitignore`
   - `.env.example`
   - `scripts/generate-master-key.sh`
6. Скрипт `generate-master-key.sh` должен выводить безопасный ключ:
   - `openssl rand -base64 32`
7. Включить виртуальные потоки:
   - `spring.threads.virtual.enabled: true`
8. Настроить минимальную защиту:
   - `/actuator/health` доступен
   - остальные actuator endpoints закрыты по умолчанию
9. Подготовить базовый `README.md` с командами запуска.

## Файлы для создания/изменения
- `pom.xml`
- `src/main/java/com/example/safeaccounts/SafeAccountsApplication.java`
- `src/main/resources/application.yaml`
- `src/main/resources/application-docker.yaml`
- `.env.example`
- `.gitignore`
- `scripts/generate-master-key.sh`
- `README.md`

## Критерии приемки
1. `./mvnw clean compile` проходит успешно.
2. `./mvnw test` проходит успешно.
3. Приложение запускается при доступном PostgreSQL.
4. `GET /actuator/health` возвращает статус `UP`.
5. В коде нет реальных секретов.
6. `.env.example` содержит только плейсхолдеры.

## Примечание
На этом этапе допустимо временно ограничить запуск без полной схемы БД, если это сделано безопасно и явно. Однако итог задачи должен быть совместим с дальнейшими миграциями Flyway.