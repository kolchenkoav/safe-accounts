# Развертывание safe-accounts на Synology NAS

Пошаговая инструкция для NAS Synology с DSM 7.2+ и Container Manager.
Общая инструкция развертывания (переменные окружения, secrets, TLS) —
`docs/deployment.md`; бэкап/восстановление — `docs/backup-restore.md`.
Основной способ деплоя — **GitLab CI** (раздел 2); разделы 3–13 описывают
**альтернативный ручной способ** (`git pull` + `docker compose up -d --build`).

## 1. Требования

| Компонент | Требование |
|---|---|
| DSM | 7.2+ с пакетом **Container Manager** (вкладка «Проект»). На старых DSM — пакет Docker + SSH (нужен Compose v2) |
| Архитектура NAS | x86_64 или arm64 — обе поддерживаются образами `postgres:16-alpine` и `eclipse-temurin:21-*-alpine` (multi-arch). На ARM сборка образа (Maven внутри Dockerfile) идет заметно **медленнее** — это нормально |
| Свободное место | ≥ 2 ГиБ на томе docker (образы + кэш Maven при сборке) плюс место под данные БД и дампы бэкапов |
| Сеть | Порт `8080` приложения **не выставлять в интернет** без reverse proxy с TLS (см. `docs/deployment.md` §5). Порт БД `5432` наружу не публиковать |
| Утилиты (SSH-вариант) | `openssl` для генерации мастер-ключа, `git` (только для варианта клонирования) |

> Приложение работает по HTTP. Перед доступом из интернета обязательно
> терминируйте TLS на reverse proxy и только после этого включайте
> `APP_HSTS_ENABLED=true` (переменная поддерживается compose).

## 2. Деплой через GitLab CI (основной способ)

Пайплайн `.gitlab-ci.yml` собирает образ `linux/amd64` и публикует его в
приватный registry GitLab (`CI_REGISTRY`), а деплой-джоба по SSH обновляет
контейнер `app` на NAS из готового образа — **сборка на NAS не выполняется**.

### Схема пайплайна

Используется Docker-executor раннер с тегом `docker` (см. `default.tags`
в `.gitlab-ci.yml`); кэш Maven (`.m2/repository`) общий для джоб.

| Стадия | Джоба | Что делает |
|---|---|---|
| `test` | `mvn -B verify` | unit-тесты (surefire) и интеграционные тесты на Testcontainers (failsafe); Docker-in-Docker как сервис |
| `build` | `mvn -B package -DskipTests` | собирает `target/safe-accounts.jar` |
| `docker` | `docker build --platform linux/amd64` | собирает и пушит `$CI_REGISTRY_IMAGE:$VERSION` и `$CI_REGISTRY_IMAGE:latest` |
| `deploy` | `scp` + `ssh` | копирует compose-файлы на NAS, `docker compose pull app`, `up -d` |
| `cleanup` | `ssh` + `docker rmi` | оставляет на NAS 3 последние версии образа и `latest`, старые удаляет |

Версия образа: тег (`CI_COMMIT_TAG`) либо `1.0.<номер пайплайна>` для веток
`master`/`main`. Полный пайплайн (с `deploy`/`cleanup`) запускается только
для `master`/`main` и тегов; остальные ветки проходят `test` и `build`.

### Настройка GitLab

1. **Deploy token** (Settings → Repository → Deploy tokens): scope
   `read_registry` — этим токеном NAS выполняет `docker login` в приватный registry.
2. **CI/CD → Variables** (Settings → CI/CD → Variables):

| Переменная | Тип в GitLab | Назначение |
|---|---|---|
| `NAS_SSH_HOST` | Variable, Masked | IP-адрес или DNS-имя NAS для `ssh`/`scp` |
| `NAS_SSH_USER` | Variable, Masked | SSH-пользователь на NAS (член группы `docker`) |
| `NAS_SSH_PRIVATE_KEY` | File (ed25519) | закрытый SSH-ключ для подключения к NAS; содержимое файла — приватный ключ |
| `NAS_REGISTRY_USER` | Variable, Masked | имя Deploy token (scope `read_registry`) |
| `NAS_REGISTRY_TOKEN` | Variable, Masked | токен Deploy token (scope `read_registry`) |

> Мастер-ключ KEK и пароль БД **не заводятся** в GitLab: они живут только
> в `.env` и `secrets/` на NAS (раздел 4) и в локальном `.env` разработчика.

### Настройка NAS

1. Включите SSH: **Панель управления → Терминал и SNMP → «Включить службу SSH»**.
2. Дайте CI-пользователю доступ к Docker. Проще всего — добавить пользователя
   в группу **`docker`** (Панель управления → Пользователь/Группа): тогда
   `docker` работает без `sudo`. Альтернатива — `sudo` с ограниченным набором
   команд (`docker login`, `docker compose pull/up`, `docker images`,
   `docker rmi`) через `sudoers`.
3. Сгенерируйте ключевую пару и добавьте открытый ключ на NAS
   (`/volume1/homes/<пользователь>/.ssh/authorized_keys`):

   ```bash
   ssh-keygen -t ed25519 -f gitlab-ci-deploy -N ""
   ssh-copy-id <пользователь>@<IP_NAS>
   ```

   Закрытый ключ `gitlab-ci-deploy` загрузите в GitLab как файл
   `NAS_SSH_PRIVATE_KEY`.
4. Проверьте подключение без пароля:

   ```bash
   ssh <пользователь>@<IP_NAS> 'docker version'
   ```

   Если docker требует пароль или `sudo` — пользователь не в группе `docker`.
5. Создайте целевой каталог (один раз):

   ```bash
   ssh <пользователь>@<IP_NAS> 'mkdir -p /volume1/docker/safe-accounts'
   ```

6. Проверьте версию Docker Compose: `pull_policy` (используется в
   `docker-compose.deploy.yml`) требует **Compose v2.24+**:

   ```bash
   ssh <пользователь>@<IP_NAS> 'docker compose version'
   ```

   На DSM 7.2+ / Container Manager обычно стоит версия 2.2x+ — этого
   достаточно. Если версия ниже 2.24 — обновите Container Manager (или
   пакет Docker), иначе первый же `docker compose pull` завершится ошибкой
   про неизвестную опцию конфигурации `pull_policy`.

   > **NAS_REGISTRY_USER / NAS_REGISTRY_TOKEN** раскрываются **на стороне
   > NAS** — внутри ssh-команды деплоя, поэтому обязаны быть доступны в
   > окружении SSH-пользователя на момент выполнения. Практически их
   > задают один раз на раннере в CI/CD Variables (masked), а ssh-команда
   > передаёт их через окружение команды; в логи они не попадают.

### Первый запуск

1. **Один раз, вручную** выполните «Шаг 2. Подготовить `.env`» (раздел 4) и,
   при желании, Docker secrets (раздел 11). CI эти файлы не создает и не
   синхронизирует (они в `.gitignore`). Compose-файлы (`docker-compose.yml`,
   `docker-compose.synology.yml`, `docker-compose.deploy.yml`) CI копирует
   на NAS при каждом деплое — обновлять их вручную на NAS не нужно.
2. Запустите пайплайн на ветке `master`/`main` (или создайте тег).
   Джоба `deploy`:
   - скопирует compose-файлы в `/volume1/docker/safe-accounts/`;
   - залогинится в registry Deploy token'ом
     (`NAS_REGISTRY_USER`/`NAS_REGISTRY_TOKEN`);
   - выполнит `SAFE_ACCOUNTS_IMAGE=$CI_REGISTRY_IMAGE:$VERSION`
     `docker compose -f docker-compose.yml -f docker-compose.synology.yml
     -f docker-compose.deploy.yml pull app`;
   - поднимет контейнер `... up -d` (без `down` — контейнеры и данные
     не теряются).
3. Проверка — раздел 7 («Шаг 4. Проверка»).

### Ручной откат

Если новая версия не работает — поднимите предыдущий тег (данные БД в volume
`pgdata` не затрагиваются; миграции Flyway идут только вперёд, при откате
схемы восстанавливайте дамп — `docs/backup-restore.md`):

```bash
ssh <пользователь>@<IP_NAS>
cd /volume1/docker/safe-accounts
SAFE_ACCOUNTS_IMAGE=registry.gitlab.com/kolchenkoav/safe-accounts:<предыдущий-тег> \
  docker compose -f docker-compose.yml -f docker-compose.synology.yml -f docker-compose.deploy.yml up -d
```

### Troubleshooting (CI)

| Симптом | Причина и решение |
|---|---|
| `ssh: connect to host <NAS> port 22: Connection timed out` | SSH на NAS недоступен: включите службу SSH, проверьте `NAS_SSH_HOST` и доступность порта 22 из сети, где стоит раннер |
| `denied: requested access to the resource is denied` при `pull app` | Deploy token не читает registry: проверьте scope `read_registry` у токена и значения `NAS_REGISTRY_USER`/`NAS_REGISTRY_TOKEN` |
| Ошибка интерполяции `SAFE_ACCOUNTS_IMAGE is required` | Джоба `deploy` не получила версию (`version.env` из джобы `docker` через `needs`) либо compose-файлы на NAS не синхронизированы — перезапустите пайплайн |
| Приложение не стартует: `VAULT master key not configured` | На NAS не заполнен `.env`: задайте ровно один источник KEK (`VAULT_MASTER_KEY_BASE64` или `VAULT_MASTER_KEY_FILE`), раздел 4 |

## 3. Шаг 1. Получить код на NAS (альтернативный ручной способ)

При деплое через GitLab CI код на NAS получать не нужно — CI сам копирует
compose-файлы. Проект удобно держать в общей папке docker: `/volume1/docker`.

**Вариант A — клонирование по SSH.** Подключитесь по SSH (Панель управления →
Терминал и SNMP → «Включить службу SSH», вход пользователем из группы
администраторов; для git установите пакет «Git Server» из Центра пакетов):

```bash
sudo git clone <URL-вашего-репозитория> /volume1/docker/safe-accounts
cd /volume1/docker/safe-accounts
```

**Вариант B — File Station.** Создайте в File Station папку
`docker/safe-accounts` и выгрузите туда содержимое проекта (например,
архивом с последующей распаковкой). **Не копируйте** `.env` (пароли) и
папку `secrets/` — секреты создаются на NAS отдельно, шагом ниже
(`.env` и `secrets/` в репозитории отсутствуют, они в `.gitignore`).

## 4. Шаг 2. Подготовить `.env`

Compose читает `.env` из корня проекта (рядом с `docker-compose.yml`) и
подставляет значения в `${...}`. Создайте файл на NAS и заполните:

```bash
cd /volume1/docker/safe-accounts
sudo cp .env.example .env        # или создайте пустой: sudo vi .env
sudo openssl rand -base64 32     # мастер-ключ (KEK), 32 случайных байта в base64
```

Эквивалент генерации ключа — скрипт проекта `./scripts/generate-master-key.sh`
(внутри тот же `openssl rand -base64 32`); `openssl` доступен в SSH-сессии DSM.

| Переменная | Обязательна | Описание |
|---|---|---|
| `POSTGRES_USER` | да | пользователь БД |
| `POSTGRES_PASSWORD` | да | пароль БД (или режим Docker secrets, см. §10) |
| `POSTGRES_DB` | нет | имя БД, по умолчанию `safe_accounts` |
| `VAULT_MASTER_KEY_BASE64` | ровно один из двух | мастер-ключ KEK, base64 из 32 байт |
| `VAULT_MASTER_KEY_FILE` | ровно один из двух | либо путь к файлу, где в первой строке ключ base64 |
| `APP_ADMIN_USERNAME` + `APP_ADMIN_PASSWORD` | обе или ни одной | bootstrap первого администратора; работает **только на пустой БД**, пароль ≥ 12 символов |
| `APP_PORT` | нет | хост-порт веб-интерфейса, по умолчанию `8080` (маппинг `"${APP_PORT:-8080}:8080"`) |

Без `POSTGRES_USER`/`POSTGRES_PASSWORD` или без источника мастер-ключа
приложение намеренно **не стартует** (fail-fast по правилам безопасности
проекта). `APP_ADMIN_USERNAME`/`APP_ADMIN_PASSWORD` задаются только парой.

Пример заполненного `.env` (значения — ваши, не из этого документа):

```dotenv
POSTGRES_USER=vault
POSTGRES_PASSWORD=<длинный-случайный-пароль>
VAULT_MASTER_KEY_BASE64=<вывод openssl rand -base64 32>
APP_ADMIN_USERNAME=admin
APP_ADMIN_PASSWORD=<пароль-не-короче-12-символов>
# APP_PORT=8080
```

Ограничьте права на файл:

```bash
sudo chmod 600 .env
```

> **ВАЖНО про KEK.** Сохраните копию мастер-ключа (распечатанную или на
> отдельном носителе) **вне NAS** и отдельно от дампов БД: дамп содержит только
> шифротекст, и без того же KEK данные необратимо теряются
> (см. `docs/backup-restore.md`).

## 5. Шаг 3 (альтернативный ручной способ). Запуск через Container Manager

1. Откройте **Container Manager → Проект (Project) → Создать (Create)**.
2. Имя проекта: `safe-accounts` (рекомендуется — см. примечание ниже).
3. Источник: **Путь (Path)** → укажите
   `/docker/safe-accounts/docker-compose.yml`.
4. На шаге параметров ничего дополнительно вводить не нужно — значения
   берутся из `.env` в корне проекта. Нажмите **Далее**.
5. Проверьте сводку и нажмите **Готово (Done)** — начнется сборка образа
   `app` (Build). Дождитесь статуса «Запущено/Running» у обоих контейнеров.

> **Про имя проекта.** В `docker-compose.yml` зафиксировано `name: safe-accounts`,
> а скрипты `scripts/backup.sh` и `scripts/restore.sh` ищут контейнеры с
> суффиксом проекта (`safe-accounts-db-1`, `safe-accounts-app-1`). Если вы
> назвали проект иначе, скриптам нужно передавать переменную
> `COMPOSE_PROJECT_NAME=<имя-проекта>`.

## 6. Шаг 3 (альтернативный ручной способ). Запуск через SSH

Тот же результат из консоли (пользователь из группы администраторов):

```bash
cd /volume1/docker/safe-accounts
sudo docker compose up -d --build
```

## 7. Шаг 4. Проверка

```bash
cd /volume1/docker/safe-accounts
sudo docker compose ps          # db и app должны быть healthy
sudo docker compose logs -f app # журнал приложения
```

В журнале `app` при первом старте видны примененные миграции Flyway и,
когда схема актуальна, сообщение вида `Schema "public" is up to date`.
В Container Manager тот же журнал: Контейнер → «Журнал» (Details → Log).

```bash
curl http://IP_NAS:8080/actuator/health   # {"status":"UP"}
```

Веб-интерфейс: `http://IP_NAS:8080/` → редирект на `/web/login`.
Первый вход — администратор из `APP_ADMIN_USERNAME`/`APP_ADMIN_PASSWORD`;
bootstrap выполняется **только на пустой БД** (если пользователи уже есть,
запись пропускается). После первого входа обе переменные можно убрать
из `.env` — администратор уже создан.

Healthcheck `app` имеет `start_period: 60s` — сразу после запуска контейнер
может несколько десятков секунд оставаться в статусе `starting`, это штатно.

## 8. Шаг 5. Автозапуск после перезагрузки NAS (важно)

В `docker-compose.yml` у сервиса `db` указано `restart: "no"` — это осознанный
компромисс проекта: жизненным циклом БД управляет оператор и скрипты
обслуживания (`scripts/restore.sh` сам останавливает `app` перед
восстановлением и работает с уже запущенным `db`). Для NAS это означает:
**после перезагрузки NAS БД сама не поднимется** (сервис `app` поднимется
— у него `restart: unless-stopped`, но без БД он не сможет работать).

Решение — override-файл `docker-compose.synology.yml`: автоперезапуск только
для `db` плюс подвязка порта БД к localhost (наружу 5432 не публикуется).
Файл уже в репозитории; при деплое через GitLab CI он синхронизируется на
NAS автоматически (раздел 2). При ручном способе убедитесь, что файл есть
в корне проекта:

```yaml
services:
  db:
    restart: unless-stopped
    ports:
      - "127.0.0.1:5432:5432"
```

И используйте в SSH:

```bash
sudo docker compose -f docker-compose.yml -f docker-compose.synology.yml up -d --build
```

Дополнительно включите автозапуск в самом Container Manager:
**Настройки → Docker** → включить пункт «Запускать контейнеры при старте
Docker» (контейнеры проекта стартуют при запуске Container Manager/Docker).

**Компромисс.** С `restart: unless-stopped` БД после ребута NAS поднимается
автоматически, что и нужно на домашнем/офисном NAS. Поведение скриптов
обслуживания не ломается: `restore.sh` перед восстановлением сам
останавливает контейнер `app`, а остановленный вручную `db` Docker заново
не запускает (политика `unless-stopped` запоминает остановку) — ручной
рестарт по-прежнему требует явной команды оператора.

## 9. Шаг 6. Обновление версии (альтернативный ручной способ)

```bash
cd /volume1/docker/safe-accounts
sudo git pull
sudo docker compose -f docker-compose.yml -f docker-compose.synology.yml up -d --build
```

Данные БД живут в volume `pgdata` и при пересборке не теряются.
Примененные миграции Flyway не редактируются — новые изменения схемы
приходят новыми файлами `V<n>__description.sql`. Если override-файл не
используется, команда та же без `-f ...`.

## 10. Шаг 7. Бэкап и восстановление

Скрипты запускаются по SSH из папки проекта (docker на DSM вызывается
через `sudo`):

```bash
cd /volume1/docker/safe-accounts

# Бэкап: pg_dump (custom-формат) выполняется внутри контейнера БД,
# дамп переносится в ./backups/safe_accounts_<БД>_<метка времени>.dump
# с правами 600. Требуется запущенный контейнер safe-accounts-db-1.
sudo ./scripts/backup.sh

# Восстановление из дампа: проверяет дамп, останавливает контейнер app,
# делает pg_restore --clean --if-exists в целевую БД.
# Подтверждение вводится вручную (или ключ --force).
sudo ./scripts/restore.sh backups/safe_accounts_safe_accounts_20250101_030000.dump
```

После восстановления запустите приложение **с тем же мастер-ключом**, что
использовался при создании дампа, и проверьте `/actuator/health` и вход
(полный сценарий — `docs/backup-restore.md`).

Расписание: **Панель управления → Планировщик задач → Создать → Запланированная
задача → Пользовательский скрипт**. Пользователь — `root` (или администратор),
расписание — ежедневно, команда:

```bash
cd /volume1/docker/safe-accounts && ./scripts/backup.sh >> ./backups/backup.log 2>&1
```

Храните несколько поколений дампов (день/неделя/месяц), копию — вне NAS.
**Мастер-ключ (KEK) храните отдельно от дампов**: дамп без KEK бесполезен
злоумышленнику, но и вы без KEK данные не восстановите.

## 11. Шаг 8 (опционально). Docker secrets вместо пароля в `.env`

Если не хотите держать пароль БД в `.env`, используйте режим secrets —
compose-файл `docker-compose.secrets.yml` монтирует файлы в `/run/secrets`
и задает переменные `POSTGRES_PASSWORD_FILE=/run/secrets/db_password` и
`VAULT_MASTER_KEY_FILE=/run/secrets/master_key`; entrypoint контейнера читает
файлы, не выводя содержимое в логи.

```bash
cd /volume1/docker/safe-accounts
sudo mkdir -p secrets && sudo chmod 700 secrets
echo -n '<пароль БД>'  | sudo tee secrets/db_password.txt >/dev/null
sudo openssl rand -base64 32 | sudo tee secrets/master_key.txt >/dev/null
sudo chmod 600 secrets/*
sudo docker compose -f docker-compose.yml -f docker-compose.secrets.yml up -d --build
```

Ожидаемые файлы: `secrets/db_password.txt` (пароль БД) и
`secrets/master_key.txt` (ключ base64 в первой строке). В этом режиме
`POSTGRES_PASSWORD` из `.env` контейнеру `app` не нужен; для сервиса `db`
пароль БД задается переменной `POSTGRES_PASSWORD`, поэтому в `.env` в любом
случае оставляют ее значение (либо применяют secrets-режим только к `app`,
как описано в `docs/deployment.md` §4, режим 2).

## 12. Troubleshooting

| Симптом | Причина и решение |
|---|---|
| Ошибка интерполяции вида `POSTGRES_USER is required` при старте | Нет `.env` рядом с `docker-compose.yml` или переменные не заполнены. Заполните `.env` (§4) и пересоздайте проект |
| Порт 8080 на NAS уже занят | Задайте в `.env` другой `APP_PORT` (например `8081`) и пересоздайте проект (`docker compose up -d`) |
| Старт падает: `Admin bootstrap misconfigured: set both APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD` | Задана только одна из переменных `APP_ADMIN_*`. Задайте обе или уберите обе |
| Старт падает: `Admin bootstrap failed: invalid configuration` | Пароль администратора не проходит политику — нужен **≥ 12 символов** (до 128) |
| Приложение не стартует, в журнале требование мастер-ключа | Не задан ни `VAULT_MASTER_KEY_BASE64`, ни `VAULT_MASTER_KEY_FILE`. Задайте ровно один источник KEK (§4) |
| Контейнер `app` в статусе `unhealthy` / `starting` дольше минуты | Смотрите журнал: Container Manager → Журнал контейнера или `sudo docker compose logs -f app`. Healthcheck — `wget /actuator/health` c `start_period 60s`; ошибка внутри — причина в журнале Spring (например, недоступна БД) |
| Контейнер `db` не запустился после перезагрузки NAS | Это `restart: "no"` из основного compose-файла. Подключите override `docker-compose.synology.yml` с `restart: unless-stopped` (§8) |
| Сборка на ARM-NAS идет очень долго | Нормально: внутри Dockerfile собирается Maven-проект. Дождитесь завершения, последующие пересборки быстрее за счет кэша слоев |
| Скрипты `backup.sh`/`restore.sh` пишут «Контейнер БД не найден» | Имя compose-проекта отличается от `safe-accounts`. Запускайте с `COMPOSE_PROJECT_NAME=<имя-проекта>` или назовите проект `safe-accounts` (§5) |

## 13. Где что лежит на NAS

| Что | Где |
|---|---|
| Код проекта, compose-файлы, скрипты | `/volume1/docker/safe-accounts` |
| `.env` (секреты окружения) | `/volume1/docker/safe-accounts/.env` (права `600`) |
| Override автозапуска БД и порта БД (localhost) | `/volume1/docker/safe-accounts/docker-compose.synology.yml` — в репозитории, синхронизируется CI |
| Override CI-деплоя (образ из registry) | `/volume1/docker/safe-accounts/docker-compose.deploy.yml` — в репозитории, синхронизируется CI |
| Файлы Docker secrets (опц.) | `/volume1/docker/safe-accounts/secrets/` (`db_password.txt`, `master_key.txt`) |
| Дампы бэкапов | `/volume1/docker/safe-accounts/backups/` (создает `backup.sh`, права `600`) |
| Данные БД (volume `pgdata`) | `/volume1/@docker/volumes/safe-accounts_pgdata/_data` — служебная папка Docker, по SSH; вручную не изменять, бэкап только через `backup.sh` |
| Журналы контейнеров | Container Manager → Контейнер → Журнал; либо `sudo docker compose logs` |
