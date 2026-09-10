# Развертывание safe-accounts на Synology NAS

Пошаговая инструкция для NAS Synology с DSM 7.2+ и Container Manager.
Общая инструкция развертывания (переменные окружения, secrets, TLS) —
`docs/deployment.md`; бэкап/восстановление — `docs/backup-restore.md`.

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

## 2. Шаг 1. Получить код на NAS

Проект удобно держать в общей папке docker: `/volume1/docker`.

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

## 3. Шаг 2. Подготовить `.env`

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

## 4. Шаг 3 (основной путь). Запуск через Container Manager

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

## 5. Шаг 3 (альтернатива). Запуск через SSH

Тот же результат из консоли (пользователь из группы администраторов):

```bash
cd /volume1/docker/safe-accounts
sudo docker compose up -d --build
```

## 6. Шаг 4. Проверка

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

## 7. Шаг 5. Автозапуск после перезагрузки NAS (важно)

В `docker-compose.yml` у сервиса `db` указано `restart: "no"` — это осознанный
компромисс проекта: жизненным циклом БД управляет оператор и скрипты
обслуживания (`scripts/restore.sh` сам останавливает `app` перед
восстановлением и работает с уже запущенным `db`). Для NAS это означает:
**после перезагрузки NAS БД сама не поднимется** (сервис `app` поднимется
— у него `restart: unless-stopped`, но без БД он не сможет работать).

Решение — override-файл, включающий автоперезапуск только для `db`.
Создайте в корне проекта файл `docker-compose.synology.yml`:

```yaml
# Override для Synology NAS: поднимать БД автоматически после перезагрузки NAS.
# Запуск:
#   docker compose -f docker-compose.yml -f docker-compose.synology.yml up -d --build
# В Container Manager тот же файл добавляется на шаге проекта
# («использовать несколько compose-файлов» / путь к основному + override).
services:
  db:
    restart: unless-stopped
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

## 8. Шаг 6. Обновление версии

```bash
cd /volume1/docker/safe-accounts
sudo git pull
sudo docker compose -f docker-compose.yml -f docker-compose.synology.yml up -d --build
```

Данные БД живут в volume `pgdata` и при пересборке не теряются.
Примененные миграции Flyway не редактируются — новые изменения схемы
приходят новыми файлами `V<n>__description.sql`. Если override-файл не
используется, команда та же без `-f ...`.

## 9. Шаг 7. Бэкап и восстановление

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

## 10. Шаг 8 (опционально). Docker secrets вместо пароля в `.env`

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

## 11. Troubleshooting

| Симптом | Причина и решение |
|---|---|
| Ошибка интерполяции вида `POSTGRES_USER is required` при старте | Нет `.env` рядом с `docker-compose.yml` или переменные не заполнены. Заполните `.env` (§3) и пересоздайте проект |
| Порт 8080 на NAS уже занят | Задайте в `.env` другой `APP_PORT` (например `8081`) и пересоздайте проект (`docker compose up -d`) |
| Старт падает: `Admin bootstrap misconfigured: set both APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD` | Задана только одна из переменных `APP_ADMIN_*`. Задайте обе или уберите обе |
| Старт падает: `Admin bootstrap failed: invalid configuration` | Пароль администратора не проходит политику — нужен **≥ 12 символов** (до 128) |
| Приложение не стартует, в журнале требование мастер-ключа | Не задан ни `VAULT_MASTER_KEY_BASE64`, ни `VAULT_MASTER_KEY_FILE`. Задайте ровно один источник KEK (§3) |
| Контейнер `app` в статусе `unhealthy` / `starting` дольше минуты | Смотрите журнал: Container Manager → Журнал контейнера или `sudo docker compose logs -f app`. Healthcheck — `wget /actuator/health` c `start_period 60s`; ошибка внутри — причина в журнале Spring (например, недоступна БД) |
| Контейнер `db` не запустился после перезагрузки NAS | Это `restart: "no"` из основного compose-файла. Подключите override `docker-compose.synology.yml` с `restart: unless-stopped` (§7) |
| Сборка на ARM-NAS идет очень долго | Нормально: внутри Dockerfile собирается Maven-проект. Дождитесь завершения, последующие пересборки быстрее за счет кэша слоев |
| Скрипты `backup.sh`/`restore.sh` пишут «Контейнер БД не найден» | Имя compose-проекта отличается от `safe-accounts`. Запускайте с `COMPOSE_PROJECT_NAME=<имя-проекта>` или назовите проект `safe-accounts` (§4) |

## 12. Где что лежит на NAS

| Что | Где |
|---|---|
| Код проекта, compose-файлы, скрипты | `/volume1/docker/safe-accounts` |
| `.env` (секреты окружения) | `/volume1/docker/safe-accounts/.env` (права `600`) |
| Override автозапуска БД | `/volume1/docker/safe-accounts/docker-compose.synology.yml` |
| Файлы Docker secrets (опц.) | `/volume1/docker/safe-accounts/secrets/` (`db_password.txt`, `master_key.txt`) |
| Дампы бэкапов | `/volume1/docker/safe-accounts/backups/` (создает `backup.sh`, права `600`) |
| Данные БД (volume `pgdata`) | `/volume1/@docker/volumes/safe-accounts_pgdata/_data` — служебная папка Docker, по SSH; вручную не изменять, бэкап только через `backup.sh` |
| Журналы контейнеров | Container Manager → Контейнер → Журнал; либо `sudo docker compose logs` |
