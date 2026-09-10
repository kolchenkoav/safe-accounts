#!/usr/bin/env bash
# safe-accounts: резервное копирование БД (Task-08).
#
# Использование:
#   ./scripts/backup.sh
#   COMPOSE_PROJECT_NAME=prod BACKUP_DIR=/var/backups/safe-accounts ./scripts/backup.sh
#
# Переменные окружения:
#   COMPOSE_PROJECT_NAME  имя docker compose проекта (по умолчанию: safe-accounts,
#                         соответствует "name:" в docker-compose.yml; можно переопределить)
#   BACKUP_DIR            каталог для дампов (по умолчанию: ./backups, создаётся автоматически)
#   POSTGRES_DB           имя БД (по умолчанию: safe_accounts)
#   POSTGRES_USER         имя пользователя БД (по умолчанию: postgres)
#
# Правила безопасности:
#   - скрипт не содержит и не печатает секретов;
#   - пароль БД внутри контейнера берётся из переменных окружения postgres-контейнера
#     (POSTGRES_PASSWORD), ему не нужен пароль на хосте;
#   - дамп шифрует данные пользователей (DEK wrapped KEK), но БЕЗ мастер-ключа
#     восстановить секреты нельзя: мастер-ключ бэкапится отдельно и вне этого скрипта.
#
# Формат: pg_dump в custom-формате (-Fc). Имя файла содержит временную метку.
set -euo pipefail

PROJECT="${COMPOSE_PROJECT_NAME:-safe-accounts}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
DB_NAME="${POSTGRES_DB:-safe_accounts}"
DB_USER="${POSTGRES_USER:-postgres}"
CONTAINER="${PROJECT}-db-1"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
mkdir -p "${BACKUP_DIR}"
OUT_FILE="${BACKUP_DIR}/safe_accounts_${DB_NAME}_${TIMESTAMP}.dump"

log() { printf '%s\n' "[backup] $*"; }
die() { printf '%s\n' "[backup] ОШИБКА: $*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker не найден в PATH."
command -v docker >/dev/null 2>&1 || true

docker inspect --format '{{.State.Status}}' "${CONTAINER}" >/dev/null 2>&1 || \
  die "Контейнер БД '${CONTAINER}' не найден. Задайте COMPOSE_PROJECT_NAME правильно."

STATUS="$(docker inspect --format '{{.State.Status}}' "${CONTAINER}")"
[ "${STATUS}" = "running" ] || die "Контейнер '${CONTAINER}' не запущен (status=${STATUS})."

log "Проект: ${PROJECT}; контейнер: ${CONTAINER}"
log "Дамп БД '${DB_NAME}' в ${OUT_FILE} ..."

# Дамп выполняется внутри postgres-контейнера (pg_dump той же версии, что и сервер).
# -Fc        : custom-формат (сжатие, для pg_restore);
# --no-owner : не переносить владельцев (при восстановлении объекты создаются от целевого пользователя);
# --no-privileges: не переносить GRANT/REVOKE (восстановление под целевого пользователя).
docker exec "${CONTAINER}" pg_dump \
  --username "${DB_USER}" \
  --dbname "${DB_NAME}" \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file /tmp/safe_accounts_backup.dump

# Переносим дамп на хост с правами только для чтения (0600): дамп содержит
# wrapped-секреты всех пользователей — обрабатывать его как чувствительные данные.
docker cp "${CONTAINER}:/tmp/safe_accounts_backup.dump" "${OUT_FILE}"
docker exec "${CONTAINER}" rm -f /tmp/safe_accounts_backup.dump
chmod 600 "${OUT_FILE}"

SIZE="$(wc -c < "${OUT_FILE}" | tr -d ' ')"
[ "${SIZE}" -gt 0 ] || die "Файл дампа пуст — резервная копия не создана."

log "Готово: ${OUT_FILE} (${SIZE} байт)"
log "ВАЖНО: мастер-ключ храните отдельно от дампа (см. docs/backup-restore.md)."
