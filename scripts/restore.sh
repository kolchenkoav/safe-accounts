#!/usr/bin/env bash
# safe-accounts: восстановление БД из дампа (Task-08).
#
# Использование:
#   ./scripts/restore.sh backups/safe_accounts_safe_accounts_20260101_120000.dump
#   ./scripts/restore.sh backups/....dump --force   # не спрашивать подтверждение
#
# Переменные окружения:
#   COMPOSE_PROJECT_NAME  имя docker compose проекта (по умолчанию: safe-accounts)
#   POSTGRES_DB           целевая БД (по умолчанию: safe_accounts)
#   POSTGRES_USER         целевой пользователь БД (по умолчанию: postgres)
#
# Правила безопасности:
#   - скрипт не содержит и не печатает секретов;
#   - восстановление выполняется от целевого пользователя БД внутри его контейнера;
#   - после восстановления секреты читаются только при наличии того же мастер-ключа,
#     с которым они были зашифрованы (VAULT_MASTER_KEY_BASE64 / VAULT_MASTER_KEY_FILE).
set -euo pipefail

PROJECT="${COMPOSE_PROJECT_NAME:-safe-accounts}"
DB_NAME="${POSTGRES_DB:-safe_accounts}"
DB_USER="${POSTGRES_USER:-postgres}"
CONTAINER="${PROJECT}-db-1"

log() { printf '%s\n' "[restore] $*"; }
die() { printf '%s\n' "[restore] ОШИБКА: $*" >&2; exit 1; }

usage() {
  cat >&2 <<EOF
Использование: $0 <файл-дампа> [--force]
Файл дампа создаётся скриптом scripts/backup.sh (формат pg_dump -Fc).
EOF
  exit 2
}

[ $# -ge 1 ] || usage
DUMP_FILE="$1"; shift
FORCE=0
for arg in "$@"; do
  case "${arg}" in
    --force) FORCE=1 ;;
    *) usage ;;
  esac
done

command -v docker >/dev/null 2>&1 || die "docker не найден в PATH."
[ -f "${DUMP_FILE}" ] || die "Файл дампа не найден: ${DUMP_FILE}"
[ -s "${DUMP_FILE}" ] || die "Файл дампа пуст: ${DUMP_FILE}"

docker inspect --format '{{.State.Status}}' "${CONTAINER}" >/dev/null 2>&1 || \
  die "Контейнер БД '${CONTAINER}' не найден. Задайте COMPOSE_PROJECT_NAME правильно."
STATUS="$(docker inspect --format '{{.State.Status}}' "${CONTAINER}")"
[ "${STATUS}" = "running" ] || die "Контейнер '${CONTAINER}' не запущен (status=${STATUS})."

log "Целевая БД: ${DB_NAME} (контейнер ${CONTAINER})"

# Проверка целевой БД: база должна существовать и быть доступной.
if ! docker exec "${CONTAINER}" psql --username "${DB_USER}" --dbname postgres --tuples-only --no-align \
     --command "SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}';" | grep -q 1; then
  die "БД '${DB_NAME}' не существует в контейнере. Создайте её: POSTGRES_DB=${DB_NAME} docker compose up -d db"
fi

# Проверка целостности дампа до начала восстановления.
log "Проверка дампа: ${DUMP_FILE}"
docker cp "${DUMP_FILE}" "${CONTAINER}:/tmp/safe_accounts_restore.dump"
if ! docker exec "${CONTAINER}" pg_restore --list /tmp/safe_accounts_restore.dump >/dev/null 2>&1; then
  docker exec "${CONTAINER}" rm -f /tmp/safe_accounts_restore.dump
  die "Файл не является корректным дампом pg_dump (custom-формат)."
fi

# Предупреждение: восстановление перезаписывает данные целевой БД.
# Остановка приложения (если оно в этом же compose-проекте) выполняется только с согласия
# оператора, чтобы не выполнять разрушительное действие незаметно.
if [ "${FORCE}" -ne 1 ]; then
  printf '[restore] ВНИМАНИЕ: данные БД "%s" будут ПЕРЕЗАПИСАНЫ из дампа %s\n' "${DB_NAME}" "${DUMP_FILE}"
  printf '[restore] Приложение safe-accounts на время восстановления рекомендуется остановить:\n'
  printf '[restore]   docker compose -p %s stop app\n' "${PROJECT}"
  printf '[restore] Продолжить? (введите yes): '
  read -r ANSWER
  [ "${ANSWER}" = "yes" ] || die "Отменено пользователем."
fi

log "Остановка приложения (если контейнер app запущен)..."
docker stop "${PROJECT}-app-1" >/dev/null 2>&1 || log "Контейнер app не запущен — пропускаю."

log "Восстановление схемы и данных из дампа..."
# --clean --if-exists : DROP объектов перед CREATE (идемпотентный повторный запуск)
# --if-exists         : без ошибок, если объекта ещё нет
# --no-owner --no-privileges: объекты создаются от целевого пользователя (как в Task-07)
if ! docker exec "${CONTAINER}" pg_restore \
    --username "${DB_USER}" \
    --dbname "${DB_NAME}" \
    --clean --if-exists \
    --no-owner --no-privileges \
    /tmp/safe_accounts_restore.dump; then
  docker exec "${CONTAINER}" rm -f /tmp/safe_accounts_restore.dump
  die "pg_restore завершился с ошибкой. Проверьте лог выше."
fi
docker exec "${CONTAINER}" rm -f /tmp/safe_accounts_restore.dump

log "Восстановление завершено."
log "Дальнейшие шаги:"
log "  1) Запустите приложение с ТЕМ ЖЕ мастер-ключом, что использовался при создании дампа."
log "  2) Проверьте /actuator/health и вход пользователя."
log "  3) Убедитесь, что записи сейфа расшифровываются (см. docs/backup-restore.md)."
