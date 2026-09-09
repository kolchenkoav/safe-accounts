#!/bin/sh
# Entrypoint контейнера приложения (Task-07).
# Поддерживает передачу пароля БД через файл секрета:
#   POSTGRES_PASSWORD_FILE=/run/secrets/db_password
# Читает файл и экспортирует SPRING_DATASOURCE_PASSWORD, затем запускает приложение.
# Значение файла никогда не выводится в логи.
set -eu

if [ -n "${POSTGRES_PASSWORD_FILE:-}" ]; then
  if [ -r "${POSTGRES_PASSWORD_FILE}" ]; then
    # Секрет из файла: пробельные символы по краям обрезаются, содержимое не логируется.
    password="$(tr -d '\r\n' < "${POSTGRES_PASSWORD_FILE}")"
    if [ -z "${password}" ]; then
      echo "POSTGRES_PASSWORD_FILE is empty" >&2
      exit 1
    fi
    export SPRING_DATASOURCE_PASSWORD="${password}"
  else
    echo "POSTGRES_PASSWORD_FILE is set but not readable: ${POSTGRES_PASSWORD_FILE}" >&2
    exit 1
  fi
fi

# Секреты больше не нужны в переменных окружения; JAVA_OPTS можно переопределить снаружи.
# app.jar имеет манифест с Class-Path -> lib/, поэтому запускается как обычный jar из /app.
exec java ${JAVA_OPTS:-} -jar /app/app.jar
