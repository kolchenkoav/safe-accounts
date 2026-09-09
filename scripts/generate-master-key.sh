#!/usr/bin/env bash
# Генерирует безопасный мастер-ключ (KEK) для safe-accounts: 32 случайных байта в base64.
# Вывод используется как значение переменной окружения VAULT_MASTER_KEY_BASE64.
#
# ВАЖНО:
#  - не сохраняйте вывод в файлы внутри репозитория и не передавайте его в логи/чаты;
#  - в .env.example ключ не записывается — только плейсхолдеры.
set -euo pipefail

if ! command -v openssl >/dev/null 2>&1; then
  echo "Ошибка: openssl не найден в PATH." >&2
  exit 1
fi

openssl rand -base64 32
