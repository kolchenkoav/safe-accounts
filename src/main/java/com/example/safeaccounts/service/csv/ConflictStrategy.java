package com.example.safeaccounts.service.csv;

/**
 * Стратегия разрешения конфликтов при импорте CSV: пара {@code (site, username)}
 * уже существует у целевого пользователя.
 */
public enum ConflictStrategy {

    /** Пропустить запись (default). Никаких изменений. */
    SKIP,

    /** Перезаписать существующую запись (новые IV, сохраняются id/createdAt). */
    UPSERT
}