package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Детальный ответ записи сейфа (GET /api/vault/{id}).
 * Пароль возвращается ТОЛЬКО при явном {@code ?reveal=true} (Task-05);
 * без reveal поле password отсутствует в JSON.
 */
public record VaultEntryDetailResponse(
        UUID id,
        String name,
        String site,
        String login,
        String password,
        String notes,
        Instant createdAt,
        Instant updatedAt,
        long version) {

    /** Фабрика ответа без расшифрованного пароля (reveal=false). */
    public static VaultEntryDetailResponse withoutPassword(
            UUID id, String name, String site, String login, String notes,
            Instant createdAt, Instant updatedAt, long version) {
        return new VaultEntryDetailResponse(id, name, site, login, null, notes, createdAt, updatedAt, version);
    }
}