package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Ответ API по тегу (Task-08, Фаза 5).
 * Возвращается на GET/POST /api/tags, PATCH /api/tags/{id},
 * GET/PUT /api/vault/{id}/tags. Никаких чувствительных данных:
 * теги хранятся в открытом виде, имя — не секрет.
 */
public record TagResponse(
        UUID id,
        String name,
        Instant createdAt) {
}
