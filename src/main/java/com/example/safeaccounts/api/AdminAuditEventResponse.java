package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Событие аудита в админ-API (Task-06). Содержимое details_json в БД по
 * построению не содержит секретов; расшифрованные пароли/токены не возвращаются.
 */
public record AdminAuditEventResponse(
        UUID id,
        UUID userId,
        UUID tokenId,
        String type,
        String objectType,
        String objectId,
        String ipAddress,
        String userAgent,
        String detailsJson,
        Instant createdAt) {
}
