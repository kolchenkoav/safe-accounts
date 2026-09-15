package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Элемент списка записей сейфа (GET /api/vault). Пароль и примечание
 * НЕ возвращаются (AGENTS.md / Task-05); только метаданные, метка, сайт и логин.
 */
public record VaultEntryListItemResponse(
        UUID id,
        String name,
        String site,
        String login,
        Instant createdAt,
        Instant updatedAt,
        long version) {
}