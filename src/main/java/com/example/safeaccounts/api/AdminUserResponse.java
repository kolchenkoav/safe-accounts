package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Ответ админ-API по пользователю (Task-06).
 * Никаких хэшей паролей и wrapped DEK внутри: только нечувствительные поля.
 */
public record AdminUserResponse(
        UUID id,
        String username,
        String role,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt) {
}
