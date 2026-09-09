package com.example.safeaccounts.api;

import java.util.UUID;

/**
 * Информация о текущем пользователе (GET /api/me).
 * Никаких хэшей, DEK и служебных деталей наружу не отдается.
 */
public record MeResponse(
        UUID id,
        String username,
        String role) {
}
