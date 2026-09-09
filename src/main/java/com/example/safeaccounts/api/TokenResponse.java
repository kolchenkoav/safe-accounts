package com.example.safeaccounts.api;

import java.time.Instant;
import java.util.UUID;

/**
 * Ответ при выпуске Bearer-токена. Токен возвращается РОВНО ОДИН РАЗ
 * при выпуске и никогда не логируется; в БД хранится только SHA-256 хэш.
 */
public record TokenResponse(
        UUID tokenId,
        String accessToken,
        Instant expiresAt) {
}
