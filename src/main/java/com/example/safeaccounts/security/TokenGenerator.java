package com.example.safeaccounts.security;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Генерация Bearer-токенов доступа.
 * <p>
 * Требования Task-04 / AGENTS.md:
 * <ul>
 *   <li>криптографически случайный (SecureRandom);</li>
 *   <li>не менее 256 бит энтропии (32 случайных байта);</li>
 *   <li>формат: префикс + base64url (без padding).</li>
 * </ul>
 * Токен выдается вызывающему коду один раз и никогда не сохраняется и не логируется:
 * в БД попадает только SHA-256 хэш ({@link PasswordHasher#hashToken(String)}).
 */
@Component
public class TokenGenerator {

    /** Префикс токена — не секрет, позволяет распознавать формат при инцидентах. */
    public static final String TOKEN_PREFIX = "sat_";

    /** Случайных байт в токене (256 бит энтропии минимум). */
    static final int TOKEN_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Генерирует новый Bearer-токен вида {@code sat_<base64url-случайные-32-байта>}.
     */
    public String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return TOKEN_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** Не-секретная подсказка для UI: последние 4 символа токена. */
    public String hint(String token) {
        if (token == null || token.length() < 4) {
            return "…";
        }
        return "…" + token.substring(token.length() - 4);
    }
}
