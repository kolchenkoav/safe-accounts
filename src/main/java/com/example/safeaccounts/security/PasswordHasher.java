package com.example.safeaccounts.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Хэширование паролей (Argon2id через Bouncy Castle) и хэширование Bearer-токенов.
 * <p>
 * Argon2id — требование AGENTS.md: устойчив к GPU/ASIC-атакам, память 64 МиБ,
 * 3 итерации, 1 поток (OWASP-совместимые параметры для серверных приложений).
 * Формат хэша: {@code $argon2id$v=19$m=65536,t=3,p=1$<salt-b64>$<hash-b64>} —
 * совместим с spring-security-crypto, может быть проверен штатно при миграции.
 * <p>
 * Хэш Bearer-токена — SHA-256: токен сам по себе криптографически случайный
 * (256+ бит энтропии), поэтому перебор невозможен и медленный KDF не требуется.
 * <p>
 * Безопасность: открытый пароль и сгенерированный токен никогда не логируются.
 */
@Component
public class PasswordHasher {

    /** Память Argon2id в КиБ (64 МиБ). */
    static final int ARGON2_MEMORY_KIB = 64 * 1024;
    /** Итерации Argon2id. */
    static final int ARGON2_ITERATIONS = 3;
    /** Потоки Argon2id. */
    static final int ARGON2_PARALLELISM = 1;
    /** Длина выходного хэша в байтах. */
    static final int HASH_BYTES = 32;
    /** Длина соли в байтах. */
    static final int SALT_BYTES = 16;

    private static final String PREFIX = "$argon2id$";

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Хэширует пароль Argon2id со случайной солью.
     *
     * @return сериализованный хэш вида $argon2id$v=19$m=..,t=..,p=1$salt$hash
     */
    public String hash(String rawPassword) {
        byte[] salt = new byte[SALT_BYTES];
        secureRandom.nextBytes(salt);
        byte[] hash = argon2id(rawPassword, salt);
        return PREFIX + "v=19$m=" + ARGON2_MEMORY_KIB + ",t=" + ARGON2_ITERATIONS
                + ",p=" + ARGON2_PARALLELISM
                + "$" + java.util.Base64.getEncoder().encodeToString(salt)
                + "$" + java.util.Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Проверяет пароль против сохраненного Argon2id-хэша.
     * Постоянновременное сравнение; при поврежденном хэше возвращает false.
     */
    public boolean verify(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || !storedHash.startsWith(PREFIX)) {
            return false;
        }
        try {
            // parts: ["v=19", "m=..,t=..,p=..", salt-b64, hash-b64]
            String[] parts = storedHash.substring(PREFIX.length()).split("\\$");
            String[] params = parts[1].split(",");
            int memory = Integer.parseInt(params[0].substring(2));
            int iterations = Integer.parseInt(params[1].substring(2));
            int parallelism = Integer.parseInt(params[2].substring(2));
            byte[] salt = java.util.Base64.getDecoder().decode(parts[2]);
            byte[] expected = java.util.Base64.getDecoder().decode(parts[3]);
            byte[] actual = argon2id(rawPassword, salt, memory, iterations, parallelism);
            return MessageDigest.isEqual(expected, actual);
        } catch (RuntimeException e) {
            // Поврежденный/неожиданный формат: пароль неверен, детали не раскрываем.
            return false;
        }
    }

    /** SHA-256 (hex) Bearer-токена для хранения в auth_tokens.token_hash. */
    public String hashToken(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(Character.forDigit((b >> 4) & 0xF, 16));
                hex.append(Character.forDigit(b & 0xF, 16));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is always available", e);
        }
    }

    private byte[] argon2id(String rawPassword, byte[] salt) {
        return argon2id(rawPassword, salt, ARGON2_MEMORY_KIB, ARGON2_ITERATIONS, ARGON2_PARALLELISM);
    }

    private byte[] argon2id(String rawPassword, byte[] salt, int memoryKib, int iterations, int parallelism) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withSalt(salt)
                .withMemoryAsKB(memoryKib)
                .withIterations(iterations)
                .withParallelism(parallelism)
                .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] hash = new byte[HASH_BYTES];
        generator.generateBytes(rawPassword.getBytes(StandardCharsets.UTF_8), hash);
        return hash;
    }
}
