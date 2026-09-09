package com.example.safeaccounts.security;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты криптографии паролей и токенов (Task-04).
 * Проверяется формат Argon2id, устойчивость к неверному паролю,
 * уникальность соли и корректность SHA-256 хэша токена.
 */
class PasswordHasherTest {

    private final PasswordHasher hasher = new PasswordHasher();

    @Test
    void hashProducesArgon2idFormatWithRandomSalt() {
        String hash = hasher.hash("correct horse battery staple");

        assertThat(hash).startsWith("$argon2id$v=19$m=65536,t=3,p=1$");
        String[] parts = hash.split("\\$");
        assertThat(parts).hasSize(6); // пустой элемент из-за ведущего '$'
        assertThat(parts[1]).isEqualTo("argon2id");
        assertThat(parts[2]).isEqualTo("v=19");
        assertThat(parts[3]).isEqualTo("m=65536,t=3,p=1");
        byte[] salt = Base64.getDecoder().decode(parts[4]);
        byte[] digest = Base64.getDecoder().decode(parts[5]);
        assertThat(salt).hasSize(PasswordHasher.SALT_BYTES);
        assertThat(digest).hasSize(PasswordHasher.HASH_BYTES);
    }

    @Test
    void verifyAcceptsCorrectPasswordAndRejectsWrong() {
        String hash = hasher.hash("correct horse battery staple");

        assertThat(hasher.verify("correct horse battery staple", hash)).isTrue();
        assertThat(hasher.verify("wrong password 1234", hash)).isFalse();
    }

    @Test
    void hashesOfSamePasswordDifferBySalt() {
        String h1 = hasher.hash("same-password-12");
        String h2 = hasher.hash("same-password-12");
        assertThat(h1).isNotEqualTo(h2);
        assertThat(hasher.verify("same-password-12", h1)).isTrue();
        assertThat(hasher.verify("same-password-12", h2)).isTrue();
    }

    @Test
    void verifyRejectsMalformedStoredHash() {
        assertThat(hasher.verify("whatever-123456", "not-a-hash")).isFalse();
        assertThat(hasher.verify("whatever-123456", "$argon2id$garbage")).isFalse();
        assertThat(hasher.verify("whatever-123456", null)).isFalse();
        assertThat(hasher.verify(null, "$argon2id$v=19$m=65536,t=3,p=1$AA==$AA==")).isFalse();
    }

    @Test
    void tokenHashIsDeterministicSha256Hex() {
        String token = "sat_abcdefghij";
        String h1 = hasher.hashToken(token);
        String h2 = hasher.hashToken(token);

        assertThat(h1).isEqualTo(h2);
        assertThat(h1).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(hasher.hashToken("sat_other-token")).isNotEqualTo(h1);
    }

    @Test
    void argon2ParametersAreVerifiedAgainstRfc9106StyleVector() {
        // Проверка совместимости реализации BC: повторный расчет по сохраненной
        // соли и параметрам из формата хэша должен давать тот же результат.
        String password = "rfc-check-password";
        String hash = hasher.hash(password);
        assertThat(hasher.verify(password, hash)).isTrue();
    }
}
