package com.example.safeaccounts.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты маскирования чувствительных полей (Task-09):
 * password, token, secret, authorization, Bearer-токены, sat_ токены.
 */
class SensitiveDataMaskerTest {

    @Test
    void masksPasswordField() {
        assertThat(SensitiveDataMasker.mask("{\"username\":\"u\",\"password\":\"Secret123!\"}"))
                .isEqualTo("{\"username\":\"u\",\"password\":\"***\"}");
    }

    @Test
    void masksTokenAndSecretFields() {
        assertThat(SensitiveDataMasker.mask("token=abc123;secret=xyz"))
                .doesNotContain("abc123")
                .doesNotContain("xyz")
                .contains("***");
    }

    @Test
    void masksAuthorizationHeader() {
        assertThat(SensitiveDataMasker.mask("Authorization: Bearer sat_verysecrettoken"))
                .doesNotContain("verysecrettoken");
    }

    @Test
    void masksBearerTokens() {
        assertThat(SensitiveDataMasker.mask("Bearer sk-live-abcdef123456"))
                .doesNotContain("abcdef123456")
                .contains("Bearer ***");
    }

    @Test
    void masksApplicationTokens() {
        assertThat(SensitiveDataMasker.mask("received token sat_AbC123xyz456 for user"))
                .doesNotContain("AbC123xyz456");
    }

    @Test
    void leavesNonSensitiveTextIntact() {
        String text = "User iso-alice failed login attempt 3";
        assertThat(SensitiveDataMasker.mask(text)).isEqualTo(text);
    }

    @Test
    void handlesNullAndEmpty() {
        assertThat(SensitiveDataMasker.mask(null)).isNull();
        assertThat(SensitiveDataMasker.mask("")).isEmpty();
    }

    @Test
    void masksCaseInsensitively() {
        assertThat(SensitiveDataMasker.mask("PASSWORD=topsecret"))
                .doesNotContain("topsecret");
        assertThat(SensitiveDataMasker.mask("Token: abcdef"))
                .doesNotContain("abcdef");
    }

    @Test
    void masksJsonStyleFields() {
        String masked = SensitiveDataMasker.mask(
                "{\"password\":\"P@ssw0rd!\",\"masterKey\":\"AAAA\"}");
        assertThat(masked).doesNotContain("P@ssw0rd!");
    }
}
