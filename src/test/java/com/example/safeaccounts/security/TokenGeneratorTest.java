package com.example.safeaccounts.security;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты генератора Bearer-токенов (Task-04):
 * формат prefix + base64url, >= 256 бит энтропии, уникальность.
 */
class TokenGeneratorTest {

    private final TokenGenerator generator = new TokenGenerator();

    @Test
    void tokenHasPrefixAndBase64urlAlphabet() {
        String token = generator.generate();
        assertThat(token).startsWith(TokenGenerator.TOKEN_PREFIX);
        String payload = token.substring(TokenGenerator.TOKEN_PREFIX.length());
        assertThat(payload).matches("[A-Za-z0-9_-]+"); // base64url, без padding
    }

    @Test
    void tokenCarriesAtLeast256BitsOfEntropy() {
        String token = generator.generate();
        String payload = token.substring(TokenGenerator.TOKEN_PREFIX.length());
        int bytes = Base64.getUrlDecoder().decode(payload).length;
        assertThat(bytes * 8).isGreaterThanOrEqualTo(256);
    }

    @Test
    void tokensAreUniqueAcrossManyGenerations() {
        Set<String> tokens = new HashSet<>();
        for (int i = 0; i < 1000; i++) {
            tokens.add(generator.generate());
        }
        assertThat(tokens).hasSize(1000);
    }

    @Test
    void hintNeverContainsTheWholeToken() {
        String token = generator.generate();
        String hint = generator.hint(token);
        assertThat(hint).hasSizeLessThan(6);
        assertThat(token.endsWith(hint.substring(1))).isTrue();
        assertThat(hint).doesNotContain(token.substring(0, token.length() - 5));
    }
}
