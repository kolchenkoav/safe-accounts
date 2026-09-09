package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос на регистрацию нового пользователя (Task-04).
 * Пароль передается только в теле запроса по TLS, никогда не логируется.
 */
public record RegisterRequest(
        @NotBlank
        @Size(min = 3, max = 64)
        String username,

        @NotBlank
        @Size(min = 12, max = 128)
        String password) {
}
