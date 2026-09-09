package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Создание пользователя администратором (Task-06).
 * Пароль передается только в теле запроса по TLS и никогда не логируется.
 */
public record AdminCreateUserRequest(
        @NotBlank
        @Size(min = 3, max = 64)
        @Pattern(regexp = "^[a-z0-9._-]{3,64}$", message = "username is invalid")
        String username,

        @NotBlank
        @Size(min = 12, max = 128)
        String password,

        /** ROLE_USER по умолчанию; ROLE_ADMIN разрешен явно. */
        @Pattern(regexp = "ROLE_USER|ROLE_ADMIN", message = "role is invalid")
        String role) {
}
