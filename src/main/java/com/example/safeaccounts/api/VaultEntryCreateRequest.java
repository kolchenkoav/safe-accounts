package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос на создание записи сейфа (Task-05).
 * Пароль передается только по TLS в теле запроса; в логи никогда не пишется.
 */
public record VaultEntryCreateRequest(
        @NotBlank
        @Size(max = 2048)
        String site,

        @NotBlank
        @Size(max = 2048)
        String login,

        @NotBlank
        @Size(max = 4096)
        String password,

        @Size(max = 8192)
        String notes) {
}
