package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос на обновление записи сейфа (Task-05).
 * Все поля заменяются целиком; пароль перешифровывается новым IV.
 */
public record VaultEntryUpdateRequest(
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
