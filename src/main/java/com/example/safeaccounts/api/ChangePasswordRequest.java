package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос смены пароля (Task-04). Текущий пароль нужен для подтверждения.
 */
public record ChangePasswordRequest(
        @NotBlank
        @Size(max = 128)
        String currentPassword,

        @NotBlank
        @Size(min = 12, max = 128)
        String newPassword) {
}
