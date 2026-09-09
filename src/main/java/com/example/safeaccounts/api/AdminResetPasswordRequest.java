package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Сброс пароля администратором (Task-06): задается новое значение пароля.
 * Пароль никогда не логируется; после сброса отзываются все токены пользователя.
 */
public record AdminResetPasswordRequest(
        @NotBlank
        @Size(min = 12, max = 128)
        String newPassword) {
}
