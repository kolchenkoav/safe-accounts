package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Запрос на создание тега (POST /api/tags).
 * Длина 1..64; допустимы буквы/цифры/пробел/_/-/.
 */
public record TagCreateRequest(
        @NotBlank
        @Size(max = 64)
        @Pattern(regexp = "^[a-zA-Z0-9 _\\-.]+$",
                message = "tag name must match ^[a-zA-Z0-9 _\\\\-.]+$")
        String name) {
}
