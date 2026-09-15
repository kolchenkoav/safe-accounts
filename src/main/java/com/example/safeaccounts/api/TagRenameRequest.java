package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Запрос на переименование тега (PATCH /api/tags/{id}).
 * Те же правила, что и при создании: 1..64 символа, regex
 * {@code ^[a-zA-Z0-9 _\\-.]+$}, уникальность case-insensitive.
 */
public record TagRenameRequest(
        @NotBlank
        @Size(max = 64)
        @Pattern(regexp = "^[a-zA-Z0-9 _\\-.]+$",
                message = "tag name must match ^[a-zA-Z0-9 _\\\\-.]+$")
        String name) {
}
