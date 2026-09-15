package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Запрос на replace-all тегов записи (PUT /api/vault/{id}/tags).
 * Тело {@code {"tags":["work","personal"]}}: итоговый набор тегов
 * записи заменяется на указанный; отсутствующие теги создаются;
 * пустой список — снимает все теги с записи.
 * <p>
 * Никаких секретов — имена тегов не шифруются.
 */
public record TagReplaceRequest(
        @NotNull
        @Size(max = 64)
        List<@NotBlank
             @Size(max = 64)
             @Pattern(regexp = "^[a-zA-Z0-9 _\\-.]+$",
                     message = "tag name must match ^[a-zA-Z0-9 _\\\\-.]+$")
             String> tags) {
}
