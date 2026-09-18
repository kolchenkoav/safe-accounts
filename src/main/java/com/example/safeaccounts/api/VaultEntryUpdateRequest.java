package com.example.safeaccounts.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос на обновление записи сейфа (Task-05; G1: пароль опционален).
 * name/site/login заменяются целиком.
 * <p>
 * password — ОПЦИОНАЛЕН: {@code null} или пустая строка означают
 * «не менять пароль» — сервис сохраняет прежний шифротекст и IV,
 * перешифровка не выполняется. Непустое значение перешифровывается новым IV,
 * как раньше. Create (`VaultEntryCreateRequest`) по-прежнему требует пароль.
 */
public record VaultEntryUpdateRequest(
        @NotBlank
        @Size(max = 256)
        String name,

        @NotBlank
        @Size(max = 2048)
        String site,

        @NotBlank
        @Size(max = 2048)
        String login,

        @Size(max = 4096)
        String password,

        @Size(max = 8192)
        String notes) {
}
