package com.example.safeaccounts.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Запрос логина (Task-04). Пароль передается только в теле запроса, не логируется.
 */
public record LoginRequest(
        @NotBlank
        @Size(max = 64)
        String username,

        @NotBlank
        @Size(max = 128)
        String password) {

    /** Защита от случайного вывода пароля в логи через toString()/log-репортеры. */
    @JsonIgnore
    @Override
    public String toString() {
        return "LoginRequest[username=" + username + "]";
    }
}
