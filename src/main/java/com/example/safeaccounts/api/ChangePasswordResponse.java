package com.example.safeaccounts.api;

/**
 * Ответ на смену пароля.
 */
public record ChangePasswordResponse(int revokedTokens) {
}
