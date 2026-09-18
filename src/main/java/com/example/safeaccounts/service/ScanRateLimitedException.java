package com.example.safeaccounts.service;

/**
 * Квота скана слабых паролей исчерпана (G2): 1 запуск/60 c на пользователя.
 * Маппится в 429 ProblemDetail + Retry-After (ApiExceptionHandler).
 * Деталей аккаунта/сейфа не содержит.
 */
public class ScanRateLimitedException extends RuntimeException {

    private final long retryAfterSeconds;

    public ScanRateLimitedException(long retryAfterSeconds) {
        super("Too many scan requests, try again later");
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
