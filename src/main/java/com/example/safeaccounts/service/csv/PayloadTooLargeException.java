package com.example.safeaccounts.service.csv;

/**
 * Превышение лимита на размер CSV (10 МБ) или количество записей экспорта (10 000).
 * Маппится в 413 Payload Too Large (RFC 7807) на уровне API.
 */
public class PayloadTooLargeException extends RuntimeException {

    public PayloadTooLargeException(String message) {
        super(message);
    }
}