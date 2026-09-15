package com.example.safeaccounts.service;

/**
 * Тег с таким именем уже существует у пользователя (case-insensitive).
 * Маппится в 409 Conflict (RFC 7807) на уровне API.
 * Сообщение нейтральное — не содержит имён тегов других пользователей.
 */
public class TagAlreadyExistsException extends RuntimeException {

    public TagAlreadyExistsException(String message) {
        super(message);
    }
}
