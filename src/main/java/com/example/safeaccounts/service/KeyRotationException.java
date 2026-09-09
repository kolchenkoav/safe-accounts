package com.example.safeaccounts.service;

/**
 * Ошибка ротации ключей (Task-06): DEK какого-то пользователя не удалось
 * распаковать старым KEK (например, ключ недоступен). Сообщение нейтральное,
 * не содержит материала ключей; уже перепакованные пользователи сохранены.
 */
public class KeyRotationException extends RuntimeException {

    public KeyRotationException(String message) {
        super(message);
    }
}
