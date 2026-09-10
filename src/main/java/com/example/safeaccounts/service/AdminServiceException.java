package com.example.safeaccounts.service;

/**
 * Ошибки административных операций веб-интерфейса (Task-12).
 * <p>
 * Сообщения нейтральные: не раскрывают внутренние детали и предназначены
 * для показа администратору как flash-сообщение. Секреты (пароли, токены,
 * материал ключей) в сообщениях запрещены.
 * <p>
 * Существующие REST-эндпоинты этот класс не используют — поведение API
 * не изменено (Task-12).
 */
public class AdminServiceException extends RuntimeException {

    public AdminServiceException(String message) {
        super(message);
    }
}
