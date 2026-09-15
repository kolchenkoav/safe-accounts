package com.example.safeaccounts.service.csv;

/**
 * Ошибка разбора/валидации CSV (синтаксис, отсутствие обязательной колонки,
 * невалидная UTF-8 и т.п.). Маппится в 400/422 RFC 7807 на уровне API.
 * Сообщения нейтральные: никаких расшифрованных секретов и самих значений.
 */
public class InvalidCsvException extends RuntimeException {

    public InvalidCsvException(String message) {
        super(message);
    }

    public InvalidCsvException(String message, Throwable cause) {
        super(message, cause);
    }
}