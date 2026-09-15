package com.example.safeaccounts.service;

/**
 * Тег всё ещё привязан хотя бы к одной записи; удаление запрещено
 * (план, раздел 5 п.1). Маппится в 409 Conflict (RFC 7807) на уровне API.
 * Сообщение нейтральное — без раскрытия количества или идентификаторов записей.
 */
public class TagStillReferencedException extends RuntimeException {

    public TagStillReferencedException(String message) {
        super(message);
    }
}
