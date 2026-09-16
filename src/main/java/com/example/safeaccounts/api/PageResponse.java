package com.example.safeaccounts.api;

import java.util.List;

/**
 * Пагинированный ответ API (P5 рефакторинга пакетов: единая форма для
 * AdminController и VaultController — обе 5-полевые и идентичные; nested
 * в VaultController оставлен только для минимизации churn, унификация
 * использования — отдельная задача, сейчас НЕ выполнялась).
 * <p>
 * JSON-контракт /api/admin/users, /api/admin/audit и /api/vault не менялся.
 */
public record PageResponse<T>(
        int page,
        int size,
        long totalElements,
        int totalPages,
        List<T> content) {
}
