package com.example.safeaccounts.crypto;

/**
 * Wrapped-форма DEK, пригодная для хранения в БД (users.dek_wrapped/dek_iv/dek_kek_id).
 * Материал открытого DEK здесь отсутствует — только шифротекст и метаданные.
 *
 * @param wrappedDekBase64 base64(iv || wrapped-dek || tag), IV включен в контейнер
 * @param ivBase64         отдельный IV последней операции wrapping (base64), для users.dek_iv
 * @param kekId            идентификатор KEK, которым выполнен wrapping (не секрет)
 */
public record WrappedDek(String wrappedDekBase64, String ivBase64, String kekId) {

    public WrappedDek {
        if (wrappedDekBase64 == null || wrappedDekBase64.isBlank()) {
            throw new IllegalArgumentException("wrappedDek must not be blank");
        }
        if (ivBase64 == null || ivBase64.isBlank()) {
            throw new IllegalArgumentException("dek iv must not be blank");
        }
        if (kekId == null || kekId.isBlank()) {
            throw new IllegalArgumentException("kekId must not be blank");
        }
    }
}
