package com.example.safeaccounts.service;

/**
 * Ошибки операций над записями сейфа (Task-05). Сообщения нейтральные:
 * не раскрывают ни существование чужих записей, ни причины ошибки расшифровки.
 */
public class VaultException extends RuntimeException {

    public enum Reason {
        /** Запись не найдена среди записей текущего пользователя. */
        NOT_FOUND,
        /** Не удалось расшифровать данные записи (повреждение, чужой DEK). */
        DECRYPTION_FAILED
    }

    private final Reason reason;

    public VaultException(Reason reason) {
        super(messageFor(reason));
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }

    private static String messageFor(Reason reason) {
        return switch (reason) {
            case NOT_FOUND -> "Vault entry not found";
            case DECRYPTION_FAILED -> "Unable to read vault entry";
        };
    }
}
