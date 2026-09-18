package com.example.safeaccounts.service;

/**
 * Попытка переименовать системный тег сканера «weak-password»
 * или переименовать другой тег В него (G2, план feat-weak-password-scan).
 * REST → 409 (ApiExceptionHandler), web → flash (WebTagController).
 */
public class TagReservedNameException extends RuntimeException {

    private final String reservedName;

    public TagReservedNameException(String reservedName) {
        super("Tag name is reserved: " + reservedName);
        this.reservedName = reservedName;
    }

    public String getReservedName() {
        return reservedName;
    }
}
