package com.example.safeaccounts.service;

/**
 * Ошибки аутентификации и управления пользователями (Task-04).
 * Сообщения нейтральные — не раскрывают, существует ли пользователь.
 */
public class AuthServiceException extends RuntimeException {

    public enum Reason {
        /** Неудачный вход (неверный логин или пароль). */
        BAD_CREDENTIALS,
        /** Учетная запись отключена администратором. */
        USER_DISABLED,
        /** Пользователь заблокирован после неудачных попыток входа. */
        USER_LOCKED,
        /** Имя пользователя занято. */
        USERNAME_TAKEN,
        /** Текущий пароль не совпал при смене пароля. */
        WRONG_CURRENT_PASSWORD,
        /** Требуемый пользователь не найден (внутренняя ошибка). */
        USER_NOT_FOUND
    }

    private final Reason reason;

    public AuthServiceException(Reason reason) {
        super(messageFor(reason));
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }

    private static String messageFor(Reason reason) {
        return switch (reason) {
            case BAD_CREDENTIALS -> "Invalid username or password";
            case USER_DISABLED -> "Account is disabled";
            case USER_LOCKED -> "Account is temporarily locked due to failed login attempts";
            case USERNAME_TAKEN -> "Username is already taken";
            case WRONG_CURRENT_PASSWORD -> "Current password is incorrect";
            case USER_NOT_FOUND -> "User not found";
        };
    }
}
