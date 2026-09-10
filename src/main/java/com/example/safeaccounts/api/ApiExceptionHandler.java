package com.example.safeaccounts.api;

import com.example.safeaccounts.security.SensitiveDataMasker;
import com.example.safeaccounts.service.AuthServiceException;
import com.example.safeaccounts.service.VaultException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Единая обработка ошибок API в формате RFC 7807 ProblemDetail.
 * Стектрейсы наружу не возвращаются; детали ошибок нейтральные.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthServiceException.class)
    public ResponseEntity<ProblemDetail> handleAuth(AuthServiceException e) {
        HttpStatus status = switch (e.getReason()) {
            case BAD_CREDENTIALS, WRONG_CURRENT_PASSWORD -> HttpStatus.UNAUTHORIZED;
            case USER_LOCKED -> HttpStatus.LOCKED; // 423: учетная запись временно заблокирована
            case USER_DISABLED -> HttpStatus.FORBIDDEN;
            case USERNAME_TAKEN -> HttpStatus.CONFLICT;
            case USER_NOT_FOUND -> HttpStatus.NOT_FOUND;
        };
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, e.getMessage()));
    }

    /** Ошибки операций над записями сейфа (Task-05): безопасные нейтральные ответы. */
    @ExceptionHandler(VaultException.class)
    public ResponseEntity<ProblemDetail> handleVault(VaultException e) {
        HttpStatus status = switch (e.getReason()) {
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case DECRYPTION_FAILED -> HttpStatus.CONFLICT; // данные нечитаемы, но детали не раскрываем
        };
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, e.getMessage()));
    }

    /** Отказ в доступе к административным функциям (Task-06): 403 без деталей. */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException e) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Access denied"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleValidation(IllegalArgumentException e) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        // Task-09: маскирование на случай, если сообщение исключения содержит секрет.
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        SensitiveDataMasker.mask(neutralize(e.getMessage()))));
    }

    /** Ошибки валидации jakarta.validation (например, короткий пароль). */
    @ExceptionHandler(org.springframework.web.bind.MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleBeanValidation(
            org.springframework.web.bind.MethodArgumentNotValidException e) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        String detail = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(fe -> fe.getField() + " is invalid")
                .orElse("Invalid request");
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, detail));
    }

    /** Ошибки HttpMessageConverter (некорректный JSON и т.п.). */
    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<ProblemDetail> handleUnreadable(
            org.springframework.http.converter.HttpMessageNotReadableException e) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Malformed request body"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleUnexpected(Exception e) {
        // Task-11: ResponseStatusException уже несет корректный статус
        // (например 404 для чужих записей веб-интерфейса) — не превращаем в 500.
        if (e instanceof org.springframework.web.server.ResponseStatusException rse) {
            HttpStatus status = HttpStatus.valueOf(rse.getStatusCode().value());
            return ResponseEntity.status(status)
                    .body(ProblemDetail.forStatusAndDetail(status,
                            status == HttpStatus.NOT_FOUND ? "Vault entry not found" : "Internal error"));
        }
        // Стектрейс и внутренние детали наружу не раскрываются.
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Internal error"));
    }

    private static String neutralize(String message) {
        return message == null ? "Invalid request" : message;
    }
}
