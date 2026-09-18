package com.example.safeaccounts.api;

import com.example.safeaccounts.security.SensitiveDataMasker;
import com.example.safeaccounts.service.AuthServiceException;
import com.example.safeaccounts.service.TagAlreadyExistsException;
import com.example.safeaccounts.service.TagStillReferencedException;
import com.example.safeaccounts.service.VaultException;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import com.example.safeaccounts.service.csv.PayloadTooLargeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Единая обработка ошибок API в формате RFC 7807 ProblemDetail.
 * Стектрейсы наружу не возвращаются; детали ошибок нейтральные.
 * <p>
 * Скоуп — только api-пакет (fix cycle 2): catch-all Exception.class больше
 * не перехватывает web-контроллеры, где ошибки обрабатывает
 * WebExceptionAdvice (flash + redirect). @RestController мета-аннотирован
 * @Controller, поэтому фильтр по аннотации здесь не подходит.
 */
@RestControllerAdvice(basePackageClasses = VaultController.class)
public class ApiExceptionHandler {

    /**
     * Серверный лог неожиданных ошибок (без раскрытия клиенту). В лог не
     * попадают пароли/токены/ключи: стек-трейс исключения их не содержит.
     */
    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

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

    /** Неверный HTTP-метод (например, POST там, где метод не описан) — 405, не 500. */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ProblemDetail> handleMethodNotSupported(
            HttpRequestMethodNotSupportedException e) {
        HttpStatus status = HttpStatus.METHOD_NOT_ALLOWED;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Method not allowed"));
    }

    /**
     * Превышение лимита размера CSV (10 МБ) или количества строк экспорта (10 000)
     * — маппится в 413 Payload Too Large (RFC 7807).
     */
    @ExceptionHandler(PayloadTooLargeException.class)
    public ResponseEntity<ProblemDetail> handlePayloadTooLarge(PayloadTooLargeException e) {
        HttpStatus status = HttpStatus.PAYLOAD_TOO_LARGE;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        SensitiveDataMasker.mask(neutralize(e.getMessage()))));
    }

    /**
     * Превышение multipart-лимита Spring (max-file-size / max-request-size) —
     * тоже 413 Payload Too Large (RFC 7807).
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ProblemDetail> handleMaxUpload(MaxUploadSizeExceededException e) {
        HttpStatus status = HttpStatus.PAYLOAD_TOO_LARGE;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Payload too large"));
    }

    /**
     * Невалидный CSV (синтаксис, отсутствие обязательной колонки,
     * нераспарсиваемая UTF-8) — 422 Unprocessable Entity (RFC 7807).
     */
    @ExceptionHandler(InvalidCsvException.class)
    public ResponseEntity<ProblemDetail> handleInvalidCsv(InvalidCsvException e) {
        HttpStatus status = HttpStatus.UNPROCESSABLE_ENTITY;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        SensitiveDataMasker.mask(neutralize(e.getMessage()))));
    }

    /** Тег с таким именем уже существует у пользователя — 409 Conflict (RFC 7807). */
    @ExceptionHandler(TagAlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleTagConflict(TagAlreadyExistsException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, neutralize(e.getMessage())));
    }

    /**
     * Гонка параллельных созданий (UNIQUE user_id+name_lower и другие
     * integrity-нарушения) в API — 409 Conflict с нейтральным текстом,
     * без деталей (fix cycle 2: раньше падало в catch-all → 500).
     */
    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> handleDataIntegrity(
            org.springframework.dao.DataIntegrityViolationException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        "Concurrent modification — repeat the request"));
    }

    /** Системный тег сканера: переименование запрещено — 409 (G2). */
    @ExceptionHandler(com.example.safeaccounts.service.TagReservedNameException.class)
    public ResponseEntity<ProblemDetail> handleTagReserved(
            com.example.safeaccounts.service.TagReservedNameException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        "Tag name is reserved: " + e.getReservedName()));
    }

    /** Тег всё ещё привязан хотя бы к одной записи — 409 Conflict (RFC 7807). */
    @ExceptionHandler(TagStillReferencedException.class)
    public ResponseEntity<ProblemDetail> handleTagReferenced(TagStillReferencedException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, neutralize(e.getMessage())));
    }

    /** Квота скана исчерпана (G2): 429 + Retry-After, без деталей аккаунта. */
    @ExceptionHandler(com.example.safeaccounts.service.ScanRateLimitedException.class)
    public ResponseEntity<ProblemDetail> handleScanRateLimited(
            com.example.safeaccounts.service.ScanRateLimitedException e) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(org.springframework.http.HttpHeaders.RETRY_AFTER,
                        String.valueOf(e.getRetryAfterSeconds()))
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.TOO_MANY_REQUESTS,
                        "Too many scan requests, try again later"));
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
        // Стектрейс и внутренние детали наружу не раскрываются,
        // но ошибка логируется на сервере для диагностики.
        log.error("Unhandled exception", e);
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status, "Internal error"));
    }

    private static String neutralize(String message) {
        return message == null ? "Invalid request" : message;
    }
}
