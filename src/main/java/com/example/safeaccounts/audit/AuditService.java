package com.example.safeaccounts.audit;

import com.example.safeaccounts.domain.AuditEvent;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Сервис аудита (Task-04). Пишет события аудита в audit_events.
 * <p>
 * Правила AGENTS.md: в аудит ЗАПРЕЩЕНО записывать пароли, токены,
 * DEK и расшифрованные секреты — как в type, так и в detailsJson.
 * detailsJson содержит только нечувствительные метаданные.
 * <p>
 * Аудит не должен ломать основной сценарий при ошибке записи: исключение
 * логируется, но не пробрасывается в обработчика запроса.
 */
@Service
public class AuditService {

    static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    public AuditService(AuditEventRepository auditEventRepository, ObjectMapper objectMapper) {
        this.auditEventRepository = auditEventRepository;
        this.objectMapper = objectMapper;
    }

    /** Типы событий аудита (Task-04). */
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILURE = "LOGIN_FAILURE";
    public static final String TOKEN_ISSUED = "TOKEN_ISSUED";
    public static final String TOKEN_REVOKED = "TOKEN_REVOKED";
    public static final String USER_CREATED = "USER_CREATED";
    public static final String USER_DISABLED = "USER_DISABLED";
    public static final String USER_ENABLED = "USER_ENABLED";
    public static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";
    /** События записей сейфа (Task-05). Расшифрованные секреты в аудит запрещены. */
    public static final String SECRET_CREATED = "SECRET_CREATED";
    public static final String SECRET_UPDATED = "SECRET_UPDATED";
    public static final String SECRET_DELETED = "SECRET_DELETED";
public static final String SECRET_REVEALED = "SECRET_REVEALED";

    /** Экспорт/импорт сейфа в CSV (Task-07 / Task-08). Агрегаты, без CSV/расшифрованных значений. */
    public static final String VAULT_EXPORTED = "VAULT_EXPORTED";
    public static final String VAULT_IMPORTED = "VAULT_IMPORTED";

    /** Административные события (Task-06). В details — только имена/счетчики/key id. */
    public static final String USER_CREATED_BY_ADMIN = "USER_CREATED_BY_ADMIN";
    public static final String USER_RESET_PASSWORD = "USER_RESET_PASSWORD";
    /** Task-12: смена роли пользователя администратором (веб-админка). */
    public static final String USER_ROLE_CHANGED = "USER_ROLE_CHANGED";
    public static final String KEY_ROTATION_STARTED = "KEY_ROTATION_STARTED";
    public static final String KEY_ROTATION_COMPLETED = "KEY_ROTATION_COMPLETED";
    public static final String KEY_ROTATION_FAILED = "KEY_ROTATION_FAILED";

    /**
     * Записывает событие аудита, привязанное к объекту (Task-05: записи сейфа).
     * objectType/objectId — только нечувствительные идентификаторы (например,
     * "VaultEntry" и UUID записи). Ошибки записи логируются, но не пробрасываются.
     */
    public void record(User user, String type, UUID tokenId,
                       String objectType, String objectId, Map<String, ?> details) {
        try {
            auditEventRepository.save(new AuditEvent(
                    UUID.randomUUID(),
                    user,
                    tokenId,
                    type,
                    objectType,
                    objectId,
                    null,
                    null,
                    toJson(details),
                    Instant.now()));
        } catch (RuntimeException e) {
            log.error("Failed to write audit event of type {}", type, e);
        }
    }

    /**
     * Записывает событие аудита. Ошибки записи логируются, но не пробрасываются.
     *
     * @param user  пользователь события (может быть null, например при неудачном
     *              входе с несуществующим именем)
     * @param type  тип события (константы этого класса)
     * @param tokenId id токена, к которому относится событие (может быть null)
     */
    public void record(User user, String type, UUID tokenId, String detailsJson) {
        try {
            auditEventRepository.save(new AuditEvent(
                    UUID.randomUUID(),
                    user,
                    tokenId,
                    type,
                    null,
                    null,
                    null,
                    null,
                    detailsJson,
                    Instant.now()));
        } catch (RuntimeException e) {
            // Не секреты: только тип события, без паролей/токенов.
            log.error("Failed to write audit event of type {}", type, e);
        }
    }

    /** Удобный вариант: details собирается в нечувствительную JSON-строку. */
    public void record(User user, String type, UUID tokenId, Map<String, ?> details) {
        record(user, type, tokenId, toJson(details));
    }

    private String toJson(Map<String, ?> details) {
        if (details == null || details.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(details);
        } catch (Exception e) {
            log.warn("Failed to serialize audit details; writing without details");
            return null;
        }
    }

    /** Вспомогательный builder нечувствительных деталей. */
    public static Map<String, Object> details() {
        return new LinkedHashMap<>();
    }
}
