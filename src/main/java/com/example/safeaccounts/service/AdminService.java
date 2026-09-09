package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.AesGcmCryptoService.CryptoException;
import com.example.safeaccounts.crypto.KeyManager;
import com.example.safeaccounts.crypto.WrappedDek;
import com.example.safeaccounts.domain.AuditEvent;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.security.PasswordHasher;
import jakarta.persistence.criteria.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Административные операции (Task-06): управление пользователями,
 * просмотр аудита, ротация KEK (rewrap пользовательских DEK).
 * <p>
 * Правила безопасности (AGENTS.md / Task-06):
 * <ul>
 *   <li>все операции требуют ROLE_ADMIN (проверка на уровне URL + повторная
 *       проверка здесь, defense in depth);</li>
 *   <li>аудит административных действий не содержит секретов: только
 *       имена/идентификаторы, количество отозванных токенов и нечувствительные
 *       key id (материал ключей никогда не логируется);</li>
 *   <li>rewrap-deks идемпотентен: пользователи, чей DEK уже завернут активным
 *       KEK, пропускаются; операцию можно безопасно повторить;</li>
 *   <li>каждый rewrap коммитится независимо (репозиторные транзакции):
 *       сбой на середине не откатывает уже перепакованные DEK, повторный
 *       запуск продолжает с места сбоя;</li>
 *   <li>если старый KEK недоступен — операция завершается понятной ошибкой
 *       и событием KEY_ROTATION_FAILED в аудите.</li>
 * </ul>
 */
@Service
public class AdminService {

    static final Logger log = LoggerFactory.getLogger(AdminService.class);

    /** Ограничение размера страницы (как в VaultService). */
    static final int MAX_PAGE_SIZE = 100;
    /** Границы длины пароля — согласованы с UserService (Task-04). */
    static final int MIN_PASSWORD_LENGTH = 12;
    static final int MAX_PASSWORD_LENGTH = 128;

    private final UserRepository userRepository;
    private final AuditEventRepository auditEventRepository;
    private final UserService userService;
    private final TokenService tokenService;
    private final PasswordHasher passwordHasher;
    private final AuditService auditService;
    private final KeyManager keyManager;
    private final AesGcmCryptoService cryptoService;
    private final Clock clock;

    public AdminService(UserRepository userRepository,
                        AuditEventRepository auditEventRepository,
                        UserService userService,
                        TokenService tokenService,
                        PasswordHasher passwordHasher,
                        AuditService auditService,
                        KeyManager keyManager,
                        AesGcmCryptoService cryptoService,
                        Clock clock) {
        this.userRepository = userRepository;
        this.auditEventRepository = auditEventRepository;
        this.userService = userService;
        this.tokenService = tokenService;
        this.passwordHasher = passwordHasher;
        this.auditService = auditService;
        this.keyManager = keyManager;
        this.cryptoService = cryptoService;
        this.clock = clock;
    }

    /** Представление события аудита для API (пользователь зафиксирован внутри транзакции). */
    public record AuditView(UUID id, UUID userId, UUID tokenId, String type,
                            String objectType, String objectId,
                            String ipAddress, String userAgent,
                            String detailsJson, Instant createdAt) {
    }

    /** Результат rewrap-deks: только нечувствительные данные. */
    public record RewrapResult(int rewrappedUsers, String activeKekId) {
    }

    // -- пользователи ---------------------------------------------------------

    @Transactional(readOnly = true)
    public Page<User> listUsers(int page, int size) {
        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        Pageable pageable = PageRequest.of(Math.max(page, 0), safeSize,
                Sort.by(Sort.Direction.ASC, "createdAt"));
        return userRepository.findAllByOrderByCreatedAtAsc(pageable);
    }

    @Transactional
    public User createUser(String username, String password, String role, User actor) {
        requireAdmin(actor);
        User created = userService.register(username, password, role);
        auditService.record(created, AuditService.USER_CREATED_BY_ADMIN, null,
                Map.of("actor", actor.getUsername(), "role", created.getRole()));
        log.info("Admin '{}' created user '{}'", actor.getUsername(), created.getUsername());
        return created;
    }

    @Transactional
    public User enableUser(UUID userId, User actor) {
        requireAdmin(actor);
        User user = requireUser(userId);
        userService.enableUser(user, actor);
        return user;
    }

    @Transactional
    public User disableUser(UUID userId, User actor) {
        requireAdmin(actor);
        User user = requireUser(userId);
        userService.disableUser(user, actor);
        return user;
    }

    /**
     * Сброс пароля администратором: новый Argon2id-хэш + отзыв ВСЕХ активных
     * токенов пользователя. В аудит пишется только количество отозванных токенов.
     *
     * @return количество отозванных токенов
     */
    @Transactional
    public int resetPassword(UUID userId, String newPassword, User actor) {
        requireAdmin(actor);
        User user = requireUser(userId);
        validatePasswordLength(newPassword);
        user.changePasswordHash(passwordHasher.hash(newPassword), clock.instant());
        userRepository.saveAndFlush(user);
        int revoked = tokenService.revokeAllForUser(user.getId());
        auditService.record(user, AuditService.USER_RESET_PASSWORD, null,
                Map.of("actor", actor.getUsername(), "revokedTokens", revoked));
        log.info("Admin '{}' reset password of user '{}', {} token(s) revoked",
                actor.getUsername(), user.getUsername(), revoked);
        return revoked;
    }

    // -- аудит ----------------------------------------------------------------

    /**
     * Пагинированный просмотр аудита с фильтрами: тип события, пользователь,
     * период. Возвращает только нечувствительные метаданные (detailsJson
     * в БД по построению не содержит секретов).
     */
    @Transactional(readOnly = true)
    public Page<AuditView> listAudit(String type, UUID userId, Instant from, Instant to,
                                     int page, int size) {
        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        Pageable pageable = PageRequest.of(Math.max(page, 0), safeSize,
                Sort.by(Sort.Direction.DESC, "createdAt"));
        Page<AuditEvent> events = auditEventRepository.findAll(
                withFilters(type, userId, from, to), pageable);
        return events.map(AdminService::toView);
    }

    private static AuditView toView(AuditEvent event) {
        User user = event.getUser();
        return new AuditView(
                event.getId(),
                user == null ? null : user.getId(),
                event.getTokenId(),
                event.getType(),
                event.getObjectType(),
                event.getObjectId(),
                event.getIpAddress(),
                event.getUserAgent(),
                event.getDetailsJson(),
                event.getCreatedAt());
    }

    private static Specification<AuditEvent> withFilters(String type, UUID userId,
                                                         Instant from, Instant to) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (type != null && !type.isBlank()) {
                predicates.add(cb.equal(root.get("type"), type));
            }
            if (userId != null) {
                predicates.add(cb.equal(root.get("user").get("id"), userId));
            }
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("createdAt"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("createdAt"), to));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }

    // -- ротация ключей -------------------------------------------------------

    /**
     * Перепаковывает DEK всех пользователей, чей {@code dek_kek_id} не совпадает
     * с активным KEK, новым активным ключом. Идемпотентно: повторный вызов
     * ничего не меняет. Событие ротации фиксируется в аудите (без материала
     * ключей — только key id и счетчики).
     *
     * @throws KeyRotationException если DEK какого-то пользователя не удалось
     *         распаковать (например, старый ключ недоступен) — понятная ошибка,
     *         уже перепакованные пользователи сохраняются, операцию можно повторить
     */
    public RewrapResult rewrapDeks(User actor) {
        requireAdmin(actor);
        String activeKekId = keyManager.getActiveKekId();
        auditService.record(actor, AuditService.KEY_ROTATION_STARTED, null,
                Map.of("actor", actor.getUsername(), "activeKekId", activeKekId));
        log.info("DEK rewrap started: target activeKekId='{}'", activeKekId);

        List<User> stale = userRepository.findByDekKekIdNot(activeKekId);
        int rewrapped = 0;
        try {
            for (User user : stale) {
                WrappedDek current = new WrappedDek(
                        user.getDekWrapped(), user.getDekIv(), user.getDekKekId());
                SecretKey dek = cryptoService.unwrapDek(current);
                WrappedDek rewrappedDek;
                try {
                    rewrappedDek = cryptoService.wrapDek(dek);
                } finally {
                    destroyQuietly(dek);
                }
                user.rewrapDek(rewrappedDek.wrappedDekBase64(),
                        rewrappedDek.ivBase64(), rewrappedDek.kekId());
                userRepository.saveAndFlush(user);
                rewrapped++;
            }
        } catch (CryptoException e) {
            // Сообщение CryptoException содержит только нечувствительный key id.
            auditService.record(actor, AuditService.KEY_ROTATION_FAILED, null,
                    Map.of("actor", actor.getUsername(), "reason", e.getMessage()));
            log.warn("DEK rewrap failed: {}", e.getMessage());
            throw new KeyRotationException("Key rotation failed: " + e.getMessage());
        }

        auditService.record(actor, AuditService.KEY_ROTATION_COMPLETED, null,
                Map.of("actor", actor.getUsername(), "rewrapped", rewrapped,
                        "activeKekId", activeKekId));
        log.info("DEK rewrap completed: {} user(s) moved to activeKekId='{}'",
                rewrapped, activeKekId);
        return new RewrapResult(rewrapped, activeKekId);
    }

    // -- internals ------------------------------------------------------------

    private User requireUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AuthServiceException(AuthServiceException.Reason.USER_NOT_FOUND));
    }

    private static void requireAdmin(User actor) {
        if (actor == null || !"ROLE_ADMIN".equals(actor.getRole())) {
            throw new AccessDeniedException("Admin role required");
        }
    }

    private static void validatePasswordLength(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least 12 characters");
        }
        if (password.length() > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too long");
        }
    }

    private static void destroyQuietly(SecretKey key) {
        try {
            key.destroy();
        } catch (DestroyFailedException e) {
            // SecretKeySpec.destroy() может быть no-op в некоторых JDK — не критично.
        }
    }
}
