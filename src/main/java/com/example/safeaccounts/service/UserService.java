package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.security.PasswordHasher;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.WrappedDek;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Бизнес-правила пользователей: регистрация, логин, блокировка от перебора,
 * смена пароля, включение/отключение (Task-04).
 * <p>
 * Правила безопасности (AGENTS.md / Task-04):
 * <ul>
 *   <li>пароли только Argon2id, открытый пароль нигде не сохраняется и не логируется;</li>
 *   <li>при регистрации генерируется персональный DEK, который заворачивается
 *       активным KEK через {@link AesGcmCryptoService#wrapDek}; в БД — только wrapped-форма;</li>
 *   <li>защита от перебора: после {@link #MAX_FAILED_ATTEMPTS} неудачных входов
 *       пользователь блокируется на {@link #LOCKOUT_DURATION};</li>
 *   <li>аудит: USER_CREATED / LOGIN_SUCCESS / LOGIN_FAILURE / PASSWORD_CHANGED /
 *       USER_DISABLED / USER_ENABLED — без секретов.</li>
 * </ul>
 */
@Service
public class UserService {

    static final Logger log = LoggerFactory.getLogger(UserService.class);

    /** Формат имени: 3-64 символа, буквы/цифры/точка/дефис/подчеркивание. */
    static final Pattern USERNAME_PATTERN = Pattern.compile("^[a-z0-9._-]{3,64}$");

    /** Минимальная длина пароля (Task-04). */
    static final int MIN_PASSWORD_LENGTH = 12;
    /** Максимальная длина пароля. */
    static final int MAX_PASSWORD_LENGTH = 128;
    /** Неудачных попыток до блокировки (Task-04). */
    static final int MAX_FAILED_ATTEMPTS = 5;
    /** Срок блокировки (Task-04). */
    static final Duration LOCKOUT_DURATION = Duration.ofMinutes(15);

    /** Синтетическая соль для выравнивания времени ответа при несуществующем пользователе. */
    static final String DUMMY_SALT_B64 = "AAAAAAAAAAAAAAAAAAAAAA==";

    private final UserRepository userRepository;
    private final PasswordHasher passwordHasher;
    private final AesGcmCryptoService cryptoService;
    private final AuditService auditService;
    private final Clock clock;

    public UserService(UserRepository userRepository,
                       PasswordHasher passwordHasher,
                       AesGcmCryptoService cryptoService,
                       AuditService auditService,
                       Clock clock) {
        this.userRepository = userRepository;
        this.passwordHasher = passwordHasher;
        this.cryptoService = cryptoService;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Регистрирует нового пользователя: Argon2id-хэш пароля + генерация DEK
     * и его wrapping активным KEK. Имя хранится в нижнем регистре.
     *
     * @return созданный пользователь
     * @throws AuthServiceException USERNAME_TAKEN, если имя уже занято;
     *         BAD_REQUEST (IllegalArgumentException), если имя/пароль не проходят валидацию
     */
    @Transactional
    public User register(String username, String password, String role) {
        String normalized = username == null ? null : username.toLowerCase(Locale.ROOT).trim();
        if (normalized == null || !USERNAME_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Username does not match required format");
        }
        validatePasswordLength(password);
        if (userRepository.existsByUsernameIgnoreCase(normalized)) {
            throw new AuthServiceException(AuthServiceException.Reason.USERNAME_TAKEN);
        }

        String roleValue = resolveRole(role);
        String passwordHash = passwordHasher.hash(password);
        WrappedDek wrapped = generateAndWrapDek();

        User user = new User(
                UUID.randomUUID(),
                normalized,
                passwordHash,
                roleValue,
                true,
                0,
                null,
                wrapped.wrappedDekBase64(),
                wrapped.ivBase64(),
                wrapped.kekId(),
                clock.instant(),
                null,
                null);
        User saved = userRepository.saveAndFlush(user);
        auditService.record(saved, AuditService.USER_CREATED, null, Map.of("role", roleValue));
        log.info("User '{}' registered with role {}", normalized, roleValue);
        return saved;
    }

    /**
     * Проверяет учетные данные для логина. Блокировка/счетчики обновляются
     * вызывающим кодом через {@link #registerFailedLogin}/{@link #registerSuccessfulLogin}.
     *
     * @return пользователя, если пароль верный
     * @throws AuthServiceException BAD_CREDENTIALS / USER_DISABLED / USER_LOCKED
     */
    @Transactional
    public User verifyCredentials(String username, String password) {
        String normalized = username == null ? null : username.toLowerCase(Locale.ROOT).trim();
        User user = normalized == null ? null : userRepository.findByUsername(normalized).orElse(null);

        if (user == null) {
            // Не раскрываем, существует ли пользователь; фиктивный Argon2id-проход
            // выравнивает время ответа (защита от user enumeration по таймингу).
            passwordHasher.verify(password == null ? "" : password,
                    "$argon2id$v=19$m=65536,t=3,p=1$" + DUMMY_SALT_B64 + "$" + DUMMY_SALT_B64);
            throw new AuthServiceException(AuthServiceException.Reason.BAD_CREDENTIALS);
        }

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(clock.instant())) {
            throw new AuthServiceException(AuthServiceException.Reason.USER_LOCKED);
        }
        if (!user.isEnabled()) {
            throw new AuthServiceException(AuthServiceException.Reason.USER_DISABLED);
        }
        if (!passwordHasher.verify(password, user.getPasswordHash())) {
            throw new AuthServiceException(AuthServiceException.Reason.BAD_CREDENTIALS);
        }
        return user;
    }

    /**
     * Неудачная попытка входа: увеличивает счетчик и, при достижении лимита,
     * блокирует пользователя на {@link #LOCKOUT_DURATION}.
     */
    @Transactional
    public void registerFailedLogin(User user) {
        int attempts = user.getFailedAttempts() + 1;
        Instant lockedUntil = null;
        if (attempts >= MAX_FAILED_ATTEMPTS) {
            lockedUntil = clock.instant().plus(LOCKOUT_DURATION);
            attempts = 0; // окно блокировки началось; следующий отсчет начнется заново
        }
        user.applyAuthState(attempts, lockedUntil, clock.instant());
        userRepository.saveAndFlush(user);
    }

    /**
     * Успешный вход: сброс счетчика неудачных попыток и блокировки.
     */
    @Transactional
    public void registerSuccessfulLogin(User user) {
        if (user.getFailedAttempts() != 0 || user.getLockedUntil() != null) {
            user.clearAuthFailures(clock.instant());
            userRepository.saveAndFlush(user);
        }
    }

    /**
     * Смена пароля текущим пользователем с проверкой текущего пароля.
     * Все токены, кроме текущего ({@code exceptTokenId}), отзываются через
     * {@link PasswordRotationCallback} в этой же транзакции.
     *
     * @return количество отозванных токенов
     */
    @Transactional
    public int changePassword(User user, String currentPassword, String newPassword, UUID exceptTokenId) {
        validatePasswordLength(newPassword);
        if (newPassword.length() > MAX_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password too long");
        }
        if (!passwordHasher.verify(currentPassword, user.getPasswordHash())) {
            throw new AuthServiceException(AuthServiceException.Reason.WRONG_CURRENT_PASSWORD);
        }
        user.changePasswordHash(passwordHasher.hash(newPassword), clock.instant());
        userRepository.saveAndFlush(user);
        auditService.record(user, AuditService.PASSWORD_CHANGED, null, (String) null);
        int revoked = 0;
        for (PasswordRotationCallback callback : passwordRotationCallbacks) {
            revoked += callback.revokeAllExcept(user.getId(), exceptTokenId);
        }
        if (revoked > 0) {
            log.info("Password changed: {} other token(s) revoked", revoked);
        }
        return revoked;
    }

    // -- hooks ---------------------------------------------------------------

    /**
     * Хук отзыва токенов при смене пароля. Реализуется TokenService;
     * интерфейс исключает циклическую зависимость UserService <-> TokenService.
     */
    public interface PasswordRotationCallback {
        /**
         * @param exceptTokenId токен, который НЕ нужно отзывать (может быть null)
         * @return количество отозванных токенов
         */
        int revokeAllExcept(UUID userId, UUID exceptTokenId);
    }

    private final List<PasswordRotationCallback> passwordRotationCallbacks = new java.util.ArrayList<>();

    /** Регистрируется Spring'ом (TokenService реализует callback). */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPasswordRotationCallbacks(List<PasswordRotationCallback> callbacks) {
        this.passwordRotationCallbacks.clear();
        if (callbacks != null) {
            this.passwordRotationCallbacks.addAll(callbacks);
        }
    }

    // -- admin ops -----------------------------------------------------------

    private static void requireAdmin(User actor) {
        if (actor == null || !"ROLE_ADMIN".equals(actor.getRole())) {
            throw new org.springframework.security.access.AccessDeniedException("Admin role required");
        }
    }

    /** Отключает пользователя (только ADMIN). */
    @Transactional
    public void disableUser(User user, User actor) {
        requireAdmin(actor);
        user.setEnabled(false, clock.instant());
        userRepository.saveAndFlush(user);
        auditService.record(user, AuditService.USER_DISABLED, null,
                Map.of("actor", actor.getUsername()));
    }

    /** Включает пользователя обратно (только ADMIN). */
    @Transactional
    public void enableUser(User user, User actor) {
        requireAdmin(actor);
        user.setEnabled(true, clock.instant());
        userRepository.saveAndFlush(user);
        auditService.record(user, AuditService.USER_ENABLED, null,
                Map.of("actor", actor.getUsername()));
    }

    // -- internals -----------------------------------------------------------

    private WrappedDek generateAndWrapDek() {
        SecretKey dek = cryptoService.generateDek();
        try {
            return cryptoService.wrapDek(dek);
        } finally {
            destroyQuietly(dek);
        }
    }

    private static void destroyQuietly(SecretKey dek) {
        try {
            dek.destroy();
        } catch (DestroyFailedException e) {
            // Не критично: SecretKeySpec.destroy() может быть no-op в некоторых JDK.
        }
    }

    private static String resolveRole(String role) {
        return switch (role == null ? "ROLE_USER" : role) {
            case "ROLE_USER", "ROLE_ADMIN" -> role;
            default -> throw new IllegalArgumentException("Unsupported role: " + role);
        };
    }

    private static void validatePasswordLength(String password) {
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new IllegalArgumentException("Password must be at least 12 characters");
        }
    }

    /** Ищет пользователя по имени (для аудита неудачных входов). */
    @Transactional(readOnly = true)
    public java.util.Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    /** Есть ли в системе хоть один пользователь (для AdminBootstrap). */
    @Transactional(readOnly = true)
    public boolean hasAnyUsers() {
        return userRepository.existsBy();
    }

    /** Загружает пользователя по id или бросает USER_NOT_FOUND. */
    @Transactional(readOnly = true)
    public User requireUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new AuthServiceException(AuthServiceException.Reason.USER_NOT_FOUND));
    }
}
