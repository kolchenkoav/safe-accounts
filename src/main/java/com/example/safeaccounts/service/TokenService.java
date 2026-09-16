package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.domain.AuthToken;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.AuthTokenRepository;
import com.example.safeaccounts.security.AuthTokenResolver;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.security.PasswordHasher;
import com.example.safeaccounts.security.TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Управление Bearer-токенами: выпуск, проверка, отзыв (Task-04).
 * <p>
 * Правила безопасности:
 * <ul>
 *   <li>сырой токен существует только в момент выпуска; в БД — только SHA-256 хэш;</li>
 *   <li>сырой токен никогда не логируется;</li>
 *   <li>отзыв — по tokenHash (logout) или по пользователю (смена пароля, админ).</li>
 * </ul>
 */
@Service
public class TokenService implements UserService.PasswordRotationCallback, AuthTokenResolver {

    /** Срок жизни токена по умолчанию (Task-04: поддержка срока действия). */
    static final Duration TOKEN_TTL = Duration.ofHours(24);

    private final AuthTokenRepository authTokenRepository;
    private final PasswordHasher passwordHasher;
    private final TokenGenerator tokenGenerator;
    private final AuditService auditService;
    private final Clock clock;

    public TokenService(AuthTokenRepository authTokenRepository,
                        PasswordHasher passwordHasher,
                        TokenGenerator tokenGenerator,
                        AuditService auditService,
                        Clock clock) {
        this.authTokenRepository = authTokenRepository;
        this.passwordHasher = passwordHasher;
        this.tokenGenerator = tokenGenerator;
        this.auditService = auditService;
        this.clock = clock;
    }

    /**
     * Выпускает новый токен для пользователя.
     *
     * @param rawToken сгенерированный сырой токен (возвращается клиенту один раз;
     *                 в БД попадает только SHA-256 хэш)
     * @return сохраненная сущность AuthToken
     */
    @Transactional
    public AuthToken issue(User user, String rawToken, String userAgent, String ipAddress) {
        Instant now = clock.instant();
        AuthToken token = new AuthToken(
                UUID.randomUUID(),
                user,
                passwordHasher.hashToken(rawToken),
                tokenGenerator.hint(rawToken),
                truncate(userAgent, 512),
                truncate(ipAddress, 64),
                now,
                now.plus(TOKEN_TTL),
                null,
                null,
                null);
        AuthToken saved = authTokenRepository.saveAndFlush(token);
        auditService.record(user, AuditService.TOKEN_ISSUED, saved.getId(), (String) null);
        return saved;
    }

    /**
     * Резолвит principal для Bearer-фильтра: действующий токен + пользователь.
     * Ленивые прокси инициализируются ВНУТРИ транзакции (open-session-in-view выключен).
     *
     * @return AuthUser или {@code null}, если токен недействителен/пользователь отключен
     */
    @Transactional(readOnly = true)
    @Override
    public AuthUser resolveAuthUser(String rawToken) {
        AuthToken token = findValidByRawTokenInternal(rawToken);
        if (token == null || !token.getUser().isEnabled()) {
            return null;
        }
        User user = token.getUser();
        // Фиксируем не-секретные поля, пока сессия открыта.
        return new AuthUser(user, token.getId());
    }

    private AuthToken findValidByRawTokenInternal(String rawToken) {
        return authTokenRepository.findByTokenHash(passwordHasher.hashToken(rawToken))
                .filter(t -> !t.isRevoked())
                .filter(t -> !t.isExpired(clock.instant()))
                .orElse(null);
    }

    /**
     * Ищет действующий (не отозванный и не истекший) токен по сырому значению.
     *
     * @return AuthToken или {@code null}, если токен недействителен
     */
    @Transactional(readOnly = true)
    public AuthToken findValidByRawToken(String rawToken) {
        return findValidByRawTokenInternal(rawToken);
    }

    /**
     * Отзывает токен по сырому значению (logout). Идемпотентно: повторный
     * вызов не дублирует событие аудита.
     */
    @Transactional
    public void revokeByRawToken(String rawToken) {
        String hash = passwordHasher.hashToken(rawToken);
        AuthToken token = authTokenRepository.findByTokenHash(hash).orElse(null);
        if (token == null || token.isRevoked()) {
            return;
        }
        authTokenRepository.revokeByTokenHash(hash, clock.instant());
        authTokenRepository.flush();
        auditService.record(token.getUser(), AuditService.TOKEN_REVOKED, token.getId(), (String) null);
    }

    /** Отзывает ВСЕ токены пользователя (компрометация, административная блокировка). */
    @Transactional
    public int revokeAllForUser(UUID userId) {
        return revokeAllExcept(userId, null);
    }

    /**
     * Отзывает все токены пользователя, кроме указанного
     * (Task-04, Security-требование 5: смена пароля).
     */
    @Override
    @Transactional
    public int revokeAllExcept(UUID userId, UUID exceptTokenId) {
        Instant now = clock.instant();
        int revoked = 0;
        List<AuthToken> tokens = authTokenRepository.findAllByUser_Id(userId);
        for (AuthToken token : tokens) {
            if (token.isRevoked() || token.getId().equals(exceptTokenId)) {
                continue;
            }
            int updated = authTokenRepository.revokeByTokenHash(token.getTokenHash(), now);
            if (updated > 0) {
                revoked += updated;
                auditService.record(token.getUser(), AuditService.TOKEN_REVOKED, token.getId(),
                        java.util.Map.of("scope", "password-change"));
            }
        }
        if (revoked > 0) {
            authTokenRepository.flush();
        }
        return revoked;
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
