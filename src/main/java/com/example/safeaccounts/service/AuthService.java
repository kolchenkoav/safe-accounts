package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.domain.AuthToken;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.TokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Прикладные сценарии аутентификации (Task-04): логин с выпуском токена,
 * logout с отзывом токена. Содержит аудит входов и защиту от перебора.
 * <p>
 * Аудит (Task-04): LOGIN_SUCCESS, LOGIN_FAILURE, TOKEN_ISSUED, TOKEN_REVOKED.
 * В аудит не пишутся пароли и токены.
 */
@Service
public class AuthService {

    /** Результат успешного логина: токен показывается клиенту ровно один раз. */
    public record LoginResult(User user, AuthToken token, String rawToken) {
    }

    private final UserService userService;
    private final TokenService tokenService;
    private final TokenGenerator tokenGenerator;
    private final AuditService auditService;

    public AuthService(UserService userService,
                       TokenService tokenService,
                       TokenGenerator tokenGenerator,
                       AuditService auditService) {
        this.userService = userService;
        this.tokenService = tokenService;
        this.tokenGenerator = tokenGenerator;
        this.auditService = auditService;
    }

    /**
     * Логин: проверка учетных данных, защита от перебора, выпуск токена, аудит.
     *
    /**
     * Логин: проверка учетных данных, защита от перебора, выпуск токена, аудит.
     * Метод НЕ транзакционный намеренно: записи аудита и обновления блокировки
     * фиксируются независимыми транзакциями и не откатываются при неудачном входе.
     *
     * @throws AuthServiceException BAD_CREDENTIALS / USER_LOCKED / USER_DISABLED
     */
    public LoginResult login(String username, String password, String userAgent, String ipAddress) {
        User user;
        try {
            user = userService.verifyCredentials(username, password);
        } catch (AuthServiceException e) {
            User known = findKnownUser(username);
            String reason = switch (e.getReason()) {
                case USER_LOCKED -> "locked";
                case USER_DISABLED -> "disabled";
                default -> "bad_credentials";
            };
            auditService.record(known, AuditService.LOGIN_FAILURE, null,
                    java.util.Map.of("reason", reason));
            if (e.getReason() == AuthServiceException.Reason.BAD_CREDENTIALS && known != null) {
                userService.registerFailedLogin(known);
            }
            throw e;
        }

        userService.registerSuccessfulLogin(user);
        String rawToken = tokenGenerator.generate();
        AuthToken token = tokenService.issue(user, rawToken, userAgent, ipAddress);
        auditService.record(user, AuditService.LOGIN_SUCCESS, token.getId(),
                java.util.Map.of("tokenId", token.getId().toString()));
        return new LoginResult(user, token, rawToken);
    }

    /**
     * Logout: отзыв переданного Bearer-токена (идемпотентно).
     */
    public void logout(String bearerToken) {
        tokenService.revokeByRawToken(bearerToken);
    }

    private User findKnownUser(String username) {
        String normalized = username == null ? null : username.toLowerCase(java.util.Locale.ROOT).trim();
        return normalized == null ? null : userService.findByUsername(normalized).orElse(null);
    }
}
