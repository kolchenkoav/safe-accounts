package com.example.safeaccounts.config;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

/**
 * Доступ к Swagger/OpenAPI (Task-09):
 * <ul>
 *   <li>dev-профиль — документация открыта;</li>
 *   <li>все остальные профили (prod, docker, it) — закрыта полностью,
 *       чтобы не раскрывать схему API на производственной поверхности.</li>
 * </ul>
 * Профиль определяется через свойство spring.profiles.active, что позволяет
 * использовать один и тот же бин во всех профилях без @Profile-условий
 * на уровень SecurityConfig.
 */
public class ProdApiDocsGuard implements AuthorizationManager<RequestAuthorizationContext> {

    private final boolean devProfile;

    public ProdApiDocsGuard(boolean devProfile) {
        this.devProfile = devProfile;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication,
                                       RequestAuthorizationContext context) {
        return new AuthorizationDecision(devProfile);
    }
}
