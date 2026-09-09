package com.example.safeaccounts.config;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.service.AuthServiceException;
import com.example.safeaccounts.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

/**
 * Bootstrap первого администратора (Task-04).
 * <p>
 * Безопасный первичный запуск:
 * <ul>
 *   <li>срабатывает только если в БД еще НЕТ ни одного пользователя;</li>
 *   <li>учетные данные задаются ТОЛЬКО переменными окружения
 *       {@code APP_ADMIN_USERNAME} / {@code APP_ADMIN_PASSWORD};</li>
 *   <li>пароль не логируется; после создания повторный запуск ничего не перезаписывает;</li>
 *   <li>пользователь создается штатным сервисом: Argon2id + персональный wrapped DEK
 *       + событие аудита USER_CREATED.</li>
 * </ul>
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class AdminBootstrap implements ApplicationRunner {

    static final Logger log = LoggerFactory.getLogger(AdminBootstrap.class);

    private final UserService userService;
    private final AuditService auditService;
    private final Environment environment;

    public AdminBootstrap(UserService userService, AuditService auditService, Environment environment) {
        this.userService = userService;
        this.auditService = auditService;
        this.environment = environment;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        String username = environment.getProperty("app.admin.username");
        String password = environment.getProperty("app.admin.password");

        if (!hasText(username) && !hasText(password)) {
            return; // bootstrap не настроен — обычный сценарий
        }
        if (!hasText(username) || !hasText(password)) {
            throw new IllegalStateException(
                    "Admin bootstrap misconfigured: set both APP_ADMIN_USERNAME and APP_ADMIN_PASSWORD");
        }

        if (userService.hasAnyUsers()) {
            log.info("Admin bootstrap skipped: users already exist");
            return;
        }

        try {
            userService.register(username, password, "ROLE_ADMIN");
            log.info("Bootstrap admin '{}' created from environment", username);
        } catch (AuthServiceException e) {
            // Не валидное имя/пароль в окружении: fail-fast, секрет не упоминаем.
            throw new IllegalStateException("Admin bootstrap failed: invalid configuration", e);
        }
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
