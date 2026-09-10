package com.example.safeaccounts.web;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Общие атрибуты моделей веб-интерфейса (Task-12).
 * <p>
 * Добавляет {@code isAdmin} для шаблонов: ссылка «Админка» в навигации
 * видна только пользователям с ролью ROLE_ADMIN. Атрибут вычисляется
 * из текущего SecurityContext и не раскрывает ничего чувствительного.
 * <p>
 * Advice ограничен обычными {@link Controller}-бинами: REST-контроллеры
 * ({@code @RestController}) не затрагиваются, поведение API не меняется.
 */
@ControllerAdvice(annotations = Controller.class)
public class WebNavAdvice {

    /** Показывать ссылку «Админка» в навигации — только ROLE_ADMIN. */
    @ModelAttribute("isAdmin")
    public boolean isAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || auth instanceof AnonymousAuthenticationToken) {
            return false;
        }
        return auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
    }
}
