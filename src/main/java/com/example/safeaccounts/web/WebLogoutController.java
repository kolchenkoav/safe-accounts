package com.example.safeaccounts.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Выход из веб-интерфейса (Task-11). Сессия инвалидируется, cookie JSESSIONID
 * удаляется; после выхода — редирект на страницу логина.
 * <p>
 * Баг-фикс: форма выхода в шаблонах отправляется методом POST
 * ({@code <form method="post" th:action="@{/logout}">} с CSRF-токеном от
 * Thymeleaf {@code RequestDataValueProcessor}), поэтому здесь принимаются и
 * POST (браузерный сценарий), и GET (совместимость). CSRF-защита цепочки
 * веб-интерфейса сохраняется для обоих методов: без валидного CSRF-токена
 * запрос отклоняется (403), выход по чужой ссылке невозможен.
 */
@Controller
public class WebLogoutController {

    @RequestMapping(
            value = "/logout",
            method = {RequestMethod.GET, RequestMethod.POST})
    public String logout(HttpServletRequest request, HttpServletResponse response,
                         Authentication authentication) {
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/web/login?logout";
    }

    /** GET/POST /web/logout — то же самое, для ссылок выхода из шаблонов. */
    @RequestMapping(
            value = "/web/logout",
            method = {RequestMethod.GET, RequestMethod.POST})
    public String logoutFromWeb(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) {
        return logout(request, response, authentication);
    }
}
