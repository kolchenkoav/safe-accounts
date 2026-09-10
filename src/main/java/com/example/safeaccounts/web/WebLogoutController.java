package com.example.safeaccounts.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Выход из веб-интерфейса (Task-11). Сессия инвалидируется, cookie JSESSIONID
 * удаляется; после выхода — редирект на страницу логина.
 */
@Controller
public class WebLogoutController {

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response,
                         Authentication authentication) {
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return "redirect:/web/login?logout";
    }

    /** GET /web/logout — то же самое, для ссылок выхода из шаблонов. */
    @GetMapping("/web/logout")
    public String logoutFromWeb(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) {
        return logout(request, response, authentication);
    }
}
