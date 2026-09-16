package com.example.safeaccounts.web;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.service.AuthService;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.AuthServiceException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Страница входа веб-интерфейса (Task-11).
 * <p>
 * Безопасность:
 * <ul>
 *   <li>аутентификация тем же {@link UserService#verifyCredentials} и теми же
 *       правилами блокировки/аудита, что и API (единообразие Task-11);</li>
 *   <li>Bearer-токен НЕ выпускается: пароль используется только внутри
 *       одного запроса, в браузер ничего не передается (HttpOnly сессия);</li>
 *   <li>пароль никогда не логируется и не возвращается в шаблон;</li>
 *   <li>ошибка входа — нейтральное сообщение, факт LOGIN_FAILURE фиксируется
 *       в аудите AuthService'ом; rate limiting по IP применяется на уровне
 *       фильтра (RateLimitFilter, Task-09).</li>
 * </ul>
 */
@Controller
public class WebLoginController {

    private final AuthService authService;
    private final SecurityContextRepository securityContextRepository;

    public WebLoginController(AuthService authService) {
        this.authService = authService;
        // Явная сессионная репозиторий-обертка: контекст сохраняется в HttpOnly
        // сессии (и в request-атрибуте), CSRF и STATELESS API это не затрагивает.
        this.securityContextRepository = new DelegatingSecurityContextRepository(
                new HttpSessionSecurityContextRepository(),
                new RequestAttributeSecurityContextRepository());
    }

    /** Страница логина. Для аутентифицированного пользователя — сразу в сейф. */
    @GetMapping({"/", "/web/login"})
    public String loginPage(Authentication authentication) {
        if (authentication != null && authentication.isAuthenticated()
                && !(authentication instanceof org.springframework.security.authentication.AnonymousAuthenticationToken)) {
            return "redirect:/web/entries";
        }
        return "login";
    }

    /**
     * Обработка формы логина. При неудаче — редирект с параметром ?error
     * (пароль не в URL и не в шаблоне); при успехе — аутентификация
     * сохраняется в HTTP-сессии (HttpOnly cookie, CSRF включен).
     */
    @PostMapping("/web/login")
    public String login(@RequestParam String username,
                        @RequestParam String password,
                        HttpServletRequest request,
                        HttpServletResponse response,
                        Model model) {
        try {
            AuthService.LoginResult result = authService.login(username, password,
                    request.getHeader("User-Agent"), request.getRemoteAddr());
            User user = result.user();

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            new AuthUser(user, null),
                            null,
                            new AuthUser(user, null).authorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            securityContextRepository.saveContext(
                    SecurityContextHolder.getContext(), request, response);

            return "redirect:/web/entries";
        } catch (AuthServiceException e) {
            // Нейтральное сообщение: не раскрываем причину (bad credentials/locked/disabled)
            return "redirect:/web/login?error";
        }
    }
}
