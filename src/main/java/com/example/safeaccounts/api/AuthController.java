package com.example.safeaccounts.api;

import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.AuthService;
import com.example.safeaccounts.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Аутентификация: логин, logout (Task-04). Контроллер тонкий,
 * бизнес-правила в AuthService/UserService/TokenService.
 * Пароли и токены никогда не логируются.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService,
                          UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    /** Логин: при успехе выпускается Bearer-токен (показывается один раз). */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthService.LoginResult result = authService.login(
                request.username(), request.password(),
                currentRequestUserAgent(), currentRequestIp());
        return ResponseEntity.ok(new TokenResponse(
                result.token().getId(),
                result.rawToken(),
                result.token().getExpiresAt()));
    }

    /** Logout: отзывает переданный Bearer-токен. Требует аутентификации. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal AuthUser principal,
                                       @RequestHeader(value = "Authorization", required = false) String authorization) {
        String raw = extractBearer(authorization);
        if (raw == null) {
            return ResponseEntity.badRequest().build();
        }
        authService.logout(raw);
        return ResponseEntity.noContent().build();
    }

    // -- request metadata (не секреты) ----------------------------------------

    private String currentRequestUserAgent() {
        var attrs = org.springframework.web.context.request.RequestContextHolder
                .getRequestAttributes();
        if (attrs instanceof org.springframework.web.context.request.ServletRequestAttributes sra) {
            return sra.getRequest().getHeader("User-Agent");
        }
        return null;
    }

    private String currentRequestIp() {
        var attrs = org.springframework.web.context.request.RequestContextHolder
                .getRequestAttributes();
        if (attrs instanceof org.springframework.web.context.request.ServletRequestAttributes sra) {
            return sra.getRequest().getRemoteAddr();
        }
        return null;
    }

    private static String extractBearer(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return null;
        }
        return authorization.substring("Bearer ".length()).trim();
    }
}
