package com.example.safeaccounts.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Bearer-токен аутентификация (Task-04).
 * <p>
 * Извлекает {@code Authorization: Bearer <token>}, проверяет хэш токена в БД
 * (только SHA-256 хранится) и заполняет SecurityContext. При отсутствии/невалидности
 * токена контекст остается пустым — запрос обрабатывается как неаутентифицированный
 * (кроме разрешенных эндпоинтов), без раскрытия деталей.
 * <p>
 * Безопасность: сырой токен не логируется; из заголовка берется только
 * не-секретная подсказка.
 */
@Component
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    static final Logger log = LoggerFactory.getLogger(BearerTokenAuthenticationFilter.class);

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthTokenResolver tokenResolver;

    public BearerTokenAuthenticationFilter(AuthTokenResolver tokenResolver) {
        this.tokenResolver = tokenResolver;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith(BEARER_PREFIX)
                && SecurityContextHolder.getContext().getAuthentication() == null) {
            String rawToken = header.substring(BEARER_PREFIX.length()).trim();
            AuthUser principal = tokenResolver.resolveAuthUser(rawToken);
            if (principal != null) {
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(principal, null, principal.authorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            // Невалидный токен: контекст остается пустым, анонимный запрос
            // будет отклонен авторизацией с 401 без деталей.
        }
        filterChain.doFilter(request, response);
    }
}
