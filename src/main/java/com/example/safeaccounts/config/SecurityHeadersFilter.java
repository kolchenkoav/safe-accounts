package com.example.safeaccounts.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Безопасные заголовки ответов (Task-09):
 * <ul>
 *   <li>X-Content-Type-Options: nosniff</li>
 *   <li>X-Frame-Options: DENY</li>
 *   <li>Cache-Control: no-store на чувствительные ответы (все API-ответы)</li>
 *   <li>Strict-Transport-Security при работе за TLS-терминацией
 *       (включается, если запрос пришел по HTTPS или задан
 *       {@code app.security.hsts-enabled})</li>
 * </ul>
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final boolean hstsEnabled;

    public SecurityHeadersFilter(
            @org.springframework.beans.factory.annotation.Value(
                    "${app.security.hsts-enabled:false}") boolean hstsEnabled) {
        this.hstsEnabled = hstsEnabled;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        if (hstsEnabled || request.isSecure()) {
            // 1 год, включая поддомены; preload опционален.
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        }
        filterChain.doFilter(request, response);
    }
}
