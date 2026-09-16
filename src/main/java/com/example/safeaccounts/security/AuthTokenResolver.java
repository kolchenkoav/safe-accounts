package com.example.safeaccounts.security;

/**
 * Резолвинг Bearer-токена в principal (P1 рефакторинга пакетов, DIP).
 * <p>
 * Security-фильтр ({@link BearerTokenAuthenticationFilter}) зависит от этого
 * интерфейса, а не от {@code service.TokenService} — это разрывает единственный
 * цикл пакетов {@code service ⇄ security} (сервисы легитимно используют
 * {@code security.AuthUser/PasswordHasher/TokenGenerator}; обратное ребро
 * убрано интерфейсом, реализуемым TokenService).
 * <p>
 * Семантика 1:1 с реализацией ({@code TokenService.resolveAuthUser}).
 */
public interface AuthTokenResolver {

    /**
     * Резолвит principal для Bearer-фильтра: действующий токен + пользователь.
     * Ленивые прокси инициализируются ВНУТРИ транзакции (open-session-in-view выключен).
     *
     * @return AuthUser или {@code null}, если токен недействителен/пользователь отключен
     */
    AuthUser resolveAuthUser(String rawToken);
}
