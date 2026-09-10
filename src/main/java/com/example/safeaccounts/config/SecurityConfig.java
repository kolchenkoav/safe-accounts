package com.example.safeaccounts.config;

import com.example.safeaccounts.security.BearerTokenAuthenticationFilter;
import com.example.safeaccounts.security.RateLimitFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Конфигурация безопасности (Task-01, Task-04, Task-09).
 *
 * <ul>
 *   <li>stateless: сессии не создаются;</li>
 *   <li>CSRF отключен — аутентификация через Bearer token;</li>
 *   <li>без аутентификации доступны только /actuator/health|info|prometheus
 *       (Task-09), POST /api/auth/login и POST /api/auth/register;</li>
 *   <li>остальные actuator-эндпоинты закрыты (denyAll);</li>
 *   <li>Swagger/OpenAPI открыт только в dev-профиле (Task-09);</li>
 *   <li>неаутентифицированные запросы получают 401 без стектрейса
 *       ({@link HttpStatusEntryPoint});</li>
 *   <li>Bearer-токен проверяется в {@link BearerTokenAuthenticationFilter};</li>
 *   <li>rate limiting по IP для login/register — в {@link RateLimitFilter}
 *       (Task-09), регистрируется раньше аутентификации.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            BearerTokenAuthenticationFilter bearerFilter,
            RateLimitFilter rateLimitFilter,
            @Value("${app.security.dev-profile:false}") boolean devProfile) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Task-09: без аутентификации разрешены только health,
                        // info и prometheus (метрики). Остальные актуаторы закрыты.
                        .requestMatchers("/actuator/health", "/actuator/health/**",
                                "/actuator/info", "/actuator/prometheus").permitAll()
                        // Остальные actuator-эндпоинты запрещены (Task-09).
                        .requestMatchers("/actuator/**").denyAll()
                        // Логин и самостоятельная регистрация — без аутентификации
                        // (защищены rate limiting'ом по IP, Task-09).
                        .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                        // Swagger/OpenAPI: только когда документация включена
                        // (dev-профиль; в prod/docker отключена — Task-09).
                        .requestMatchers("/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                            .access(new ProdApiDocsGuard(devProfile))
                        // Административные функции — только ROLE_ADMIN (Task-06)
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // Все остальные запросы требуют аутентификации
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                // Rate limiting (Task-09) до аутентификации
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                // Bearer-аутентификация (Task-04)
                .addFilterBefore(bearerFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
