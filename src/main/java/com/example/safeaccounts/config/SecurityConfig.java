package com.example.safeaccounts.config;

import com.example.safeaccounts.security.BearerTokenAuthenticationFilter;
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
 * Конфигурация безопасности (Task-01 + Task-04).
 *
 * <ul>
 *   <li>stateless: сессии не создаются;</li>
 *   <li>CSRF отключен — аутентификация через Bearer token;</li>
 *   <li>без аутентификации доступны только /actuator/health,
 *       POST /api/auth/login и документация API;</li>
 *   <li>неаутентифицированные запросы получают 401 без стектрейса
 *       ({@link HttpStatusEntryPoint});</li>
 *   <li>Bearer-токен проверяется в {@link BearerTokenAuthenticationFilter}.</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   BearerTokenAuthenticationFilter bearerFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Здоровье доступно без аутентификации (для оркестраторов/балансировщиков)
                        .requestMatchers("/actuator/health").permitAll()
                        // Остальные actuator-эндпоинты закрыты
                        .requestMatchers("/actuator/**").denyAll()
                        // Логин, самостоятельная регистрация и документация API — без аутентификации
                        .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                        .requestMatchers("/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()
                        // Административные функции — только ROLE_ADMIN (Task-06)
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        // Все остальные запросы требуют аутентификации
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
                .httpBasic(basic -> basic.disable())
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable())
                // Bearer-аутентификация (Task-04)
                .addFilterBefore(bearerFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
