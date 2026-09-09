package com.example.safeaccounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Базовая конфигурация безопасности каркаса (Task-01).
 *
 * Actuator: наружу доступен только /actuator/health, остальные actuator-эндпоинты
 * закрыты по умолчанию (exposure уже ограничен в application.yaml, здесь —
 * дополнительная защита на уровне Spring Security).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Здоровье доступно без аутентификации (для оркестраторов/балансировщиков)
                        .requestMatchers("/actuator/health").permitAll()
                        // Все остальные actuator-эндпоинты закрыты по умолчанию
                        .requestMatchers("/actuator/**").denyAll()
                        // Все остальные запросы требуют аутентификации
                        .anyRequest().authenticated())
                .httpBasic(basic -> {});
        return http.build();
    }
}
