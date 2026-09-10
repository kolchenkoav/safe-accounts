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
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * Конфигурация безопасности (Task-01, Task-04, Task-09, Task-11).
 *
 * <p>Два независимых filter chain:
 * <ol>
 *   <li><b>Веб-интерфейс (Task-11)</b> — маршруты {@code /web/**}, {@code /}
 *       и {@code /logout}: серверная HTTP-сессия (HttpOnly cookie),
 *       CSRF-защита, rate limiting на логин. Аутентификация — по сессии,
 *       Bearer-токен здесь не используется и в браузер не выдается.</li>
 *   <li><b>API (Task-01..09)</b> — {@code /api/**}, {@code /actuator/**},
 *       {@code /api-docs/**}, {@code /swagger-ui/**}: stateless, CSRF отключен
 *       (Bearer-аутентификация) — поведение прежних задач не изменено.</li>
 * </ol>
 *
 * <p>Безопасность Task-11: пароли форм не логируются; сессия — HttpOnly;
 * CSRF включен для всех веб-форм (POST-маршруты); чужие записи недоступны
 * (owner-scoped проверки в VaultService, единые с API).
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Цепочка веб-интерфейса (Task-11): сессии + CSRF.
     * Матчится только на веб-маршруты, поэтому не влияет на API.
     */
    @Bean
    public SecurityFilterChain webSecurityFilterChain(
            HttpSecurity http,
            RateLimitFilter rateLimitFilter) throws Exception {
        // Дефолтный CsrfTokenRequestAttributeHandler: токен доступен и атрибутом
        // запроса (для Thymeleaf-форм), и в HttpSessionCsrfTokenRepository.
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();

        http
                .securityMatcher("/", "/web/**", "/logout")
                .csrf(csrf -> csrf.csrfTokenRequestHandler(csrfHandler))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                // Явно задаем сессионный репозиторий контекста: web chain хранит
                // аутентификацию в HTTP-сессии, API chain остается stateless.
                .securityContext(context -> context
                        .securityContextRepository(new DelegatingSecurityContextRepository(
                                new HttpSessionSecurityContextRepository(),
                                new RequestAttributeSecurityContextRepository())))
                // Rate limiting по IP и для веб-логина (Task-09/Task-11)
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        // Статика веб-интерфейса (стили, скрипт темы) — без аутентификации
                        .requestMatchers("/web/style.css", "/web/theme.js").permitAll()
                        // Страница логина и обработчик формы — без аутентификации
                        .requestMatchers("/", "/web/login").permitAll()
                        // Task-12: веб-раздел администратора — только ROLE_ADMIN.
                        // Неаутентифицированный -> редирект на /web/login (entry point
                        // ниже), аутентифицированный без роли -> 403.
                        .requestMatchers("/web/admin/**").hasRole("ADMIN")
                        // Остальное — только аутентифицированным
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        // Неаутентифицированный доступ к страницам — редирект на логин
                        .authenticationEntryPoint(
                                new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint(
                                        "/web/login")))
                .formLogin(form -> form.disable())
                .logout(logout -> logout.disable());
        return http.build();
    }

    /**
     * Цепочка API (Task-01..09) — поведение не изменено (Task-11:
     * «веб-часть не должна ломать текущую Bearer-аутентификацию»).
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            BearerTokenAuthenticationFilter bearerFilter,
            RateLimitFilter rateLimitFilter,
            @Value("${app.security.dev-profile:false}") boolean devProfile) throws Exception {
        http
                .securityMatcher("/api/**", "/actuator/**", "/api-docs/**",
                        "/swagger-ui/**", "/swagger-ui.html")
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
