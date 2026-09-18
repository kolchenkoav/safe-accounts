package com.example.safeaccounts.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Rate limiting (Task-09, Фаза 6; web-маршруты — Фаза 5) для:
 * <ul>
 *   <li>{@code POST /api/auth/login} и {@code POST /api/auth/register} — bucket
 *       {@link RateLimiter#BUCKET_AUTH} (защита от перебора паролей);</li>
 *   <li>{@code POST /api/vault/import} и
 *       {@code POST /api/admin/users/{id}/vault/import} — bucket
 *       {@link RateLimiter#BUCKET_IMPORT};</li>
 *   <li>{@code POST /web/entries/import} и
 *       {@code POST /web/admin/users/{id}/vault/import} — тот же bucket
 *       {@link RateLimiter#BUCKET_IMPORT} (Фаза 5, план §2.7).</li>
 * </ul>
 * Превышение лимита — {@code 429 Too Many Requests} в формате RFC 7807
 * ProblemDetail (для web-запросов тоже JSON — согласованное решение №4,
 * HTML-страница 429 отложена). Заголовок {@code Retry-After} подсказывает,
 * когда можно повторить (в секундах, рассчитан по оставшемуся окну).
 * <p>
 * Ключ внутри bucket'а:
 * <ul>
 *   <li>api-маршруты — IP из {@code request.getRemoteAddr()}
 *       (приложение за доверенным TLS-терминатором;
 *       {@code X-Forwarded-For} не доверяем);</li>
 *   <li>web-маршруты импорта — username из аутентификации сессии
 *       (SecurityContext восстанавливается из сессии ДО этого фильтра),
 *       fallback — IP (анонимные запросы всё равно завернутся на логин).</li>
 * </ul>
 * IP/username в логах — не секрет; пароли/токены/CSV-содержимое в логи
 * не попадают.
 * <p>
 * Матчинг путей идёт по сырому {@code request.getRequestURI()} — это
 * защищено дефолтным StrictHttpFirewall (spring-security-web), который
 * блокирует «;»/«%3b» в пути ДО FilterChainProxy (пиннинг-IT —
 * SecurityChecksIT). При кастомизации firewall нужно добавить
 * нормализацию пути перед матчингом (backlog).
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    static final String PROBLEM_TYPE = "about:blank";
    static final String PROBLEM_TITLE = "Too Many Requests";
    static final String PROBLEM_DETAIL = "Too many requests, try again later";

    /**
     * Эндпоинты импорта REST API: {@code /api/vault/import} — собственный сейф,
     * {@code /api/admin/users/{id}/vault/import} — чужой сейф (ADMIN).
     * Фиксированная часть {@code /import} в конце пути гарантирует, что
     * под фильтр не попадут экспорт и любые будущие эндпоинты вроде
     * {@code /api/vault/import-...}.
     */
    private static final Pattern IMPORT_PATH =
            Pattern.compile("^/api/(vault|admin/users/[^/]+/vault)/import$");

    /** Web-эндпоинты импорта (Фаза 5, план §2.7): те же два сценария в UI. */
    private static final Pattern WEB_IMPORT_PATH =
            Pattern.compile("^/web/(entries|admin/users/[^/]+/vault)/import$");

    private final RateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // getRequestURI, а не getServletPath: в MockMvc servletPath пуст.
        if (!"POST".equals(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        if ("/api/auth/login".equals(path) || "/api/auth/register".equals(path)) {
            return false;
        }
        return !IMPORT_PATH.matcher(path).matches() && !WEB_IMPORT_PATH.matcher(path).matches();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        String bucket = pickBucket(request);
        // Web-импорт: ключ — username из сессии (план §2.7), fallback — IP.
        String key = rateLimitKey(request, path);
        RateLimiter.Decision decision = rateLimiter.tryAcquireWithRetryAfter(key, bucket);
        if (!decision.allowed()) {
            log.warn("Rate limit exceeded for {} on {} {} (bucket={}, retryAfter={}s)",
                    key, request.getMethod(), path, bucket, decision.retryAfterSeconds());
            writeProblem(response, decision.retryAfterSeconds());
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Ключ rate-limit: для web-маршрутов импорта — username аутентификации
     * (SecurityContext уже восстановлен из сессии), иначе — IP клиента.
     */
    private String rateLimitKey(HttpServletRequest request, String path) {
        if (WEB_IMPORT_PATH.matcher(path).matches()) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.isAuthenticated() && auth.getName() != null
                    && !auth.getName().isEmpty()
                    && !"anonymousUser".equals(auth.getName())) {
                return "user:" + auth.getName();
            }
        }
        return request.getRemoteAddr();
    }

    /**
     * Возвращает имя bucket'а для указанного запроса: import-эндпоинты
     * (api и web) → {@link RateLimiter#BUCKET_IMPORT}, всё остальное
     * (включая login/register) → {@link RateLimiter#BUCKET_AUTH}.
     * Scan (G2) лимитируется в сервисе ПОСЛЕ аутентификации: у Bearer-запросов
     * SecurityContext на фазе фильтра пуст (anonymous), и ключ user:<name>
     * деградировал бы до IP.
     */
    private String pickBucket(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (IMPORT_PATH.matcher(path).matches() || WEB_IMPORT_PATH.matcher(path).matches()) {
            return RateLimiter.BUCKET_IMPORT;
        }
        return RateLimiter.BUCKET_AUTH;
    }

    private void writeProblem(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.TOO_MANY_REQUESTS, PROBLEM_DETAIL);
        problem.setType(URI.create(PROBLEM_TYPE));
        problem.setTitle(PROBLEM_TITLE);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", problem.getType().toString());
        body.put("title", problem.getTitle());
        body.put("status", problem.getStatus());
        body.put("detail", problem.getDetail());

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
