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
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Rate limiting (Task-09, Фаза 6) для:
 * <ul>
 *   <li>{@code POST /api/auth/login} и {@code POST /api/auth/register} — bucket
 *       {@link RateLimiter#BUCKET_AUTH} (защита от перебора паролей);</li>
 *   <li>{@code POST /api/vault/import} и
 *       {@code POST /api/admin/users/{id}/vault/import} — bucket
 *       {@link RateLimiter#BUCKET_IMPORT} (защита от массовой записи в сейф).</li>
 * </ul>
 * Превышение лимита — {@code 429 Too Many Requests} в формате RFC 7807
 * ProblemDetail (см. AGENTS.md). Заголовок {@code Retry-After} подсказывает,
 * когда можно повторить (в секундах, рассчитан по оставшемуся окну).
 * <p>
 * IP берётся из {@code request.getRemoteAddr()}: приложение предназначено
 * для работы за доверенным TLS-терминатором; заголовок {@code X-Forwarded-For}
 * не доверяем, т.к. он легко подделывается. IP в логах — не секрет;
 * пароли/токены/CSV-содержимое в логи не попадают.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    static final String PROBLEM_TYPE = "about:blank";
    static final String PROBLEM_TITLE = "Too Many Requests";
    static final String PROBLEM_DETAIL = "Too many requests, try again later";

    /**
     * Эндпоинты импорта:
     * <ul>
     *   <li>{@code /api/vault/import} — собственный сейф;</li>
     *   <li>{@code /api/admin/users/{id}/vault/import} — чужой сейф (ADMIN).</li>
     * </ul>
     * Фиксированная часть {@code /import} в конце пути гарантирует, что
     * под фильтр не попадут экспорт и любые будущие эндпоинты вроде
     * {@code /api/vault/import-...}.
     */
    private static final Pattern IMPORT_PATH =
            Pattern.compile("^/api/(vault|admin/users/[^/]+/vault)/import$");

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
        return !IMPORT_PATH.matcher(path).matches();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();
        String bucket = pickBucket(request);
        RateLimiter.Decision decision = rateLimiter.tryAcquireWithRetryAfter(clientIp, bucket);
        if (!decision.allowed()) {
            log.warn("Rate limit exceeded for IP {} on {} {} (bucket={}, retryAfter={}s)",
                    clientIp, request.getMethod(), request.getRequestURI(),
                    bucket, decision.retryAfterSeconds());
            writeProblem(response, decision.retryAfterSeconds());
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Возвращает имя bucket'а для указанного запроса. На сегодня два:
     * import-эндпоинты → {@link RateLimiter#BUCKET_IMPORT}, всё остальное
     * (включая login/register) → {@link RateLimiter#BUCKET_AUTH}.
     */
    private String pickBucket(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (IMPORT_PATH.matcher(path).matches()) {
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
        response.setHeader("Retry-After", Long.toString(retryAfterSeconds));
        objectMapper.writeValue(response.getWriter(), body);
    }
}