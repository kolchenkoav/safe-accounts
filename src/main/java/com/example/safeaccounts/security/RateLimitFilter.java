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

/**
 * Rate limiting (Task-09) для POST /api/auth/login и POST /api/auth/register.
 * <p>
 * Превышение лимита — 429 Too Many Requests в формате RFC 7807 ProblemDetail
 * (см. AGENTS.md: 429 тоже ProblemDetail). Заголовок Retry-After подсказывает,
 * когда можно повторить. IP берется из request.getRemoteAddr(): приложение
 * предназначено для работы за доверенным TLS-терминатором; заголовок
 * X-Forwarded-For не доверяем, т.к. он легко подделывается.
 * <p>
 * IP в логах — не секрет; пароли/токены в логи не попадают.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    static final String PROBLEM_TYPE = "about:blank";
    static final String PROBLEM_TITLE = "Too Many Requests";
    static final String PROBLEM_DETAIL = "Too many requests, try again later";

    private final RateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // getRequestURI, а не getServletPath: в MockMvc servletPath пуст.
        String path = request.getRequestURI();
        return !("POST".equals(request.getMethod())
                && ("/api/auth/login".equals(path) || "/api/auth/register".equals(path)));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientIp = request.getRemoteAddr();
        if (!rateLimiter.tryAcquire(clientIp)) {
            log.warn("Rate limit exceeded for IP {} on {} {}", clientIp,
                    request.getMethod(), request.getRequestURI());
            writeProblem(response);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void writeProblem(HttpServletResponse response) throws IOException {
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
        response.setHeader("Retry-After", "60");
        objectMapper.writeValue(response.getWriter(), body);
    }
}
