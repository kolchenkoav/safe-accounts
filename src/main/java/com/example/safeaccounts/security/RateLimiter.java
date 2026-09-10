package com.example.safeaccounts.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory rate limiter (Task-09) — скользящее окно на client IP.
 * <p>
 * Ограничивает количество запросов с одного IP за заданный интервал.
 * Предназначен для эндпоинтов, уязвимых к перебору:
 * {@code POST /api/auth/login} и {@code POST /api/auth/register}.
 * <p>
 * Безопасность: при превышении лимита клиент получает 429 Too Many Requests
 * в формате RFC 7807 ProblemDetail (см. RateLimitFilter). Состояние лимитера
 * секретов не содержит и в логи не пишется.
 * <p>
 * Компромисс (зафиксирован в Task-09): реализация однопроцессная.
 * При горизонтальном масштабировании требуется распределенный лимитер
 * (например, Redis) — иначе лимиты действуют на каждый инстанс отдельно.
 */
@Component
public class RateLimiter {

    private final long windowMillis;
    private final int maxRequestsPerWindow;

    // IP -> текущее окно со счетчиком.
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimiter(
            @Value("${app.rate-limit.window-seconds:60}") long windowSeconds,
            @Value("${app.rate-limit.max-requests:10}") int maxRequestsPerWindow) {
        this.windowMillis = windowSeconds * 1000;
        this.maxRequestsPerWindow = maxRequestsPerWindow;
    }

    /**
     * Пытается зарегистрировать запрос от указанного клиента.
     *
     * @param clientIp IP клиента (из {@code request.getRemoteAddr()})
     * @return true, если запрос разрешен; false, если лимит превышен
     */
    public boolean tryAcquire(String clientIp) {
        if (clientIp == null || clientIp.isBlank()) {
            // IP определить не удалось: не блокируем, но и не считаем.
            return true;
        }
        long now = System.currentTimeMillis();
        Window window = windows.compute(clientIp, (ip, existing) -> {
            if (existing == null || now - existing.startMillis >= windowMillis) {
                return new Window(now);
            }
            existing.count.incrementAndGet();
            return existing;
        });
        boolean allowed = window.count.get() <= maxRequestsPerWindow;
        cleanup(now);
        return allowed;
    }

    /** Сколько запросов от IP израсходовано в текущем окне (используется тестами). */
    public int usedBy(String clientIp) {
        Window window = windows.get(clientIp);
        if (window == null) {
            return 0;
        }
        long now = System.currentTimeMillis();
        if (now - window.startMillis >= windowMillis) {
            return 0;
        }
        return (int) window.count.get();
    }

    /** Сброс состояния (используется тестами). */
    public void reset() {
        windows.clear();
    }

    // -- internals -----------------------------------------------------------

    /** Окно: время начала + счетчик запросов. Пересоздается при выходе из окна. */
    private static final class Window {
        final long startMillis;
        final AtomicLong count;

        Window(long startMillis) {
            this.startMillis = startMillis;
            this.count = new AtomicLong(1);
        }
    }

    /**
     * Удаляет устаревшие окна, чтобы Map не росла бесконечно
     * (в том числе при brute force с подменой IP).
     */
    private void cleanup(long now) {
        windows.values().removeIf(w -> now - w.startMillis >= windowMillis * 2);
        if (windows.size() > 100_000) {
            windows.clear();
        }
    }
}
