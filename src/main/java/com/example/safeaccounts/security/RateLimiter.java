package com.example.safeaccounts.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory rate limiter (Task-09, Фаза 6) — скользящее окно на client IP.
 * <p>
 * Поддерживает несколько независимых bucket'ов с разными лимитами/окнами.
 * На сегодня определены два:
 * <ul>
 *   <li>{@link #BUCKET_AUTH} — для {@code POST /api/auth/login} и
 *       {@code POST /api/auth/register} (Task-09, защита от перебора).</li>
 *   <li>{@link #BUCKET_IMPORT} — для {@code POST /api/vault/import} и
 *       {@code POST /api/admin/users/{id}/vault/import} (Фаза 6, защита
 *       от массовой записи в сейф).</li>
 *   <li>{@link #BUCKET_SCAN} — для {@code POST /api/vault/scan} и
 *       {@code POST /api/admin/users/{id}/vault/scan} (G2: расшифровка
 *       до 10 000 записей — CPU-интерсив; 1 запуск/60 с на пользователя).</li>
 * </ul>
 * Ключ внутри bucket'а — IP клиента из {@code request.getRemoteAddr()}.
 * Расшифровка токена в фильтре не требуется, что согласуется с уже
 * существующим rate-limit'ом login/register.
 * <p>
 * Превышение лимита — {@code 429 Too Many Requests} в формате RFC 7807
 * ProblemDetail с заголовком {@code Retry-After} (см. {@link RateLimitFilter}).
 * Состояние лимитера секретов не содержит и в логи не пишется.
 * <p>
 * Компромисс (зафиксирован в Task-09): реализация однопроцессная.
 * При горизонтальном масштабировании требуется распределенный лимитер
 * (например, Redis) — иначе лимиты действуют на каждый инстанс отдельно.
 */
@Component
public class RateLimiter {

    /** Bucket для /api/auth/login и /api/auth/register. */
    public static final String BUCKET_AUTH = "auth";

    /** Bucket для /api/vault/import и /api/admin/users/{id}/vault/import. */
    public static final String BUCKET_IMPORT = "import";

    /** Bucket для /api/vault/scan и /api/admin/users/{id}/vault/scan (G2). */
    public static final String BUCKET_SCAN = "scan";

    /** Имя bucket'а по умолчанию для обратной совместимости со старым API. */
    private static final String DEFAULT_BUCKET = BUCKET_AUTH;

    /** Конфигурация всех известных bucket'ов (вычисляется один раз на старте). */
    private final Map<String, Bucket> buckets;

    /** Состояние: bucketName -> (IP -> Window). */
    private final Map<String, Map<String, Window>> windows = new ConcurrentHashMap<>();

    public RateLimiter(
            @Value("${app.rate-limit.window-seconds:60}") long authWindowSeconds,
            @Value("${app.rate-limit.max-requests:10}") int authMaxRequests,
            @Value("${app.vault.import.rate-limit.window-seconds:60}") long importWindowSeconds,
            @Value("${app.vault.import.rate-limit.max-requests:3}") int importMaxRequests,
            @Value("${app.vault.scan.rate-limit.window-seconds:60}") long scanWindowSeconds,
            @Value("${app.vault.scan.rate-limit.max-requests:1}") int scanMaxRequests) {
        this.buckets = Map.of(
                BUCKET_AUTH, new Bucket(authWindowSeconds * 1000L, authMaxRequests),
                BUCKET_IMPORT, new Bucket(importWindowSeconds * 1000L, importMaxRequests),
                BUCKET_SCAN, new Bucket(scanWindowSeconds * 1000L, scanMaxRequests));
    }

    // -- устаревший API (single-arg), делегирует в bucket AUTH -----------------

    /**
     * Пытается зарегистрировать запрос от указанного клиента в bucket'е AUTH.
     *
     * @param clientIp IP клиента (из {@code request.getRemoteAddr()})
     * @return true, если запрос разрешен; false, если лимит превышен
     */
    public boolean tryAcquire(String clientIp) {
        return tryAcquire(clientIp, DEFAULT_BUCKET);
    }

    /** Сколько запросов от IP израсходовано в текущем окне bucket'а AUTH (для тестов). */
    public int usedBy(String clientIp) {
        return usedBy(clientIp, DEFAULT_BUCKET);
    }

    // -- новый API: с явным именем bucket'а ------------------------------------

    /**
     * Пытается зарегистрировать запрос от клиента в указанном bucket'е.
     *
     * @param clientIp   IP клиента
     * @param bucketName имя bucket'а ({@link #BUCKET_AUTH} или {@link #BUCKET_IMPORT});
     *                   неизвестный bucket трактуется как «пропустить всегда»
     * @return true, если запрос разрешен; false, если лимит превышен
     */
    public boolean tryAcquire(String clientIp, String bucketName) {
        return check(clientIp, bucketName).allowed;
    }

    /**
     * Пытается зарегистрировать запрос и возвращает решение с точным
     * {@code Retry-After} (в секундах, &ge; 1). Если bucket неизвестен или IP пустой —
     * запрос пропускается.
     */
    public Decision tryAcquireWithRetryAfter(String clientIp, String bucketName) {
        return check(clientIp, bucketName);
    }

    /** Сколько запросов от IP израсходовано в текущем окне указанного bucket'а. */
    public int usedBy(String clientIp, String bucketName) {
        Bucket bucket = buckets.get(bucketName);
        if (bucket == null) {
            return 0;
        }
        Map<String, Window> perIp = windows.get(bucketName);
        if (perIp == null) {
            return 0;
        }
        Window window = perIp.get(clientIp);
        if (window == null) {
            return 0;
        }
        long now = System.currentTimeMillis();
        if (now - window.startMillis >= bucket.windowMillis) {
            return 0;
        }
        return (int) window.count.get();
    }

    /** Сброс всего состояния (используется тестами). */
    public void reset() {
        windows.clear();
    }

    // -- internals -----------------------------------------------------------

    /**
     * Общая реализация: возвращает решение + retryAfterSeconds.
     * Сложность O(1) на запрос.
     */
    private Decision check(String clientIp, String bucketName) {
        Bucket bucket = buckets.get(bucketName);
        if (bucket == null || clientIp == null || clientIp.isBlank()) {
            // Не блокируем: неизвестный bucket или IP — не считаем.
            return Decision.ALLOWED;
        }
        long now = System.currentTimeMillis();
        Map<String, Window> perIp = windows.computeIfAbsent(bucketName,
                k -> new ConcurrentHashMap<>());
        Window window = perIp.compute(clientIp, (ip, existing) -> {
            if (existing == null || now - existing.startMillis >= bucket.windowMillis) {
                return new Window(now, bucket.windowMillis);
            }
            existing.count.incrementAndGet();
            return existing;
        });
        boolean allowed = window.count.get() <= bucket.maxRequests;
        cleanup(now);
        if (allowed) {
            return Decision.ALLOWED;
        }
        long retryAfterMillis = bucket.windowMillis - (now - window.startMillis);
        long retryAfterSeconds = Math.max(1L, (retryAfterMillis + 999L) / 1000L);
        return new Decision(false, retryAfterSeconds);
    }

    /**
     * Решение лимитера.
     *
     * @param allowed           true, если запрос разрешен
     * @param retryAfterSeconds сколько секунд ждать до повтора (>= 1, если !allowed)
     */
    public record Decision(boolean allowed, long retryAfterSeconds) {
        /** Решение «разрешить» (retryAfterSeconds игнорируется). */
        public static final Decision ALLOWED = new Decision(true, 0L);
    }

    /** Конфигурация одного bucket'а (window + лимит). */
    private record Bucket(long windowMillis, int maxRequests) {
    }

    /**
     * Окно: время начала, размер окна (зафиксирован на момент создания),
     * счетчик запросов. Пересоздается при выходе из окна.
     */
    private static final class Window {
        final long startMillis;
        final long windowMillis;
        final AtomicLong count;

        Window(long startMillis, long windowMillis) {
            this.startMillis = startMillis;
            this.windowMillis = windowMillis;
            this.count = new AtomicLong(1);
        }
    }

    /**
     * Удаляет устаревшие окна, чтобы Map не росла бесконечно
     * (в том числе при brute force с подменой IP). Для каждого bucket'а
     * окно проверяется по своему размеру.
     */
    private void cleanup(long now) {
        for (Map.Entry<String, Map<String, Window>> entry : windows.entrySet()) {
            Map<String, Window> perIp = entry.getValue();
            perIp.values().removeIf(w -> now - w.startMillis >= w.windowMillis * 2);
        }
        int total = windows.values().stream().mapToInt(Map::size).sum();
        if (total > 100_000) {
            windows.clear();
        }
    }
}