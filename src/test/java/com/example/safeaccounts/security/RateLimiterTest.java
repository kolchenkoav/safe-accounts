package com.example.safeaccounts.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты rate limiter (Task-09, Фаза 6): скользящее окно, лимит по IP,
 * независимость клиентов, сброс состояния, изоляция bucket'ов,
 * корректный {@code Retry-After} при превышении.
 */
class RateLimiterTest {

    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        // ВАЖНО: сигнатура конструктора — (authWindow, authMax, importWindow, importMax,
        // scanWindow, scanMax). Параметры bucket'а AUTH: окно 60с, лимит 5 — повторяет
        // ранее существовавший тест-набор. IMPORT: окно 60с, лимит 2. SCAN: окно 60с, лимит 1.
        rateLimiter = new RateLimiter(60, 5, 60, 2, 60, 1);
    }

    // -- bucket AUTH (исходное поведение Task-09) ----------------------------

    @Test
    void authBucketAllowsUpToLimit() {
        String ip = "10.0.0.1";
        for (int i = 0; i < 5; i++) {
            assertThat(rateLimiter.tryAcquire(ip)).as("request %d", i + 1).isTrue();
        }
    }

    @Test
    void authBucketBlocksAfterLimit() {
        String ip = "10.0.0.2";
        for (int i = 0; i < 5; i++) {
            rateLimiter.tryAcquire(ip);
        }
        assertThat(rateLimiter.tryAcquire(ip)).isFalse();
        assertThat(rateLimiter.tryAcquire(ip)).isFalse();
    }

    @Test
    void authBucketLimitsArePerIp() {
        for (int i = 0; i < 5; i++) {
            rateLimiter.tryAcquire("10.0.0.3");
        }
        assertThat(rateLimiter.tryAcquire("10.0.0.3")).isFalse();
        // Другой IP не затронут
        assertThat(rateLimiter.tryAcquire("10.0.0.4")).isTrue();
    }

    @Test
    void nullOrBlankIpIsAllowed() {
        assertThat(rateLimiter.tryAcquire(null)).isTrue();
        assertThat(rateLimiter.tryAcquire("")).isTrue();
        assertThat(rateLimiter.tryAcquire("  ")).isTrue();
    }

    @Test
    void usedByCountsRequestsInWindow() {
        String ip = "10.0.0.5";
        rateLimiter.tryAcquire(ip);
        rateLimiter.tryAcquire(ip);
        assertThat(rateLimiter.usedBy(ip)).isEqualTo(2);
        assertThat(rateLimiter.usedBy("unknown")).isEqualTo(0);
    }

    @Test
    void resetClearsState() {
        String ip = "10.0.0.6";
        for (int i = 0; i < 5; i++) {
            rateLimiter.tryAcquire(ip);
        }
        assertThat(rateLimiter.tryAcquire(ip)).isFalse();
        rateLimiter.reset();
        assertThat(rateLimiter.tryAcquire(ip)).isTrue();
    }

    // -- bucket IMPORT (Фаза 6) ---------------------------------------------

    @Test
    void importBucketAllowsUpToLimitThenBlocks() {
        String ip = "10.1.0.1";
        // лимит IMPORT = 2: первые два запроса проходят
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
        // третий — отклоняется
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isFalse();
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isFalse();
    }

    @Test
    void importBucketIsolatedFromAuthBucket() {
        // Один IP — два разных bucket'а, счётчики НЕ пересекаются.
        String ip = "10.1.0.2";
        // Исчерпываем AUTH (лимит 5)
        for (int i = 0; i < 5; i++) {
            assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_AUTH)).isTrue();
        }
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_AUTH)).isFalse();
        // IMPORT у этого же IP — лимит 2, оба проходят
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isFalse();
        // Обратное направление: 6 попыток IMPORT ничего не значат про AUTH
        for (int i = 0; i < 4; i++) {
            rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT);
        }
        assertThat(rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_AUTH)).isFalse();
    }

    @Test
    void importBucketReturnsRetryAfterSecondsOnLimit() {
        // Минимальное окно (1с) и лимит 1: после первого запроса следующий сразу отклонён.
        RateLimiter small = new RateLimiter(60, 100, 1, 1, 60, 1);
        String ip = "10.1.0.3";
        assertThat(small.tryAcquireWithRetryAfter(ip, RateLimiter.BUCKET_IMPORT).allowed())
                .isTrue();
        RateLimiter.Decision denied =
                small.tryAcquireWithRetryAfter(ip, RateLimiter.BUCKET_IMPORT);
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.retryAfterSeconds()).isBetween(1L, 1L);
    }

    @Test
    void importBucketResetsAfterWindow() throws Exception {
        // Окно 1с — после ожидания счётчик сбрасывается.
        RateLimiter small = new RateLimiter(60, 100, 1, 1, 60, 1);
        String ip = "10.1.0.4";
        assertThat(small.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
        assertThat(small.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isFalse();
        Thread.sleep(1100);
        assertThat(small.tryAcquire(ip, RateLimiter.BUCKET_IMPORT)).isTrue();
    }

    @Test
    void unknownBucketIsAllowed() {
        String ip = "10.1.0.5";
        // Неизвестное имя bucket'а — запрос пропускается без счётчика.
        assertThat(rateLimiter.tryAcquire(ip, "does-not-exist")).isTrue();
        assertThat(rateLimiter.tryAcquire(ip, "does-not-exist")).isTrue();
        assertThat(rateLimiter.tryAcquire(ip, "does-not-exist")).isTrue();
    }

    @Test
    void usedByIsPerBucket() {
        String ip = "10.1.0.6";
        rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_AUTH);
        rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_AUTH);
        rateLimiter.tryAcquire(ip, RateLimiter.BUCKET_IMPORT);

        assertThat(rateLimiter.usedBy(ip, RateLimiter.BUCKET_AUTH)).isEqualTo(2);
        assertThat(rateLimiter.usedBy(ip, RateLimiter.BUCKET_IMPORT)).isEqualTo(1);
        // Одноаргументный API — bucket AUTH
        assertThat(rateLimiter.usedBy(ip)).isEqualTo(2);
    }
}