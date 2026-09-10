package com.example.safeaccounts.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты rate limiter (Task-09): скользящее окно, лимит по IP,
 * независимость клиентов, сброс состояния.
 */
class RateLimiterTest {

    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new RateLimiter(60, 5);
    }

    @Test
    void allowsUpToLimit() {
        String ip = "10.0.0.1";
        for (int i = 0; i < 5; i++) {
            assertThat(rateLimiter.tryAcquire(ip)).as("request %d", i + 1).isTrue();
        }
    }

    @Test
    void blocksAfterLimit() {
        String ip = "10.0.0.2";
        for (int i = 0; i < 5; i++) {
            rateLimiter.tryAcquire(ip);
        }
        assertThat(rateLimiter.tryAcquire(ip)).isFalse();
        assertThat(rateLimiter.tryAcquire(ip)).isFalse();
    }

    @Test
    void limitsArePerIp() {
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
}
