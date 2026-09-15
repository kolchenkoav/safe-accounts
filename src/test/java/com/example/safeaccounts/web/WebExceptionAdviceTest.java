package com.example.safeaccounts.web;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты анти-open-redirect хелпера WebExceptionAdvice.safeReturnTo
 * (Фаза 5, тест-харднинг): same-origin Referer возвращает свой путь,
 * всё подозрительное — нейтральный fallback.
 */
class WebExceptionAdviceTest {

    private static final String FALLBACK = WebExceptionAdvice.DEFAULT_IMPORT_RETURN;

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("https");
        request.setServerName("vault.example.com");
        request.setServerPort(8443);
        request.setRemoteAddr("203.0.113.10");
        return request;
    }

    @Test
    void sameOriginWebRefererReturnsItsPath() {
        var request = request();
        request.addHeader("Referer",
                "https://vault.example.com:8443/web/admin/users/123/vault/import");
        assertThat(WebExceptionAdvice.safeReturnTo(request))
                .isEqualTo("/web/admin/users/123/vault/import");
    }

    @Test
    void crossDomainRefererFallsBack() {
        var request = request();
        request.addHeader("Referer", "https://evil.example.com/web/entries/import");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void refererWithoutSchemeFallsBack() {
        var request = request();
        request.addHeader("Referer", "/web/entries/import");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void refererOutsideWebPathFallsBack() {
        var request = request();
        request.addHeader("Referer", "https://vault.example.com:8443/api/vault");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void refererWithDoubleSlashFallsBack() {
        var request = request();
        request.addHeader("Referer", "https://vault.example.com:8443//web/entries");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void refererWithColonAfterPathFallsBack() {
        var request = request();
        request.addHeader("Referer", "https://vault.example.com:8443/web/http://evil");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void garbageRefererFallsBack() {
        var request = request();
        request.addHeader("Referer", "::::");
        assertThat(WebExceptionAdvice.safeReturnTo(request)).isEqualTo(FALLBACK);
    }

    @Test
    void absentRefererFallsBack() {
        assertThat(WebExceptionAdvice.safeReturnTo(request())).isEqualTo(FALLBACK);
    }
}
