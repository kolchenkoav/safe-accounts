package com.example.safeaccounts.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.example.safeaccounts.security.RateLimiter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты Фазы 6: rate-limit на импорт (POST /api/vault/import
 * и POST /api/admin/users/{id}/vault/import).
 * <p>
 * Сценарий: лимит 2 запроса на 5 секунд на IP, MockMvc использует 127.0.0.1.
 * Первые два вызова проходят лимитер (401 от auth-фильтра, но не 429), третий —
 * 429 RFC 7807 с заголовком {@code Retry-After}. Сценарий изолирован от
 * bucket'а AUTH: после исчерпания import-лимита login/register продолжают
 * работать.
 * <p>
 * PostgreSQL поднимается через Testcontainers; секреты синтетические, только
 * тестовый профиль (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
// Фаза 6: жестко задаём маленький лимит — application-it.yaml повышает
// значение для других ИТ-тестов (VaultApiIT делает несколько импортов).
@TestPropertySource(properties = {
        "app.vault.import.rate-limit.window-seconds=5",
        "app.vault.import.rate-limit.max-requests=2"
})
class ImportRateLimitIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    RateLimiter rateLimiter;

    private static final String CSV_BODY =
            "name,url,username,password,note\r\nSite,u,l,p,n\r\n";

    private static MockMultipartFile csvFile() {
        return new MockMultipartFile(
                "file", "import.csv", "text/csv",
                CSV_BODY.getBytes(StandardCharsets.UTF_8));
    }

    @BeforeEach
    void resetLimiter() {
        // Без сброса состояние от предыдущего теста в этом же JVM может
        // просочиться в текущий, если MockMvc использует один IP.
        rateLimiter.reset();
    }

    // -- POST /api/vault/import ---------------------------------------------

@Test
    void vaultImportReturns429AfterLimitExceeded() throws Exception {
        // Первые два — НЕ 429 (хоть и не 200: rate-limit бежит до auth,
        // поэтому без токена они вернут 401, но это уже после лимитера).
        assertWithinLimit(2);
        // Третий — 429 RFC 7807 + Retry-After
        mockMvc.perform(multipart("/api/vault/import").file(csvFile()))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.title").value("Too Many Requests"))
                .andExpect(jsonPath("$.detail").isNotEmpty());
    }

/** Делает {@code count} вызовов подряд и проверяет, что ни один не вернул 429. */
    private void assertWithinLimit(int count, RequestPostProcessor... postProcessors) throws Exception {
        for (int i = 0; i < count; i++) {
            final int attempt = i + 1;
            var request = multipart("/api/vault/import").file(csvFile());
            for (RequestPostProcessor pp : postProcessors) {
                request.with(pp);
            }
            mockMvc.perform(request).andExpect(result -> {
                int status = result.getResponse().getStatus();
                if (status == 429) {
                    throw new AssertionError(
                            "request " + attempt + " must not be rate-limited yet, got 429");
                }
            });
        }
    }

    // -- POST /api/admin/users/{id}/vault/import ----------------------------

@Test
    void adminImportReturns429AfterLimitExceeded() throws Exception {
        String adminPath = "/api/admin/users/" + UUID.randomUUID() + "/vault/import";

        assertWithinLimitAdmin(adminPath, 2);
        mockMvc.perform(multipart(adminPath).file(csvFile()))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.status").value(429));
    }

    private void assertWithinLimitAdmin(String path, int count) throws Exception {
        for (int i = 0; i < count; i++) {
            final int attempt = i + 1;
            mockMvc.perform(multipart(path).file(csvFile()))
                    .andExpect(result -> {
                        int status = result.getResponse().getStatus();
                        if (status == 429) {
                            throw new AssertionError(
                                    "admin request " + attempt + " must not be rate-limited yet, got 429");
                        }
                    });
        }
    }

    // -- изоляция bucket'ов --------------------------------------------------

    @Test
    void importLimitDoesNotBlockLogin() throws Exception {
        // Исчерпываем IMPORT-бакет
        for (int i = 0; i < 2; i++) {
            mockMvc.perform(multipart("/api/vault/import").file(csvFile()));
        }
        mockMvc.perform(multipart("/api/vault/import").file(csvFile()))
                .andExpect(status().isTooManyRequests());

        // /api/auth/login — это другой bucket; здесь лимит высокий (10000),
        // запрос проходит (как 401 — пользователь не существует).
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/auth/login")
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"nope\",\"password\":\"Str0ng-Passw0rd!\"}"))
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    if (status == 429) {
                        throw new AssertionError(
                                "login must not be rate-limited by import bucket, got 429");
                    }
                });
    }

    // -- per-IP изоляция ----------------------------------------------------

@Test
    void importLimitIsPerIp() throws Exception {
        // IP A — два запроса
        RequestPostProcessor ipA = req -> {
            req.setRemoteAddr("10.0.0.1");
            return req;
        };
        assertWithinLimit(2, ipA);
        // IP A — третий уже 429
        mockMvc.perform(multipart("/api/vault/import").file(csvFile()).with(ipA))
                .andExpect(status().isTooManyRequests());

        // IP B — не затронут (1-й запрос проходит лимитер)
        RequestPostProcessor ipB = req -> {
            req.setRemoteAddr("10.0.0.2");
            return req;
        };
        assertWithinLimit(1, ipB);
    }
}