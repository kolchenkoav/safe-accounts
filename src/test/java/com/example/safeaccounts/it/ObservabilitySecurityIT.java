package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.example.safeaccounts.security.RateLimiter;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты Task-09: rate limiting по IP (429 + RFC 7807),
 * безопасные заголовки, закрытость служебных эндпоинтов (actuator, swagger),
 * отсутствие утечек в health.
 * <p>
 * PostgreSQL поднимается через Testcontainers; учетные данные — синтетические
 * тестовые значения только в тестовом профиле (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
// Task-09: жестко задаем лимит 10 — application-it.yaml повышает его для
// других ИТ-тестов; сценарий 429 здесь проверяется на точном лимите.
@TestPropertySource(properties = {
        "app.rate-limit.window-seconds=60",
        "app.rate-limit.max-requests=10"
})
class ObservabilitySecurityIT {

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
    @Autowired
    TransactionTemplate transactionTemplate;
    @Autowired
    UserRepository userRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    AuditEventRepository auditEventRepository;

    private static final String PASSWORD = "Str0ng-Passw0rd!";

    @BeforeEach
    void resetLimiter() {
        rateLimiter.reset();
        // Герметичность для теста export-аудита (см. ниже): пользователь/записи
        // не переиспользуются между прогонами JVM (имя регистрируется заново).
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
            vaultEntryRepository.deleteAll();
            userRepository.deleteAll();
        });
    }

    // -- rate limiting ---------------------------------------------------------

    @Test
    void loginReturns429WithProblemDetailWhenLimitExceeded() throws Exception {
        // Лимит по умолчанию 10 запросов/мин на IP (application.yaml);
// MockMvc использует remoteAddr 127.0.0.1.
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(
                                    new LoginRequest("rl-user-" + i, PASSWORD))))
                    .andExpect(status().isUnauthorized()); // пользователь не существует
        }
        // 11-й запрос — 429 Too Many Requests в формате RFC 7807.
        // Фаза 6: Retry-After теперь рассчитывается точно по оставшемуся окну
        // (а не фиксировано 60), потому что RateLimiter хранит момент старта
        // окна; после 11 быстрых запросов в MockMvc остаётся чуть меньше 60с.
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("rl-user-x", PASSWORD))))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.detail").isNotEmpty())
                .andExpect(jsonPath("$.title").value("Too Many Requests"))
                // Значение Retry-After должно быть целым от 1 до 60
                // (не больше исходного окна 60с).
                .andExpect(result -> {
                    String header = result.getResponse().getHeader("Retry-After");
                    org.assertj.core.api.Assertions.assertThat(header)
                            .as("Retry-After header")
                            .isNotNull()
                            .matches("\\d+");
                    int seconds = Integer.parseInt(header);
                    org.assertj.core.api.Assertions.assertThat(seconds)
                            .isBetween(1, 60);
                })
                .andReturn().getResponse().getContentAsString();
        // 429 не содержит деталей о запросе (пароля и т.п.)
        assertThat(body).doesNotContain(PASSWORD);
    }

    @Test
    void registerReturns429WhenLimitExceeded() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(post("/api/auth/register")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(
                                    new RegisterRequest("reg-rl-" + i, PASSWORD))))
                    .andExpect(status().isCreated());
        }
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new RegisterRequest("reg-rl-overflow", PASSWORD))))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void limiterDoesNotBlockOtherEndpointsAfterAuthLimit() throws Exception {
        // Исчерпываем лимит на login
        for (int i = 0; i < 11; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(
                                    new LoginRequest("nolimit-user", PASSWORD))))
                    .andExpect(status().is(i == 10 ? 429 : 401));
        }
        // Другие эндпоинты не блокируются (rate limit только на login/register)
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized()); // 401 (нет токена), не 429
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    // -- безопасные заголовки ----------------------------------------------------

    @Test
    void securityHeadersArePresentOnApiResponses() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    void securityHeadersOnLoginResponse() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("hdr-user", PASSWORD))))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    // -- служебные эндпоинты закрыты ---------------------------------------------

    @Test
    void sensitiveActuatorEndpointsAreDenied() throws Exception {
        // Разрешенные: health, info, prometheus
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/info")).andExpect(status().isOk());
        mockMvc.perform(get("/actuator/prometheus")).andExpect(status().isOk());
        // Запрещенные: env, beans, mappings, metrics, threaddump, loggers.
        // denyAll для неаутентифицированного запроса дает 401 (entry point) —
        // важно лишь то, что доступ запрещен и содержимое не раскрывается.
        for (String endpoint : List.of("env", "beans", "mappings", "metrics",
                "threaddump", "loggers", "configprops", "caches", "conditions",
                "scheduledtasks", "httptrace", "shutdown")) {
            mockMvc.perform(get("/actuator/" + endpoint))
                    .andExpect(status().is4xxClientError());
        }
    }

    @Test
    void healthDoesNotExposeSensitiveDetails() throws Exception {
        String body = mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        // show-details: never: никаких компонентов, URL БД, пользователей
        assertThat(body).doesNotContain("db");
        assertThat(body).doesNotContain("jdbc");
        assertThat(body).doesNotContain("safe_app");
        assertThat(body).doesNotContain("it_db_password");
        assertThat(body).contains("\"status\"");
    }

    @Test
    void prometheusExposesOnlyMetricsWithoutSecrets() throws Exception {
        String body = mockMvc.perform(get("/actuator/prometheus"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("it_db_password");
        assertThat(body).doesNotContain("B00tstrap-Admin-Pass");
        assertThat(body).contains("jvm_");
    }

    @Test
    void swaggerIsClosedOutsideDevProfile() throws Exception {
        // Тестовый профиль не dev: документация закрыта (Task-09)
        mockMvc.perform(get("/swagger-ui.html"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api-docs")).andExpect(status().isUnauthorized());
    }

    // -- маскирование ------------------------------------------------------------

    @Test
    void validationErrorDoesNotEchoPassword() throws Exception {
        // Ошибка валидации не должна возвращать тело с паролем
        String body = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"mask-user\",\"password\":\"short\"}"))
                .andExpect(status().isBadRequest())
                .andReturn().getResponse().getContentAsString();
        assertThat(body).doesNotContain("short");
    }

    // -- Фаза 8: мини-тест антиутечки пароля записи после export -------------

    @Test
    void exportDoesNotLeakEntryPasswordIntoAuditLog() throws Exception {
        String username = "obs-export-user";
        // Уникальный пароль записи, который не встречается ни в одной служебной
        // строке (CSV-формат, метки, etc.) — удобный маркер для поиска утечки.
        String entryPassword = "ObsExport-Marker-Pass-9z8x!";
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(username, PASSWORD))))
                .andExpect(status().isCreated());
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk())
                .andReturn();
        String token = objectMapper.readTree(login.getResponse().getContentAsString())
                .get("accessToken").asText();

        mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VaultEntryCreateRequest(
                                "ObsEntry", "https://obs.example.com", "alice",
                                entryPassword, "obs-note"))))
                .andExpect(status().isCreated());

        // Сам экспорт: HTTP-тело содержит пароль (это by design), но
        // журналируемый аудит и стандартный log-message — не должны.
        mockMvc.perform(get("/api/vault/export")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"));

        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository
                    .findAllByUser_IdOrderByCreatedAtDesc(
                            userRepository.findByUsername(username).orElseThrow().getId());
            // В аудите должны быть только агрегаты: ни пароля, ни логина, ни note.
            for (var event : events) {
                String blob = String.valueOf(event.getDetailsJson());
                assertThat(blob)
                        .as("audit detailsJson must not contain entry password for %s",
                                event.getType())
                        .doesNotContain(entryPassword)
                        .doesNotContain("obs-note")
                        .doesNotContain("alice");
            }
            // VAULT_EXPORTED записан и содержит только агрегаты.
            var exported = events.stream()
                    .filter(e -> "VAULT_EXPORTED".equals(e.getType()))
                    .findFirst().orElseThrow();
            String details = String.valueOf(exported.getDetailsJson());
            assertThat(details).contains("entryCount").contains("csvSha256").contains("bom");
        });
    }
}
