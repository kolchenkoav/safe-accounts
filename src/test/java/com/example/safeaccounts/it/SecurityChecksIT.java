package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.config.AdminBootstrap;
import com.example.safeaccounts.domain.AuthToken;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.AuthTokenRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Task-10: проверки безопасности (раздел «Проверки безопасности»).
 * <p>
 * Подтверждается, что:
 * <ul>
 *   <li>в БД нет plaintext-секретов (vault_entries, users, auth_tokens);</li>
 *   <li>отозванный токен не работает;</li>
 *   <li>роль USER не имеет доступа к /api/admin/**;</li>
 *   <li>ошибки авторизации не раскрывают лишнего (RFC 7807, без стектрейсов);</li>
 *   <li>попытка получить чужую запись не приводит к утечке данных.</li>
 * </ul>
 * PostgreSQL — Testcontainers, секреты синтетические (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class SecurityChecksIT {

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
    UserRepository userRepository;
    @Autowired
    AuthTokenRepository authTokenRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    TransactionTemplate transactionTemplate;
    @Autowired
    AdminBootstrap adminBootstrap;

    private static final String PASSWORD = "Str0ng-Sec-Pass1!";
    private static final String ENTRY_PASSWORD = "Sec-Entry-Pass!";

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            vaultEntryRepository.deleteAll();
            authTokenRepository.deleteAll();
            userRepository.deleteAll();
        });
    }

    // -- helpers --------------------------------------------------------------

    private String registerAndLogin(String username) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(username, PASSWORD))))
                .andExpect(status().isCreated());
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    private UUID createEntry(String token, String site, String login,
                             String password, String notes) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest(site, login, password, notes))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(
                objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText());
    }

    // -- 1. vault_entries: нет plaintext ---------------------------------------

    @Test
    void vaultEntriesTableHasNoPlaintextValues() throws Exception {
        String token = registerAndLogin("sec-vault");
        UUID id = createEntry(token, "https://secret-site.example.com", "secret-login",
                ENTRY_PASSWORD, "secret-note");

        transactionTemplate.executeWithoutResult(status -> {
            VaultEntry entry = vaultEntryRepository.findById(id).orElseThrow();

            // В шифротекстах нет ни сайта, ни логина, ни пароля, ни примечания
            assertThat(entry.getSiteEnc())
                    .isNotBlank()
                    .doesNotContain("secret-site")
                    .doesNotContain("example.com");
            assertThat(entry.getLoginEnc())
                    .isNotBlank()
                    .doesNotContain("secret-login");
            assertThat(entry.getPasswordEnc())
                    .isNotBlank()
                    .doesNotContain(ENTRY_PASSWORD)
                    .doesNotContain("Sec-Entry");
            assertThat(entry.getNotesEnc())
                    .isNotBlank()
                    .doesNotContain("secret-note");

            // Все поля — валидный base64 (AES-256-GCM сохраняется как base64)
            assertThat(entry.getSiteEnc()).matches("[A-Za-z0-9+/=]+");
            assertThat(entry.getLoginEnc()).matches("[A-Za-z0-9+/=]+");
            assertThat(entry.getPasswordEnc()).matches("[A-Za-z0-9+/=]+");
            assertThat(entry.getNotesEnc()).matches("[A-Za-z0-9+/=]+");
        });
    }

    // -- 2. users: нет открытых паролей и DEK -----------------------------------

    @Test
    void usersTableHasNoPlaintextPasswordOrDek() throws Exception {
        registerAndLogin("sec-user");

        transactionTemplate.executeWithoutResult(status -> {
            List<User> users = userRepository.findAll();
            assertThat(users).hasSize(1);
            User user = users.get(0);

            // Пароль — только Argon2id-хэш, plaintext отсутствует
            assertThat(user.getPasswordHash()).startsWith("$argon2id$");
            assertThat(user.getPasswordHash()).doesNotContain(PASSWORD);

            // DEK — только wrapped (base64 AES-GCM), не строковый plaintext
            assertThat(user.getDekWrapped()).isNotBlank();
            assertThat(user.getDekWrapped()).matches("[A-Za-z0-9+/=]+");
            // Wrapped DEK не может совпадать с IV и не содержит маркеров plaintext
            assertThat(user.getDekWrapped()).isNotEqualTo(user.getDekIv());
        });
    }

    // -- 3. auth_tokens: нет открытых токенов ------------------------------------

    @Test
    void authTokensTableHasNoRawTokens() throws Exception {
        String rawToken = registerAndLogin("sec-token");

        transactionTemplate.executeWithoutResult(status -> {
            List<AuthToken> tokens = authTokenRepository.findAll();
            assertThat(tokens).hasSize(1);
            AuthToken stored = tokens.get(0);

            // Сырой токен не хранится ни в одном поле
            assertThat(stored.getTokenHash()).doesNotContain(rawToken);
            assertThat(stored.getTokenHint()).doesNotContain(rawToken);
            assertThat(stored.getUserAgent()).isNull();
            assertThat(stored.getIpAddress()).isNotBlank();

            // Хэш есть и он не совпадает с сырым токеном (sat_...)
            assertThat(stored.getTokenHash()).isNotBlank();
            assertThat(stored.getTokenHash()).hasSize(64); // SHA-256 hex
        });
    }

    // -- 4. Отозванный токен не работает -----------------------------------------

    @Test
    void revokedTokenDoesNotWork() throws Exception {
        String token = registerAndLogin("sec-revoke");

        // Токен работает до отзыва
        mockMvc.perform(get("/api/vault").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Отзыв через logout
        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        // Токен больше не работает на защищенных эндпоинтах
        mockMvc.perform(get("/api/vault").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/vault/" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());

        // В БД токен помечен отозванным, сырой токен в БД не появился
        transactionTemplate.executeWithoutResult(status -> {
            List<AuthToken> tokens = authTokenRepository.findAll();
            assertThat(tokens).hasSize(1);
            assertThat(tokens.get(0).isRevoked()).isTrue();
            assertThat(tokens.get(0).getTokenHash()).doesNotContain(token);
        });
    }

    // -- 5. USER не имеет доступа к /api/admin/** ---------------------------------

    @Test
    void userRoleCannotAccessAdminEndpoints() throws Exception {
        String userToken = registerAndLogin("sec-plain-user");

        // Все административные эндпоинты закрыты для ROLE_USER
        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/audit").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/crypto/rewrap-deks")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        // Без аутентификации — 401, а не 403 (не раскрываем наличие эндпоинтов)
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    // -- 6-7. Ошибки авторизации не раскрывают лишнего ------------------------------

    @Test
    void authorizationErrorsDoNotLeakInformation() throws Exception {
        String ownerToken = registerAndLogin("sec-owner");
        String attackerToken = registerAndLogin("sec-attacker");
        UUID entryId = createEntry(ownerToken, "https://leak-test.example.com",
                "owner-login", ENTRY_PASSWORD, "owner-note");

        // Чужая запись: 404 без данных
        String body404 = mockMvc.perform(get("/api/vault/" + entryId)
                        .header("Authorization", "Bearer " + attackerToken))
                .andExpect(status().isNotFound())
                .andReturn().getResponse().getContentAsString();
        assertThat(body404)
                .doesNotContain(ENTRY_PASSWORD)
                .doesNotContain("owner-login")
                .doesNotContain("owner-note")
                .doesNotContain("leak-test");

        // Admin-эндпоинт: 403 без деталей и стектрейсов
        String body403 = mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + attackerToken))
                .andExpect(status().isForbidden())
                .andReturn().getResponse().getContentAsString();
        assertThat(body403).doesNotContain("at ").doesNotContain("Exception");

        // 401 без деталей
        String body401 = mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        assertThat(body401).isBlank();

        // Ошибка логина: RFC 7807, без стектрейсов и без утечки имени/пароля
        String body401Login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("sec-owner", "Wr0ng-Passw0rd!"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").isNotEmpty())
                .andExpect(jsonPath("$.detail").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        assertThat(body401Login)
                .doesNotContain("Wr0ng-Passw0rd!")
                .doesNotContain("at ")
                .doesNotContain("Exception");
    }

    // --VaultEntries: нет plaintext при обновлении и удалении (продвинутое) -------

    @Test
    void noPlaintextAfterUpdateAndAcrossMultipleEntries() throws Exception {
        String token = registerAndLogin("sec-multi");
        UUID id1 = createEntry(token, "https://one.example.com", "login-1",
                ENTRY_PASSWORD, "note-1");
        UUID id2 = createEntry(token, "https://two.example.com", "login-2",
                ENTRY_PASSWORD, "note-2");

        // Обновляем первую запись — в БД не должно остаться plaintext после UPDATE
        mockMvc.perform(put("/api/vault/" + id1)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new com.example.safeaccounts.api.VaultEntryUpdateRequest(
                                        "https://one-updated.example.com", "login-1-upd",
                                        "New-Sec-Pass-42!", "note-1-upd"))))
                .andExpect(status().isOk());

        transactionTemplate.executeWithoutResult(status -> {
            for (VaultEntry e : vaultEntryRepository.findAll()) {
                String blob = String.valueOf(e.getSiteEnc())
                        + String.valueOf(e.getLoginEnc())
                        + String.valueOf(e.getPasswordEnc())
                        + String.valueOf(e.getNotesEnc());
                // Ни старые, ни новые plaintext-значения не появляются в БД
                assertThat(blob)
                        .doesNotContain("one.example.com")
                        .doesNotContain("one-updated.example.com")
                        .doesNotContain("login-1-upd")
                        .doesNotContain(ENTRY_PASSWORD)
                        .doesNotContain("New-Sec-Pass-42!")
                        .doesNotContain("note-1-upd")
                        .doesNotContain("two.example.com")
                        .doesNotContain("login-2")
                        .doesNotContain("note-2");
            }
        });
    }

    // -- 5 (доп). Admin API работает для админа (не случайно сломан) ----------------

    @Test
    void adminEndpointsWorkForAdminRole() throws Exception {
        // Bootstrap-админ создается только на ПУСТОЙ БД — как в VaultApiIT.
        transactionTemplate.executeWithoutResult(status -> {
            try {
                adminBootstrap.run(null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        String adminToken = registerAndLogin("sec-admin-helper");
        // Логин под bootstrap-админом
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("bootstrap-admin", "B00tstrap-Admin-Pass!"))))
                .andExpect(status().isOk())
                .andReturn();
        String realAdminToken = objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();

        // Админ имеет доступ к админ-эндпоинтам
        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + realAdminToken))
                .andExpect(status().isOk());
        // Обычный пользователь не имеет
        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isForbidden());
    }
}
