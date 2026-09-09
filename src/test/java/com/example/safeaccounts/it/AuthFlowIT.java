package com.example.safeaccounts.it;

import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.config.AdminBootstrap;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.anonymous;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты Task-04: регистрация, логин, Bearer-токены,
 * отзыв токенов, аудит, изоляция пользователей, bootstrap админа.
 * PostgreSQL поднимается через Testcontainers; учетные данные — синтетические
 * тестовые значения только в тестовом профиле (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class AuthFlowIT {

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
    AuditEventRepository auditEventRepository;
    @Autowired
    TransactionTemplate transactionTemplate;
    @Autowired
    AdminBootstrap adminBootstrap;

    private static final String PASSWORD = "Str0ng-Passw0rd!";

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
            userRepository.deleteAll();
        });
    }

    // -- helpers --------------------------------------------------------------

    private String registerAndLogin(String username) throws Exception {
        register(username, PASSWORD);
        return loginAndGetToken(username, PASSWORD);
    }

    private void register(String username, String password) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(username, password))))
                .andExpect(status().isCreated());
    }

    private String loginAndGetToken(String username, String password) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("accessToken").asText();
    }

    // -- тесты ----------------------------------------------------------------

    @Test
    void successfulLoginReturnsToken() throws Exception {
        register("login-ok", PASSWORD);
        String token = loginAndGetToken("login-ok", PASSWORD);

        assertThat(token).startsWith("sat_");
        // Токен дает доступ к /api/me
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("login-ok"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"));
    }

    @Test
    void wrongPasswordReturnsProblemDetail() throws Exception {
        register("login-bad", PASSWORD);

        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("login-bad", "Wr0ng-Passw0rd!"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.type").isNotEmpty())
                .andExpect(jsonPath("$.detail").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        // RFC 7807: без стектрейсов и без утечки деталей.
        assertThat(body).doesNotContain("at ");
        assertThat(body).doesNotContain("Exception");
    }

    @Test
    void loginOfUnknownUserIsIndistinguishableFromWrongPassword() throws Exception {
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("ghost-user", "Wr0ng-Passw0rd!"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid username or password"));
    }

    @Test
    void lockedUserCannotLoginAfterFiveFailures() throws Exception {
        register("locked-user", PASSWORD);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(new LoginRequest("locked-user", "Wr0ng-Passw0rd!"))))
                    .andExpect(status().isUnauthorized());
        }

        // 6-я попытка — с ПРАВИЛЬНЫМ паролем: аккаунт уже заблокирован.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("locked-user", PASSWORD))))
                .andExpect(status().isLocked())
                .andExpect(jsonPath("$.detail").value(
                        "Account is temporarily locked due to failed login attempts"));
    }

    @Test
    void tokenGrantsAccessToProtectedEndpoints() throws Exception {
        String token = registerAndLogin("bearer-user");

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Без токена — 401
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
        // С невалидным токеном — 401
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer sat_totally-invalid-token"))
                .andExpect(status().isUnauthorized());
        // С мусорным заголовком — 401
        mockMvc.perform(get("/api/me").header("Authorization", "Basic dXNlcjpwYXNz"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void revokedTokenIsRejectedAndReIssueWorks() throws Exception {
        String token = registerAndLogin("revoke-user");

        // Logout отзывает токен
        mockMvc.perform(post("/api/auth/logout").header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        // Отозванный токен больше не работает
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());

        // Re-issue: повторный логин выдает НОВЫЙ рабочий токен
        String newToken = loginAndGetToken("revoke-user", PASSWORD);
        assertThat(newToken).isNotEqualTo(token);
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + newToken))
                .andExpect(status().isOk());
    }

    @Test
    void userIsolationOnMeAndTokens() throws Exception {
        String tokenA = registerAndLogin("iso-alice");
        registerAndLogin("iso-bob");

        // Токен Alice дает доступ только к её данным
        String meBody = mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // /api/me возвращает данные ровно того пользователя, которому выдан токен:
        // чужой токен не дает доступ к чужим данным (token -> user связка в БД).
        assertThat(objectMapper.readTree(meBody).get("username").asText())
                .isEqualTo("iso-alice");

        // Bob под своим токеном видит только свои данные, а не данные Alice
        String tokenB = loginAndGetToken("iso-bob", PASSWORD);
        String meBob = mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(objectMapper.readTree(meBob).get("username").asText())
                .isEqualTo("iso-bob");
    }

    @Test
    void creatingUserStoresWrappedDekAndAudit() throws Exception {
        register("dek-user", PASSWORD);

        User user = transactionTemplate.execute(s ->
                userRepository.findByUsername("dek-user")).orElseThrow();

        assertThat(user.getDekWrapped()).isNotBlank();
        assertThat(user.getDekIv()).isNotBlank();
        assertThat(user.getDekKekId()).isEqualTo("primary");
        assertThat(user.getPasswordHash()).startsWith("$argon2id$");
        assertThat(user.getUsername()).isEqualTo("dek-user"); // нижний регистр

        // Аудит USER_CREATED записан
        long created = auditEventRepository.findAll().stream()
                .filter(e -> "USER_CREATED".equals(e.getType()))
                .count();
        assertThat(created).isGreaterThanOrEqualTo(1);
    }

    @Test
    void auditWritesLoginSuccessAndFailure() throws Exception {
        register("audit-user", PASSWORD);
        loginAndGetToken("audit-user", PASSWORD);

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("audit-user", "Wr0ng-Passw0rd!"))))
                .andExpect(status().isUnauthorized());

        List<String> types = auditEventRepository.findAll().stream()
                .map(e -> e.getType()).toList();
        assertThat(types).contains("LOGIN_SUCCESS", "LOGIN_FAILURE", "TOKEN_ISSUED");
    }

    @Test
    void passwordChangeRevokesOtherTokensButKeepsCurrent() throws Exception {
        String tokenA = registerAndLogin("pwd-user");
        String tokenB = loginAndGetToken("pwd-user", PASSWORD);

        String changeBody = mockMvc.perform(post("/api/me/password")
                        .header("Authorization", "Bearer " + tokenA)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new com.example.safeaccounts.api.ChangePasswordRequest(PASSWORD, "N3w-Str0ng-Pass!"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        // Смена пароля прошла: хотя бы один другой токен отозван
        int revoked = objectMapper.readTree(changeBody).get("revokedTokens").asInt();
        assertThat(revoked).isGreaterThanOrEqualTo(1);

        // Старые токены отозваны, текущий — работает
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isOk());

        // Логин по старому паролю больше невозможен, по новому — возможен
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest("pwd-user", PASSWORD))))
                .andExpect(status().isUnauthorized());
        String newToken = loginAndGetToken("pwd-user", "N3w-Str0ng-Pass!");
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + newToken))
                .andExpect(status().isOk());
    }

    @Test
    void bootstrapCreatesAdminOnlyOnEmptyDatabase() {
        // БД пустая (cleanDatabase): bootstrap должен создать админа
        transactionTemplate.executeWithoutResult(status -> {
            try {
                adminBootstrap.run(null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

        User admin = userRepository.findByUsername("bootstrap-admin").orElseThrow();
        assertThat(admin.getRole()).isEqualTo("ROLE_ADMIN");
        assertThat(admin.isEnabled()).isTrue();
        assertThat(admin.getDekWrapped()).isNotBlank();

        // Повторный запуск НЕ перезаписывает администратора
        String originalHash = admin.getPasswordHash();
        transactionTemplate.executeWithoutResult(status -> {
            try {
                adminBootstrap.run(null);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        User again = userRepository.findByUsername("bootstrap-admin").orElseThrow();
        assertThat(again.getPasswordHash()).isEqualTo(originalHash);
    }

    @Test
    @WithMockUser(username = "springsec", roles = "USER")
    void springSecurityIntegrationSmoke() throws Exception {
        // Проверка интеграции с Spring Security test (WithMockUser + MockMvc).
        mockMvc.perform(get("/api/me").with(anonymous()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void registerValidationRejectsShortPasswordAndBadUsername() throws Exception {
        // Пароль < 12 символов
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("val-user", "short"))))
                .andExpect(status().isBadRequest());

        // Плохой формат имени
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("bad name!", PASSWORD))))
                .andExpect(status().isBadRequest());

        // Дубликат имени
        register("dup-check", PASSWORD);
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest("dup-check", PASSWORD))))
                .andExpect(status().isConflict());
    }
}
