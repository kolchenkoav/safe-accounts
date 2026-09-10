package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.api.VaultEntryUpdateRequest;
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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Task-10: сквозной e2e-сценарий (раздел «Обязательные сценарии e2e»).
 * Полный жизненный цикл: регистрация -> логин -> CRUD записи сейфа ->
 * проверка изоляции от второго пользователя. PostgreSQL — Testcontainers,
 * секреты синтетические, только тестовый профиль (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class E2eFlowIT {

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

    private static final String PASSWORD = "Str0ng-E2e-Pass1!";
    private static final String ENTRY_PASSWORD = "E2e-Entry-Pass!";

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
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
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

    // -- обязательный e2e-сценарий (шаги 1-7) ----------------------------------

    @Test
    void e2eCreateReadListRevealUpdateDelete() throws Exception {
        // 1-2. Создать пользователя и выполнить логин
        String token = registerAndLogin("e2e-user");
        assertThat(token).startsWith("sat_");

        // 3. Создать запись сейфа
        UUID id = createEntry(token, "https://e2e.example.com", "e2e-login",
                ENTRY_PASSWORD, "e2e-note");

        // 4. Получить список записей (без пароля)
        String listBody = mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andReturn().getResponse().getContentAsString();
        assertThat(listBody)
                .doesNotContain(ENTRY_PASSWORD)
                .doesNotContain("e2e-note")
                .contains("https://e2e.example.com");

        // 5. Получить детальную запись с reveal=true (пароль раскрывается)
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.site").value("https://e2e.example.com"))
                .andExpect(jsonPath("$.login").value("e2e-login"))
                .andExpect(jsonPath("$.password").value(ENTRY_PASSWORD))
                .andExpect(jsonPath("$.notes").value("e2e-note"));

        // 6. Обновить запись
        mockMvc.perform(put("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VaultEntryUpdateRequest(
                                "https://e2e-updated.example.com", "e2e-login-2",
                                "E2e-New-Pass-42!", "e2e-note-2"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.site").value("https://e2e-updated.example.com"))
                .andExpect(jsonPath("$.password").doesNotExist());

        // 7. Удалить запись
        mockMvc.perform(delete("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    // -- шаг 8: изоляция второго пользователя ----------------------------------

    @Test
    void secondUserHasNoAccessToFirstUsersEntries() throws Exception {
        String ownerToken = registerAndLogin("e2e-owner");
        UUID id = createEntry(ownerToken, "https://private-e2e.example.com",
                "owner-login", ENTRY_PASSWORD, "owner-note");

        String otherToken = registerAndLogin("e2e-stranger");

        // Чтение списка: чужих записей не видно вообще
        mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));

        // Чтение/детали/reveal/update/delete чужой записи — нейтральный 404
        mockMvc.perform(get("/api/vault/" + id)
                        .header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/api/vault/" + id)
                        .header("Authorization", "Bearer " + otherToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new VaultEntryUpdateRequest(
                                "https://attacker.example.com", "attacker", "Attacker-Pass-9!", null))))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete("/api/vault/" + id)
                        .header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isNotFound());

        // Ответ 404 не раскрывает данные чужой записи
        String notFoundBody = mockMvc.perform(get("/api/vault/" + id)
                        .header("Authorization", "Bearer " + otherToken))
                .andExpect(status().isNotFound())
                .andReturn().getResponse().getContentAsString();
        assertThat(notFoundBody)
                .doesNotContain(ENTRY_PASSWORD)
                .doesNotContain("owner-login")
                .doesNotContain("owner-note")
                .doesNotContain("https://private-e2e.example.com");

        // Данные владельца не изменились
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + ownerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.site").value("https://private-e2e.example.com"))
                .andExpect(jsonPath("$.password").value(ENTRY_PASSWORD))
                .andExpect(jsonPath("$.notes").value("owner-note"));
    }

    // -- изоляция токенов и параллельные сессии --------------------------------

    @Test
    void tokensAreBoundToTheirOwnUserOnly() throws Exception {
        String tokenA = registerAndLogin("e2e-token-a");
        String tokenB = registerAndLogin("e2e-token-b");

        UUID idA = createEntry(tokenA, "https://a.example.com", "la", ENTRY_PASSWORD, null);
        UUID idB = createEntry(tokenB, "https://b.example.com", "lb", ENTRY_PASSWORD, null);

        // Токен A видит только свою запись, токен B — только свою
        String listA = mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(listA).contains("https://a.example.com").doesNotContain("https://b.example.com");

        String listB = mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(listB).contains("https://b.example.com").doesNotContain("https://a.example.com");

        // Кросс-доступ к деталям запрещен
        mockMvc.perform(get("/api/vault/" + idA).header("Authorization", "Bearer " + tokenB))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/vault/" + idB).header("Authorization", "Bearer " + tokenA))
                .andExpect(status().isNotFound());
    }
}
