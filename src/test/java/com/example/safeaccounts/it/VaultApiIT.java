package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.api.VaultEntryUpdateRequest;
import com.example.safeaccounts.repository.AuditEventRepository;
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

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты CRUD API сейфа (Task-05): полный CRUD-цикл,
 * изоляция пользователей, отсутствие пароля в списках, reveal только
 * владельцу и с аудитом, перешифрование при обновлении, plaintext
 * в БД отсутствует. PostgreSQL — Testcontainers; секреты синтетические,
 * только тестовый профиль (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class VaultApiIT {

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
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    AuditEventRepository auditEventRepository;
    @Autowired
    TransactionTemplate transactionTemplate;
    @Autowired
    com.example.safeaccounts.config.AdminBootstrap adminBootstrap;

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Entry-Pass-123!";

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
            vaultEntryRepository.deleteAll();
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

    // -- тесты ----------------------------------------------------------------

    @Test
    void fullCrudCycleWorks() throws Exception {
        String token = registerAndLogin("vault-crud");

        // create
        UUID id = createEntry(token, "https://example.com", "alice", ENTRY_PASSWORD, "note-1");

        // read (без reveal: пароль отсутствует)
        mockMvc.perform(get("/api/vault/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.site").value("https://example.com"))
                .andExpect(jsonPath("$.login").value("alice"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.notes").value("note-1"));

        // update
        mockMvc.perform(put("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryUpdateRequest("https://new.example.com", "bob", "New-Pass-456!", null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.site").value("https://new.example.com"))
                .andExpect(jsonPath("$.login").value("bob"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.notes").doesNotExist());

        // read с reveal: обновленный пароль возвращается
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value("New-Pass-456!"));

        // delete
        mockMvc.perform(delete("/api/vault/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/vault/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    @Test
    void listDoesNotContainPasswordsOrNotes() throws Exception {
        String token = registerAndLogin("vault-list");
        createEntry(token, "https://a.example.com", "alice", ENTRY_PASSWORD, "secret-note");
        createEntry(token, "https://b.example.com", "bob", ENTRY_PASSWORD, null);

        String body = mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(2))
                .andExpect(jsonPath("$.content.length()").value(2))
                .andReturn().getResponse().getContentAsString();

        // Пароли и примечания не должны встречаться нигде в ответе списка
        assertThat(body).doesNotContain(ENTRY_PASSWORD).doesNotContain("secret-note");
        assertThat(body).contains("https://a.example.com").contains("alice");
    }

    @Test
    void foreignEntryIsInaccessibleAndIndistinguishableFromMissing() throws Exception {
        String ownerToken = registerAndLogin("vault-owner");
        String attackerToken = registerAndLogin("vault-attacker");
        UUID entryId = createEntry(ownerToken, "https://private.example.com", "alice", ENTRY_PASSWORD, null);

        // Чужая запись: единый нейтральный 404 на все операции
        mockMvc.perform(get("/api/vault/" + entryId).header("Authorization", "Bearer " + attackerToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/api/vault/" + entryId + "?reveal=true")
                        .header("Authorization", "Bearer " + attackerToken))
                .andExpect(status().isNotFound());
        mockMvc.perform(put("/api/vault/" + entryId)
                        .header("Authorization", "Bearer " + attackerToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryUpdateRequest("https://evil.example.com", "x", "Evil-Pass-789!", null))))
                .andExpect(status().isNotFound());
        mockMvc.perform(delete("/api/vault/" + entryId).header("Authorization", "Bearer " + attackerToken))
                .andExpect(status().isNotFound());

        // Запись владельца не изменилась
        mockMvc.perform(get("/api/vault/" + entryId + "?reveal=true")
                        .header("Authorization", "Bearer " + ownerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.site").value("https://private.example.com"))
                .andExpect(jsonPath("$.password").value(ENTRY_PASSWORD));
    }

    @Test
    void databaseStoresOnlyCiphertexts() throws Exception {
        String token = registerAndLogin("vault-cipher");
        UUID id = createEntry(token, "https://example.com", "alice", ENTRY_PASSWORD, "plain-note");

        transactionTemplate.executeWithoutResult(status -> {
            var entry = vaultEntryRepository.findById(id).orElseThrow();
            assertThat(entry.getSiteEnc()).doesNotContain("example.com");
            assertThat(entry.getLoginEnc()).doesNotContain("alice");
            assertThat(entry.getPasswordEnc()).doesNotContain(ENTRY_PASSWORD);
            assertThat(entry.getNotesEnc()).doesNotContain("plain-note");
            // Шифротекст не пуст и не совпадает между двумя записями (случайный IV)
        });
    }

    @Test
    void twoEntriesHaveDifferentCiphertextsForSamePassword() throws Exception {
        String token = registerAndLogin("vault-iv");
        UUID id1 = createEntry(token, "https://x.example.com", "l1", ENTRY_PASSWORD, null);
        UUID id2 = createEntry(token, "https://y.example.com", "l2", ENTRY_PASSWORD, null);

        transactionTemplate.executeWithoutResult(status -> {
            var e1 = vaultEntryRepository.findById(id1).orElseThrow();
            var e2 = vaultEntryRepository.findById(id2).orElseThrow();
            // Одинаковый plaintext, разный случайный IV => разные шифротексты
            assertThat(e1.getPasswordEnc()).isNotEqualTo(e2.getPasswordEnc());
        });
    }

    @Test
    void updateReencryptsInDatabase() throws Exception {
        String token = registerAndLogin("vault-reenc");
        UUID id = createEntry(token, "https://example.com", "alice", ENTRY_PASSWORD, null);
        String encBefore = transactionTemplate.execute(s ->
                vaultEntryRepository.findById(id).orElseThrow().getPasswordEnc());

        mockMvc.perform(put("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryUpdateRequest("https://example.com", "alice", "New-Pass-789!", null))))
                .andExpect(status().isOk());

        transactionTemplate.executeWithoutResult(status -> {
            var entry = vaultEntryRepository.findById(id).orElseThrow();
            assertThat(entry.getPasswordEnc()).isNotEqualTo(encBefore);
            assertThat(entry.getPasswordEnc()).doesNotContain("New-Pass-789!");
        });
    }

    @Test
    void validationRejectsInvalidPayloads() throws Exception {
        String token = registerAndLogin("vault-valid");

        // Пустой site
        mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest(" ", "login", ENTRY_PASSWORD, null))))
                .andExpect(status().isBadRequest());
        // Превышение длины пароля
        mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest("site", "login", "p".repeat(4097), null))))
                .andExpect(status().isBadRequest());
        // Некорректный JSON
        mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest());
        // Несуществующая запись
        mockMvc.perform(get("/api/vault/" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());
    }

    @Test
    void vaultRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/vault")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/vault")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest("s", "l", "p", null))))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void vaultEventsAreAuditedWithoutSecrets() throws Exception {
        String token = registerAndLogin("vault-audit");
        UUID id = createEntry(token, "https://example.com", "alice", ENTRY_PASSWORD, "top-secret-note");

        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mockMvc.perform(put("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryUpdateRequest("https://example.com", "alice2", ENTRY_PASSWORD, null))))
                .andExpect(status().isOk());
        mockMvc.perform(delete("/api/vault/" + id).header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(
                    userRepository.findByUsername("vault-audit").orElseThrow().getId());
            var types = events.stream().map(e -> e.getType()).toList();
            assertThat(types).contains(
                    "SECRET_CREATED", "SECRET_REVEALED", "SECRET_UPDATED", "SECRET_DELETED");
            // Ни одно событие не содержит расшифрованных секретов
            for (var event : events) {
                String blob = String.valueOf(event.getDetailsJson()) + event.getObjectId()
                        + event.getObjectType() + event.getType();
                assertThat(blob).doesNotContain(ENTRY_PASSWORD)
                        .doesNotContain("top-secret-note")
                        .doesNotContain("alice");
                if (event.getType().startsWith("SECRET_")) {
                    assertThat(event.getObjectType()).isEqualTo("VaultEntry");
                    assertThat(event.getObjectId()).isEqualTo(id.toString());
                }
            }
        });
    }

    @Test
    void adminHasNoImplicitAccessToForeignEntries() throws Exception {
        // Bootstrap-админ создается только на ПУСТОЙ БД (hasAnyUsers), поэтому
        // сначала админ, потом обычный пользователь.
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("vault-user");
        UUID entryId = createEntry(userToken, "https://example.com", "alice", ENTRY_PASSWORD, null);

        mockMvc.perform(get("/api/vault/" + entryId).header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    private String loginAdmin() throws Exception {
        // Bootstrap-админ создается ApplicationRunner'ом только на пустой БД;
        // cleanDatabase() в BeforeEach ее очищает, поэтому создаем вручную.
        transactionTemplate.executeWithoutResult(status ->
                adminBootstrap.run(null));
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("bootstrap-admin", "B00tstrap-Admin-Pass!"))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    @Test
    void listPaginationAndSortingWorks() throws Exception {
        String token = registerAndLogin("vault-page");
        createEntry(token, "https://1.example.com", "l1", ENTRY_PASSWORD, null);
        createEntry(token, "https://2.example.com", "l2", ENTRY_PASSWORD, null);
        createEntry(token, "https://3.example.com", "l3", ENTRY_PASSWORD, null);

        mockMvc.perform(get("/api/vault?page=0&size=2")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(2))
                .andExpect(jsonPath("$.totalElements").value(3))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.content[0].site").value("https://1.example.com"))
                .andExpect(jsonPath("$.content[1].site").value("https://2.example.com"));
    }
}
