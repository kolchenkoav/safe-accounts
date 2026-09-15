package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты API тегов (Task-08, Фаза 5):
 * CRUD тегов, валидация имени (regex), дубликаты (409), удаление при
 * наличии ссылок (409), GET/PUT/DELETE на тегах записи, owner-check.
 * PostgreSQL — Testcontainers.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class TagApiIT {

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
    TagRepository tagRepository;
    @Autowired
    AuditEventRepository auditEventRepository;
    @Autowired
    TransactionTemplate transactionTemplate;

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Entry-Pass-123!";

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
            tagRepository.deleteAll();
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

    private UUID createEntry(String token, String name, String site, String login,
                             String password, String notes) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest(name, site, login, password, notes))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(
                objectMapper.readTree(result.getResponse().getContentAsString()).get("id").asText());
    }

    private static ObjectNode body(ObjectMapper mapper, String name) {
        ObjectNode node = mapper.createObjectNode();
        node.put("name", name);
        return node;
    }

    private static ObjectNode bodyTags(ObjectMapper mapper, String... names) {
        ObjectNode node = mapper.createObjectNode();
        var arr = node.putArray("tags");
        for (String n : names) {
            arr.add(n);
        }
        return node;
    }

    // -- CRUD тегов пользователя ---------------------------------------------

    @Test
    void getTagsReturnsEmptyListForNewUser() throws Exception {
        String token = registerAndLogin("tags-empty");
        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void createTagReturns201AndShowsInList() throws Exception {
        String token = registerAndLogin("tags-create");

        MvcResult created = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "Work"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Work"))
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.createdAt").isNotEmpty())
                .andReturn();

        UUID tagId = UUID.fromString(
                objectMapper.readTree(created.getResponse().getContentAsString())
                        .get("id").asText());

        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(tagId.toString()))
                .andExpect(jsonPath("$[0].name").value("Work"));

        // Никаких секретов в аудите
        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(
                    userRepository.findByUsername("tags-create").orElseThrow().getId());
            assertThat(events.stream().map(e -> e.getType())).contains("TAG_CREATED");
        });
    }

    @Test
    void createTagRejectsInvalidNameRegex() throws Exception {
        String token = registerAndLogin("tags-invalid");

        // Пробел в начале допустим (после trim всё хорошо), но запрещённые символы — нет.
        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "bad/name"))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.type").value("about:blank"));

        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, ""))))
                .andExpect(status().isBadRequest());

        // Превышение длины
        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper,
                                "x".repeat(65)))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createTagRejectsDuplicateCaseInsensitive() throws Exception {
        String token = registerAndLogin("tags-dup");
        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "Work"))))
                .andExpect(status().isCreated());
        // Тот же тег в другом регистре
        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "WORK"))))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void patchTagRenamesAndUpdatesNameLower() throws Exception {
        String token = registerAndLogin("tags-rename");
        MvcResult created = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "Old-Name"))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID tagId = UUID.fromString(
                objectMapper.readTree(created.getResponse().getContentAsString()).get("id").asText());

        mockMvc.perform(patch("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "New-Name"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("New-Name"))
                .andExpect(jsonPath("$.id").value(tagId.toString()));

        // name_lower обновился — можно создать «Old-Name» заново (т.к. name_lower другой)
        mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "Old-Name"))))
                .andExpect(status().isCreated());
    }

    @Test
    void deleteTagReturns204AndRemovesFromList() throws Exception {
        String token = registerAndLogin("tags-delete");
        MvcResult created = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "Trash"))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID tagId = UUID.fromString(
                objectMapper.readTree(created.getResponse().getContentAsString()).get("id").asText());

        mockMvc.perform(delete("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void deleteTagWithReferencesReturns409() throws Exception {
        String token = registerAndLogin("tags-ref");
        UUID entryId = createEntry(token, "RefEntry", "https://ref.example.com",
                "alice", ENTRY_PASSWORD, null);

        // Создаём тег и привязываем к записи
        MvcResult created = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "RefTag"))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID tagId = UUID.fromString(
                objectMapper.readTree(created.getResponse().getContentAsString()).get("id").asText());

        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyTags(objectMapper, "RefTag"))))
                .andExpect(status().isOk());

        // Удаление — 409 (план, раздел 5 п.1)
        mockMvc.perform(delete("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.status").value(409));
    }

    @Test
    void deleteForeignTagReturns404() throws Exception {
        String owner = registerAndLogin("tags-owner");
        String other = registerAndLogin("tags-other");
        MvcResult created = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + owner)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "OwnerTag"))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID tagId = UUID.fromString(
                objectMapper.readTree(created.getResponse().getContentAsString()).get("id").asText());

        // Чужой пользователь видит только свои теги
        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + other))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        // DELETE чужого тега — нейтральный 404
        mockMvc.perform(delete("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + other))
                .andExpect(status().isNotFound());

        // PATCH чужого тега — нейтральный 404
        mockMvc.perform(patch("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + other)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "x"))))
                .andExpect(status().isNotFound());

        // Тег владельца не изменился
        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + owner))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].name").value("OwnerTag"));
    }

    // -- теги записи ---------------------------------------------------------

    @Test
    void getEntryTagsReturnsList() throws Exception {
        String token = registerAndLogin("tags-entry-get");
        UUID entryId = createEntry(token, "E", "https://e.example.com", "l", ENTRY_PASSWORD, null);

        mockMvc.perform(get("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void putEntryTagsReplacesAllAndCreatesNew() throws Exception {
        String token = registerAndLogin("tags-entry-put");
        UUID entryId = createEntry(token, "E", "https://e.example.com", "l", ENTRY_PASSWORD, null);

        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                bodyTags(objectMapper, "work", "personal"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));

        mockMvc.perform(get("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));

        // Теги создались и видны в /api/tags
        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(2));

        // Пустой список — снимает все теги
        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyTags(objectMapper))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    void putEntryTagsRejectsInvalidName() throws Exception {
        String token = registerAndLogin("tags-entry-invalid");
        UUID entryId = createEntry(token, "E", "https://e.example.com", "l", ENTRY_PASSWORD, null);

        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                bodyTags(objectMapper, "bad/name"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void deleteEntryTagReturns204AndUnlinks() throws Exception {
        String token = registerAndLogin("tags-entry-del");
        UUID entryId = createEntry(token, "E", "https://e.example.com", "l", ENTRY_PASSWORD, null);

        MvcResult t1 = mockMvc.perform(post("/api/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(body(objectMapper, "RemMe"))))
                .andExpect(status().isCreated())
                .andReturn();
        UUID tagId = UUID.fromString(
                objectMapper.readTree(t1.getResponse().getContentAsString()).get("id").asText());

        // Привязываем
        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyTags(objectMapper, "RemMe"))))
                .andExpect(status().isOk());

        // Снимаем один тег
        mockMvc.perform(delete("/api/vault/" + entryId + "/tags/" + tagId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        // Теперь тег можно удалить (нет ссылок)
        mockMvc.perform(delete("/api/tags/" + tagId)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
    }

    @Test
    void foreignEntryTagsReturns404() throws Exception {
        String owner = registerAndLogin("tags-entry-owner");
        String other = registerAndLogin("tags-entry-stranger");
        UUID entryId = createEntry(owner, "OE", "https://oe.example.com", "l", ENTRY_PASSWORD, null);

        mockMvc.perform(get("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + other))
                .andExpect(status().isNotFound());

        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + other)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyTags(objectMapper, "x"))))
                .andExpect(status().isNotFound());

        UUID someTag = UUID.randomUUID();
        mockMvc.perform(delete("/api/vault/" + entryId + "/tags/" + someTag)
                        .header("Authorization", "Bearer " + other))
                .andExpect(status().isNotFound());
    }

    @Test
    void tagsEndpointsRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/tags")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/tags")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"x\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/vault/" + UUID.randomUUID() + "/tags"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void entryTagsReplacementIsAudited() throws Exception {
        String token = registerAndLogin("tags-audit");
        UUID entryId = createEntry(token, "E", "https://e.example.com", "l", ENTRY_PASSWORD, null);

        mockMvc.perform(put("/api/vault/" + entryId + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(bodyTags(objectMapper, "a", "b"))))
                .andExpect(status().isOk());

        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(
                    userRepository.findByUsername("tags-audit").orElseThrow().getId());
            assertThat(events.stream().map(e -> e.getType()))
                    .contains("ENTRY_TAGS_REPLACED", "TAG_CREATED");
            // AGENTS.md: списки тегов в detailsJson запрещены — пишется только tagCount.
            var replaced = events.stream()
                    .filter(e -> "ENTRY_TAGS_REPLACED".equals(e.getType()))
                    .findFirst().orElseThrow();
            assertThat(replaced.getDetailsJson()).containsAnyOf("\"tagCount\":2", "\"tagCount\": 2");
            assertThat(replaced.getDetailsJson()).doesNotContain("\"a\"").doesNotContain("\"b\"");
        });
    }
}
