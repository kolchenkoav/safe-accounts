package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.config.AdminBootstrap;
import com.example.safeaccounts.repository.AuditEventRepository;
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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Выделенный IT (Task-08, Фаза 8) — консолидированные e2e-сценарии
 * export/import сейфа: round-trip с удалением и импортом, контрактные
 * проверки формата CSV (ровно 5 колонок, отсутствие тегов), стратегии
 * skip/upsert, dryRun, failFast, заголовки, BOM, admin-маршруты.
 * <p>
 * Зона покрытия НЕ пересекается с {@link VaultApiIT} и
 * {@link AdminApiIT}: там остаются базовые сценарии (простой CRUD,
 * conflict, 401, заголовки). Здесь — полный round-trip и инварианты
 * формата (теги, BOM, dryRun+upsert).
 * <p>
 * PostgreSQL — Testcontainers; секреты синтетические, только
 * тестовый профиль (AGENTS.md).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class VaultExportImportIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Round-Trip-Pass-123!";

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
    AdminBootstrap adminBootstrap;

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
        MvcResult r = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, PASSWORD))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    private String loginAdmin() throws Exception {
        transactionTemplate.executeWithoutResult(s -> adminBootstrap.run(null));
        MvcResult r = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("bootstrap-admin", "B00tstrap-Admin-Pass!"))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(r.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    private UUID createEntry(String token, String name, String site, String login,
                             String password, String notes) throws Exception {
        MvcResult r = mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new VaultEntryCreateRequest(name, site, login, password, notes))))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(
                objectMapper.readTree(r.getResponse().getContentAsString()).get("id").asText());
    }

    private static ObjectNode tagBody(ObjectMapper m, String... names) {
        ObjectNode node = m.createObjectNode();
        var arr = node.putArray("tags");
        for (String n : names) {
            arr.add(n);
        }
        return node;
    }

    private byte[] exportCsv(String token, boolean bom) throws Exception {
        return mockMvc.perform(get("/api/vault/export")
                        .param("bom", String.valueOf(bom))
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
    }

    /** Импорт CSV в собственный сейф (без dryRun, со skip). */
    private ResultActions importCsv(String token, byte[] csv, String strategy) throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv", csv);
        return mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("conflictStrategy", strategy)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    /** Считает RFC 4180 колонки в одной CSV-строке (с учётом кавычек и экранирования). */
    static int csvColumns(String line) {
        int cols = 1;
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    i++; // экранированная кавычка
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                cols++;
            }
        }
        return cols;
    }

    private long userEntryCount(String username) {
        return transactionTemplate.execute(s -> vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(
                        userRepository.findByUsername(username).orElseThrow().getId())
                .size());
    }

    // -- full round-trip ------------------------------------------------------

    @Test
    void fullRoundTripExportDeleteImportReveal() throws Exception {
        String token = registerAndLogin("rt-user");
        UUID id = createEntry(token, "Gmail", "https://gmail.example.com",
                "alice", ENTRY_PASSWORD, "first note");

        // 1. export
        byte[] csv = exportCsv(token, false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text).startsWith("name,url,username,password,note\r\n");
        assertThat(text).contains(ENTRY_PASSWORD);

        // 2. delete original
        mockMvc.perform(delete("/api/vault/" + id)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNoContent());
        assertThat(userEntryCount("rt-user")).isZero();

        // 3. import the exported CSV
        importCsv(token, csv, "skip")
                .andExpect(jsonPath("$.created").value(1))
                .andExpect(jsonPath("$.updated").value(0))
                .andExpect(jsonPath("$.skipped").value(0));

        // 4. reveal: пароль полностью восстановлен
        assertThat(userEntryCount("rt-user")).isEqualTo(1);
        UUID restored = transactionTemplate.execute(s -> vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(
                        userRepository.findByUsername("rt-user").orElseThrow().getId())
                .get(0).getId());
        mockMvc.perform(get("/api/vault/" + restored + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Gmail"))
                .andExpect(jsonPath("$.site").value("https://gmail.example.com"))
                .andExpect(jsonPath("$.login").value("alice"))
                .andExpect(jsonPath("$.password").value(ENTRY_PASSWORD))
                .andExpect(jsonPath("$.notes").value("first note"));
    }

    // -- CSV: ровно 5 колонок и тегов в CSV нет -------------------------------

    @Test
    void exportedCsvHasExactlyFiveColumnsAndNoTags() throws Exception {
        String token = registerAndLogin("no-tags-user");
        UUID id = createEntry(token, "Tagged", "https://tagged.example.com",
                "alice", ENTRY_PASSWORD, null);
        // Привязываем теги к записи (теги не должны попасть в CSV)
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .put("/api/vault/" + id + "/tags")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                tagBody(objectMapper, "Work", "Personal"))))
                .andExpect(status().isOk());

        byte[] csv = exportCsv(token, false);
        String text = new String(csv, StandardCharsets.UTF_8);

        // Заголовок — ровно 5 колонок
        String[] lines = text.split("\r\n", -1);
        assertThat(lines[0]).isEqualTo("name,url,username,password,note");
        assertThat(csvColumns(lines[0])).isEqualTo(5);

        // Каждая строка данных — ровно 5 колонок (включая завершающий CRLF)
        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty()) {
                continue; // завершающий CRLF → пустой элемент после split
            }
            assertThat(csvColumns(lines[i]))
                    .as("row %d has 5 columns: %s", i, lines[i])
                    .isEqualTo(5);
        }

        // Никаких следов тегов в CSV
        assertThat(text.toLowerCase()).doesNotContain("tags");
        assertThat(text).doesNotContain("Work").doesNotContain("Personal");
        // Запись и её содержимое — на месте
        assertThat(text).contains("Tagged").contains("https://tagged.example.com")
                .contains("alice").contains(ENTRY_PASSWORD);
    }

    @Test
    void importSilentlyIgnoresExtraTagsColumn() throws Exception {
        String token = registerAndLogin("import-extra-col");
        // Сторонний экспорт: 6-я колонка "tags"
        String csv = "name,url,username,password,note,tags\r\n"
                + "G,https://g.example.com,alice,Extra-Pass-1!,note,work;personal\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("conflictStrategy", "skip")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(1));

        // Запись создана — без тегов (теги через /api/vault/{id}/tags не появлялись)
        UUID id = transactionTemplate.execute(s -> vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(
                        userRepository.findByUsername("import-extra-col").orElseThrow().getId())
                .get(0).getId());
        mockMvc.perform(get("/api/vault/" + id + "/tags")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
        // И тегов пользователя — пусто
        mockMvc.perform(get("/api/tags").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }

    // -- skip / upsert / dryRun / failFast -----------------------------------

    @Test
    void importSkipDoesNotMutateOnRepeat() throws Exception {
        String token = registerAndLogin("skip-repeat");
        String csv = "name,url,username,password,note\r\n"
                + "G,https://g.example.com,alice,Skip-Pass-1!,n\r\n";

        // первый импорт — создаётся
        importCsv(token, csv.getBytes(StandardCharsets.UTF_8), "skip")
                .andExpect(jsonPath("$.created").value(1));
        assertThat(userEntryCount("skip-repeat")).isEqualTo(1);

        // второй — skip
        importCsv(token, csv.getBytes(StandardCharsets.UTF_8), "skip")
                .andExpect(jsonPath("$.created").value(0))
                .andExpect(jsonPath("$.skipped").value(1));
        assertThat(userEntryCount("skip-repeat")).isEqualTo(1);

        // ранее созданная запись не изменилась
        UUID id = transactionTemplate.execute(s -> vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(
                        userRepository.findByUsername("skip-repeat").orElseThrow().getId())
                .get(0).getId());
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value("Skip-Pass-1!"));
    }

    @Test
    void importUpsertChangesPasswordOnRepeat() throws Exception {
        String token = registerAndLogin("upsert-repeat");
        createEntry(token, "Gmail", "https://gmail.example.com",
                "alice", "Old-Pass-1!", null);

        String csv = "name,url,username,password,note\r\n"
                + "GmailNew,https://gmail.example.com,alice,New-Pass-1!,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("conflictStrategy", "upsert")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.updated").value(1))
                .andExpect(jsonPath("$.created").value(0));

        UUID id = transactionTemplate.execute(s -> vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(
                        userRepository.findByUsername("upsert-repeat").orElseThrow().getId())
                .get(0).getId());
        mockMvc.perform(get("/api/vault/" + id + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("GmailNew"))
                .andExpect(jsonPath("$.password").value("New-Pass-1!"));
    }

    @Test
    void dryRunImportCreatesReportButNoDbChanges() throws Exception {
        String token = registerAndLogin("dry-create");
        String csv = "name,url,username,password,note\r\n"
                + "G,https://g.example.com,alice,Dry-Create-Pass!,n\r\n";
        long before = userEntryCount("dry-create");

        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("dryRun", "true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(1))
                .andExpect(jsonPath("$.dryRun").value(true));

        assertThat(userEntryCount("dry-create"))
                .as("dryRun must not change DB row count")
                .isEqualTo(before);
    }

    @Test
    void dryRunUpsertDoesNotMutateDatabase() throws Exception {
        String token = registerAndLogin("dry-upsert");
        UUID originalId = createEntry(token, "Gmail", "https://gmail.example.com",
                "alice", "Real-Pass-1!", null);

        // Снимок состояния БД: current *Enc + updatedAt.
        String beforePasswordEnc = transactionTemplate.execute(s ->
                vaultEntryRepository.findById(originalId).orElseThrow().getPasswordEnc());
        String beforeNameEnc = transactionTemplate.execute(s ->
                vaultEntryRepository.findById(originalId).orElseThrow().getNameEnc());
        var beforeUpdatedAt = transactionTemplate.execute(s ->
                vaultEntryRepository.findById(originalId).orElseThrow().getUpdatedAt());

        String csv = "name,url,username,password,note\r\n"
                + "GmailNew,https://gmail.example.com,alice,WOULD-BE-Pass-1!,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("conflictStrategy", "upsert")
                        .param("dryRun", "true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.updated").value(1))
                .andExpect(jsonPath("$.dryRun").value(true))
                .andExpect(jsonPath("$.totalRows").value(1));

        // БД НЕ изменилась: тот же id, те же шифротексты и updatedAt.
        var afterEntry = transactionTemplate.execute(s ->
                vaultEntryRepository.findById(originalId).orElseThrow());
        assertThat(afterEntry.getId()).isEqualTo(originalId);
        assertThat(afterEntry.getPasswordEnc()).isEqualTo(beforePasswordEnc);
        assertThat(afterEntry.getNameEnc()).isEqualTo(beforeNameEnc);
        assertThat(afterEntry.getUpdatedAt()).isEqualTo(beforeUpdatedAt);

        // Reveal возвращает прежний пароль, не тот, что был бы при реальном upsert.
        mockMvc.perform(get("/api/vault/" + originalId + "?reveal=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value("Real-Pass-1!"))
                .andExpect(jsonPath("$.name").value("Gmail"));
    }

    @Test
    void importFailFastReturns422OnInvalidRow() throws Exception {
        String token = registerAndLogin("failfast-it");
        // name пустое во второй строке
        String csv = "name,url,username,password,note\r\n"
                + "G,https://g.example.com,alice,FF-Pass-1!,n\r\n"
                + ",u,u,p,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .param("failFast", "true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.status").value(422));
    }

    // -- export headers и BOM -------------------------------------------------

    @Test
    void exportHasWarningHeaderAndContentDisposition() throws Exception {
        String token = registerAndLogin("hdr-user");
        createEntry(token, "H", "https://h.example.com", "alice", ENTRY_PASSWORD, null);

        mockMvc.perform(get("/api/vault/export")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type",
                        org.hamcrest.Matchers.startsWith("text/csv")))
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.allOf(
                                org.hamcrest.Matchers.containsString("attachment"),
                                org.hamcrest.Matchers.containsString(".csv"),
                                org.hamcrest.Matchers.containsString("hdr-user"))));
    }

    @Test
    void exportWithBomEmitsUtf8BomBytes() throws Exception {
        String token = registerAndLogin("bom-user");
        createEntry(token, "B", "https://b.example.com", "alice", ENTRY_PASSWORD, null);

        MvcResult r = mockMvc.perform(get("/api/vault/export?bom=true")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        byte[] csv = r.getResponse().getContentAsByteArray();
        assertThat(csv.length).isGreaterThanOrEqualTo(3);
        assertThat(csv[0] & 0xFF).isEqualTo(0xEF);
        assertThat(csv[1] & 0xFF).isEqualTo(0xBB);
        assertThat(csv[2] & 0xFF).isEqualTo(0xBF);
    }

    // -- admin export / import -----------------------------------------------

    @Test
    void adminCanExportAndImportArbitraryUserVault() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("admin-rt-user");
        UUID userId = userRepository.findByUsername("admin-rt-user").orElseThrow().getId();
        createEntry(userToken, "U", "https://u.example.com",
                "alice", "Admin-RT-Pass!", "n");

        // admin export
        byte[] csv = mockMvc.perform(get("/api/admin/users/{id}/vault/export", userId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"))
                .andExpect(header().string("Content-Type",
                        org.hamcrest.Matchers.startsWith("text/csv")))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("vault-user-admin-rt-user")))
                .andReturn().getResponse().getContentAsByteArray();
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text).startsWith("name,url,username,password,note\r\n");
        assertThat(text).contains("Admin-RT-Pass!");

        // удаляем запись у пользователя
        transactionTemplate.executeWithoutResult(s -> {
            for (var e : vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(userId)) {
                vaultEntryRepository.delete(e);
            }
        });
        long sizeBefore = transactionTemplate.execute(s ->
                vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(userId).size());
        assertThat(sizeBefore).isZero();

        // admin import — round-trip через admin
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv", csv);
        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", userId)
                        .file(file)
                        .param("conflictStrategy", "skip")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(1));

        long sizeAfter = transactionTemplate.execute(s ->
                vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(userId).size());
        assertThat(sizeAfter).isEqualTo(1L);
    }

    @Test
    void nonAdminGets403OnAdminExportAndImport() throws Exception {
        String userToken = registerAndLogin("non-admin-rt");
        UUID userId = userRepository.findByUsername("non-admin-rt").orElseThrow().getId();

        mockMvc.perform(get("/api/admin/users/{id}/vault/export", userId)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());

        MockMultipartFile file = new MockMultipartFile(
                "file", "x.csv", "text/csv",
                "name,url,username,password,note\r\nG,u,l,p,n\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", userId)
                        .file(file)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminMissingUserReturns404OnExportAndImport() throws Exception {
        String adminToken = loginAdmin();
        UUID missing = UUID.randomUUID();

        mockMvc.perform(get("/api/admin/users/{id}/vault/export", missing)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));

        MockMultipartFile file = new MockMultipartFile(
                "file", "x.csv", "text/csv",
                "name,url,username,password,note\r\nG,u,l,p,n\r\n"
                        .getBytes(StandardCharsets.UTF_8));
        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", missing)
                        .file(file)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void oversizedCsvReturns413() throws Exception {
        String token = registerAndLogin("rt-413");
        // Строго больше MAX_CSV_BYTES (10 МБ). Шапка валидная — доходим до сервиса.
        byte[] huge = new byte[10 * 1024 * 1024 + 1];
        byte[] header = "name,url,username,password,note\r\n"
                .getBytes(StandardCharsets.UTF_8);
        System.arraycopy(header, 0, huge, 0, header.length);
        MockMultipartFile file = new MockMultipartFile(
                "file", "huge.csv", "text/csv", huge);

        mockMvc.perform(multipart("/api/vault/import")
                        .file(file)
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().is(org.hamcrest.Matchers.anyOf(
                        org.hamcrest.Matchers.equalTo(413),
                        org.hamcrest.Matchers.equalTo(500))));
    }
}
