package com.example.safeaccounts.it;

import com.example.safeaccounts.api.LoginRequest;
import com.example.safeaccounts.api.RegisterRequest;
import com.example.safeaccounts.api.VaultEntryCreateRequest;
import com.example.safeaccounts.config.AdminBootstrap;
import com.example.safeaccounts.crypto.WrappedDek;
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
import org.springframework.mock.web.MockMultipartFile;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционные тесты административного API (Task-06):
 * доступ только у ADMIN, управление пользователями, сброс пароля
 * с отзывом токенов, просмотр аудита, ротация KEK (rewrap-deks)
 * с сохранением читаемости секретов. PostgreSQL — Testcontainers.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class AdminApiIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String NEW_PASSWORD = "Br4nd-New-Pass!42";

    @Autowired
    MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;
    @Autowired
    UserRepository userRepository;
    @Autowired
    AuditEventRepository auditEventRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
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

    private String loginAdmin() throws Exception {
        // Bootstrap-админ создается только на пустой БД; cleanDatabase() ее очищает.
        transactionTemplate.executeWithoutResult(status -> adminBootstrap.run(null));
        return login("bootstrap-admin", "B00tstrap-Admin-Pass!");
    }

    private String login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new LoginRequest(username, password))))
                .andExpect(status().isOk())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken").asText();
    }

    private String registerAndLogin(String username) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new RegisterRequest(username, PASSWORD))))
                .andExpect(status().isCreated());
        return login(username, PASSWORD);
    }

    private UUID userId(String username) {
        return transactionTemplate.execute(status ->
                userRepository.findByUsername(username).orElseThrow().getId());
    }

    // -- security -------------------------------------------------------------

    @Test
    void adminEndpointsRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/admin/users")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/admin/audit")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/admin/crypto/rewrap-deks")).andExpect(status().isUnauthorized());
    }

    @Test
    void regularUserGetsForbiddenOnAdminEndpoints() throws Exception {
        String userToken = registerAndLogin("plain-user");

        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/admin/audit").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/users/{id}/disable", UUID.randomUUID())
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/users/{id}/reset-password", UUID.randomUUID())
                        .header("Authorization", "Bearer " + userToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                Map.of("newPassword", NEW_PASSWORD))))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/admin/crypto/rewrap-deks")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // -- пользователи ---------------------------------------------------------

    @Test
    void adminCanCreateListEnableDisableUsers() throws Exception {
        String adminToken = loginAdmin();

        // create
        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", "admin-made-user",
                                "password", "Adm1n-Made-Pass!",
                                "role", "ROLE_USER"))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("admin-made-user"))
                .andExpect(jsonPath("$.role").value("ROLE_USER"))
                .andExpect(jsonPath("$.enabled").value(true))
                // хэш пароля и wrapped DEK не раскрываются
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.dekWrapped").doesNotExist());

        // список
        mockMvc.perform(get("/api/admin/users").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.username == 'admin-made-user')]").exists());

        UUID created = userId("admin-made-user");

        // disable
        mockMvc.perform(post("/api/admin/users/{id}/disable", created)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));

        // Отключенный пользователь не может войти (403 USER_DISABLED —
        // существующее поведение AuthService/ApiExceptionHandler из Task-04).
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("admin-made-user", "Adm1n-Made-Pass!"))))
                .andExpect(status().isForbidden());

        // enable
        mockMvc.perform(post("/api/admin/users/{id}/enable", created)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(true));

        // после включения вход работает
        login("admin-made-user", "Adm1n-Made-Pass!");
    }

    @Test
    void adminCreateUserRejectsDuplicateAndInvalidRole() throws Exception {
        String adminToken = loginAdmin();
        registerAndLogin("dup-target");

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", "dup-target",
                                "password", "Adm1n-Made-Pass!"))))
                .andExpect(status().isConflict());

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", "bad-role-user",
                                "password", "Adm1n-Made-Pass!",
                                "role", "ROLE_SUPERUSER"))))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of(
                                "username", "short-pass-user",
                                "password", "short"))))
                .andExpect(status().isBadRequest());
    }

    @Test
    void resetPasswordRevokesOldTokensAndAudits() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("reset-target");
        UUID target = userId("reset-target");

        // Токен пользователя еще действует.
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/admin/users/{id}/reset-password", target)
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("newPassword", NEW_PASSWORD))))
                .andExpect(status().isOk());

        // Старый токен отозван.
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isUnauthorized());

        // Вход со старым паролем больше не работает; с новым — работает.
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new LoginRequest("reset-target", PASSWORD))))
                .andExpect(status().isUnauthorized());
        login("reset-target", NEW_PASSWORD);

        // Аудит содержит событие и не содержит паролей.
        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(target);
            assertThat(events.stream().map(e -> e.getType()))
                    .contains("USER_RESET_PASSWORD");
            for (var event : events) {
                String blob = String.valueOf(event.getDetailsJson()) + event.getType();
                assertThat(blob).doesNotContain(PASSWORD).doesNotContain(NEW_PASSWORD);
            }
        });
    }

    @Test
    void disabledUserWithValidTokenCannotUseVault() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("disable-target");
        UUID target = userId("disable-target");

        mockMvc.perform(post("/api/admin/users/{id}/disable", target)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());

        // Токен жив, но пользователь отключен — доступ запрещен (Task-06 тест 3).
        // Фильтр токенов fail-closed: 401 вместо 403 (не раскрываем статус
        // учетной записи).
        mockMvc.perform(get("/api/vault").header("Authorization", "Bearer " + userToken))
                .andExpect(status().isUnauthorized());
    }

    // -- аудит ----------------------------------------------------------------

    @Test
    void adminCanReadAuditWithPaginationAndFilters() throws Exception {
        String adminToken = loginAdmin();
        registerAndLogin("audit-user");

        // Генерируем события.
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer "
                        + login("audit-user", PASSWORD)))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/admin/audit?type=LOGIN_SUCCESS&size=5")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.content[0].type").value("LOGIN_SUCCESS"))
                // пароль в событиях аудита отсутствует
                .andExpect(jsonPath("$.content[*].detailsJson")
                        .value(org.hamcrest.Matchers.everyItem(
                                org.hamcrest.Matchers.not(
                                        org.hamcrest.Matchers.containsString(PASSWORD)))));

        // Фильтр по пользователю.
        UUID uid = userId("audit-user");
        mockMvc.perform(get("/api/admin/audit?userId=" + uid)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].userId").value(uid.toString()));

        // Фильтр по периоду.
        mockMvc.perform(get("/api/admin/audit?from=2020-01-01T00:00:00Z&to=2030-01-01T00:00:00Z")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(org.hamcrest.Matchers.greaterThanOrEqualTo(1)));

        mockMvc.perform(get("/api/admin/audit?from=2035-01-01T00:00:00Z")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    // -- ротация ключей -------------------------------------------------------

    @Test
    void rewrapDeksMovesUsersToActiveKeyAndKeepsSecretsReadable() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("rotate-user");
        UUID uid = userId("rotate-user");

        // Секрет до ротации.
UUID entryId = createEntry(userToken, "Admin-Label", "https://example.com", "alice", "Entry-Pass-123!", "note-1");
        String wrappedBefore = transactionTemplate.execute(status ->
                userRepository.findById(uid).orElseThrow().getDekWrapped());

        // Симулируем пользователя, чей DEK завернут СТАРЫМ ключом 'old'
        // (сценарий до ротации: конфигурация has old+primary, primary активен).
        transactionTemplate.executeWithoutResult(status -> {
            var u = userRepository.findById(uid).orElseThrow();
            var dek = cryptoService.unwrapDek(new WrappedDek(
                    u.getDekWrapped(), u.getDekIv(), u.getDekKekId()));
            var oldKekWrapped = wrapWithKek(dek, "old");
            u.rewrapDek(oldKekWrapped.wrappedDekBase64(), oldKekWrapped.ivBase64(), "old");
            userRepository.saveAndFlush(u);
        });

        mockMvc.perform(post("/api/admin/crypto/rewrap-deks")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rewrappedUsers").value(1));

        // DEK перепакован активным ключом 'primary' (wrapped изменился из-за
        // случайного IV; kek id теперь активный).
        transactionTemplate.executeWithoutResult(status -> {
            var user = userRepository.findById(uid).orElseThrow();
            assertThat(user.getDekWrapped()).isNotEqualTo(wrappedBefore);
            assertThat(user.getDekKekId()).isEqualTo("primary");
        });

        // Повторный запуск идемпотентен.
        mockMvc.perform(post("/api/admin/crypto/rewrap-deks")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rewrappedUsers").value(0));

        // Расшифровка секретов после ротации продолжает работать (Task-06 тест 6).
        mockMvc.perform(get("/api/vault/" + entryId + "?reveal=true")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").value("Entry-Pass-123!"))
                .andExpect(jsonPath("$.notes").value("note-1"))
                .andExpect(jsonPath("$.site").value("https://example.com"))
                .andExpect(jsonPath("$.login").value("alice"));

        // Аудит ротации: STARTED + COMPLETED, без материала ключей.
        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(
                    userId("bootstrap-admin"));
            var types = events.stream().map(e -> e.getType()).toList();
            assertThat(types).contains("KEY_ROTATION_STARTED", "KEY_ROTATION_COMPLETED");
            for (var event : events) {
                if (event.getType().startsWith("KEY_ROTATION")) {
                    String blob = String.valueOf(event.getDetailsJson());
                    assertThat(blob).doesNotContain(wrappedBefore);
                }
            }
        });
    }

    @Autowired
    com.example.safeaccounts.crypto.AesGcmCryptoService cryptoService;
    @Autowired
    com.example.safeaccounts.crypto.KeyManager keyManager;

    /** Переупаковывает DEK указанным (не обязательно активным) KEK. */
    private com.example.safeaccounts.crypto.WrappedDek wrapWithKek(
            javax.crypto.SecretKey dek, String kekId) {
        try {
            var kekField = com.example.safeaccounts.crypto.KeyManager.class
                    .getDeclaredField("keysById");
            kekField.setAccessible(true);
            @SuppressWarnings("unchecked")
            var keys = (java.util.Map<String, javax.crypto.SecretKey>) kekField.get(keyManager);
            byte[] dekBytes = dek.getEncoded();
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keys.get(kekId),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            byte[] wrapped = cipher.doFinal(dekBytes);
            byte[] container = java.nio.ByteBuffer.allocate(iv.length + wrapped.length)
                    .put(iv).put(wrapped).array();
            return new com.example.safeaccounts.crypto.WrappedDek(
                    java.util.Base64.getEncoder().encodeToString(container),
                    java.util.Base64.getEncoder().encodeToString(iv),
                    kekId);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
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

    // -- export / import (Task-07 / Task-08, Фаза 5) ------------------------

    @Test
    void adminCanExportAnotherUsersVault() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("admin-export-user");
        UUID userId = userId("admin-export-user");
        createEntry(userToken, "UserEntry", "https://user.example.com",
                "alice", "User-Entry-Pass!", "user-note");

        MvcResult result = mockMvc.perform(get("/api/admin/users/{id}/vault/export", userId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"))
                .andExpect(header().string("Content-Type",
                        org.hamcrest.Matchers.startsWith("text/csv")))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("vault-user-admin-export-user")))
                .andReturn();

        String csv = new String(result.getResponse().getContentAsByteArray(),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csv).startsWith("name,url,username,password,note\r\n");
        assertThat(csv).contains("UserEntry").contains("https://user.example.com")
                .contains("alice").contains("User-Entry-Pass!");
        // Аудит VAULT_EXPORTED пишется, actor=admin, target=user.
        // Event записан с user=actor (bootstrap-admin), а не с target.
        UUID adminId = userId("bootstrap-admin");
        transactionTemplate.executeWithoutResult(status -> {
            var events = auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(adminId);
            var exported = events.stream()
                    .filter(e -> "VAULT_EXPORTED".equals(e.getType()))
                    .findFirst().orElseThrow();
            String blob = String.valueOf(exported.getDetailsJson());
            assertThat(blob).doesNotContain("User-Entry-Pass!").doesNotContain("user-note");
        });
    }

    @Test
    void adminExportMissingUserReturns404() throws Exception {
        String adminToken = loginAdmin();
        UUID missing = UUID.randomUUID();

        mockMvc.perform(get("/api/admin/users/{id}/vault/export", missing)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404));
    }

    @Test
    void nonAdminCannotAccessAdminExport() throws Exception {
        String userToken = registerAndLogin("plain-export-user");
        UUID userId = userId("plain-export-user");
        mockMvc.perform(get("/api/admin/users/{id}/vault/export", userId)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedCannotAccessAdminExport() throws Exception {
        UUID someId = UUID.randomUUID();
        mockMvc.perform(get("/api/admin/users/{id}/vault/export", someId))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminCanImportIntoAnotherUsersVault() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("admin-import-user");
        UUID userId = userId("admin-import-user");

        String csv = "name,url,username,password,note\r\n"
                + "ImportedByAdmin,https://ia.example.com,alice,Admin-Imp-Pass!,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", userId)
                        .file(file)
                        .param("conflictStrategy", "skip")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.created").value(1));

        // Запись появилась в сейфе целевого пользователя
        long count = transactionTemplate.execute(s ->
                vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(userId).size());
        assertThat(count).isEqualTo(1);

        // Владелец видит свою запись
        long ownerCount = transactionTemplate.execute(s ->
                vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(userId).size());
        assertThat(ownerCount).isEqualTo(1);
    }

    @Test
    void adminImportMissingUserReturns404() throws Exception {
        String adminToken = loginAdmin();
        UUID missing = UUID.randomUUID();
        String csv = "name,url,username,password,note\r\nG,u,l,p,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", missing)
                        .file(file)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    @Test
    void nonAdminCannotAccessAdminImport() throws Exception {
        String userToken = registerAndLogin("plain-import-user");
        UUID userId = userId("plain-import-user");
        String csv = "name,url,username,password,note\r\nG,u,l,p,n\r\n";
        MockMultipartFile file = new MockMultipartFile(
                "file", "import.csv", "text/csv",
                csv.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        mockMvc.perform(multipart("/api/admin/users/{id}/vault/import", userId)
                        .file(file)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    // -- Фаза 8: инвариант формата admin-CSV (ровно 5 колонок) -------------

    @Test
    void adminExportedCsvHasExactlyFiveColumnsInHeaderAndEveryRow() throws Exception {
        String adminToken = loginAdmin();
        String userToken = registerAndLogin("admin-five-cols");
        UUID userId = userId("admin-five-cols");
        createEntry(userToken, "A", "https://a.example.com", "alice", "Admin-Five-Pass!", null);
        createEntry(userToken, "B", "https://b.example.com", "bob", "Admin-Five-Pass!", null);

        byte[] csv = mockMvc.perform(get("/api/admin/users/{id}/vault/export", userId)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        String text = new String(csv, java.nio.charset.StandardCharsets.UTF_8);
        String[] lines = text.split("\r\n", -1);

        assertThat(lines[0]).isEqualTo("name,url,username,password,note");
        assertThat(adminCountCsvColumns(lines[0])).isEqualTo(5);

        for (int i = 1; i < lines.length; i++) {
            if (lines[i].isEmpty()) {
                continue;
            }
            assertThat(adminCountCsvColumns(lines[i]))
                    .as("row %d must have 5 columns: %s", i, lines[i])
                    .isEqualTo(5);
        }
    }

    /** Считает колонки по RFC 4180 (с учётом кавычек и удвоенных кавычек). */
    private static int adminCountCsvColumns(String line) {
        int cols = 1;
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                cols++;
            }
        }
        return cols;
    }
}
