package com.example.safeaccounts.it;

import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

/**
 * Интеграционные тесты тегов в web-UI (Фаза 2 плана frontend, §2.3).
 * CSV export/import добавят следующие фазы — здесь только теги.
 * <p>
 * Паттерн авторизации — как в {@code WebUiIT}: Testcontainers PostgreSQL,
 * регистрация через API, логин через /web/login с CSRF, сессия MockMvc.
 * <p>
 * Проверяется: привязка/отвязка на карточке, страница /web/tags
 * (создание/переименование/удаление), фильтр ?tag=, дубль имени,
 * невалидные имена, CSRF, чужие записи (404, не 500).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class WebUiTagsExportImportIT {

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
    UserRepository userRepository;
    @Autowired
    com.example.safeaccounts.service.UserService userService;
    @Autowired
    com.example.safeaccounts.service.AdminService adminService;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    TagRepository tagRepository;
    @Autowired
    TransactionTemplate transactionTemplate;

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Entry-Pass-123!";
    private static final Pattern UUID_PATH =
            Pattern.compile("/web/entries/([0-9a-fA-F-]{36})");
    private static final Pattern TAG_ID_IN_RENAME =
            Pattern.compile("/web/tags/([0-9a-fA-F-]{36})/rename");
    private static final Pattern TAG_ID_IN_FILTER =
            Pattern.compile("tag=([0-9a-fA-F-]{36})");

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            // vault_entry_tags чистится каскадно при удалении записей/тегов
            // через deleteAll сущностей (JPA владеет связью), но порядок важен.
            vaultEntryRepository.deleteAll();
            tagRepository.deleteAll();
            userRepository.deleteAll();
        });
    }

    // -- helpers --------------------------------------------------------------

    private void registerUser(String username) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}"
                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
    }

    private org.springframework.mock.web.MockHttpSession login(String username) throws Exception {
        MvcResult loginResult = mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"))
                .andReturn();
        return (org.springframework.mock.web.MockHttpSession) loginResult.getRequest().getSession();
    }

    private String createEntry(org.springframework.mock.web.MockHttpSession session,
                               String name) throws Exception {
        MvcResult result = mockMvc.perform(post("/web/entries")
                        .session(session)
                        .with(csrf())
                        .param("name", name)
                        .param("site", "https://example.com")
                        .param("login", "alice")
                        .param("password", ENTRY_PASSWORD)
                        .param("notes", ""))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"))
                .andReturn();
        // id записи — из ссылки на просмотр в списке
        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        Matcher matcher = UUID_PATH.matcher(html(list));
        assertThat(matcher.find()).as("entry link in list").isTrue();
        return matcher.group(1);
    }

    private void createTag(org.springframework.mock.web.MockHttpSession session, String name)
            throws Exception {
        mockMvc.perform(post("/web/tags")
                        .session(session)
                        .with(csrf())
                        .param("name", name))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/tags"))
                .andExpect(flash().attribute("flashMessage", "Тег создан"));
    }

    private String firstTagId(org.springframework.mock.web.MockHttpSession session) throws Exception {
        MvcResult tags = mockMvc.perform(get("/web/tags").session(session))
                .andExpect(status().isOk())
                .andReturn();
        Matcher matcher = TAG_ID_IN_RENAME.matcher(html(tags));
        assertThat(matcher.find()).as("rename form for tag").isTrue();
        return matcher.group(1);
    }

    private long userTagCount(String username) {
        return transactionTemplate.execute(tx ->
                tagRepository.findAllByUser_IdOrderByNameLowerAsc(userIdOf(username)).size());
    }

    private Set<UUID> entryTagIds(UUID entryId) {
        return transactionTemplate.execute(tx ->
                vaultEntryRepository.findById(entryId).stream()
                        .flatMap(e -> e.getTags().stream())
                        .map(Tag::getId)
                        .collect(Collectors.toSet()));
    }

    private UUID userIdOf(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow().getId();
    }

    /** Создает администратора напрямую через UserService (паттерн WebUiIT). */
    private void createAdmin(String username) {
        userService.register(username, PASSWORD, "ROLE_ADMIN");
    }

    private static String html(MvcResult result)
            throws java.io.UnsupportedEncodingException {
        return result.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    // -- (a) привязка нового тега через карточку -------------------------------

    @Test
    void attachNewTagFromEntryCardShowsChipInListAndCard() throws Exception {
        registerUser("taguser");
        var session = login("taguser");
        String entryId = createEntry(session, "Запись с тегом");

        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(session)
                        .with(csrf())
                        .param("tagName", "work"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/" + entryId))
                .andExpect(flash().attribute("flashMessage", "Тег привязан"));

        // Чип виден на карточке (блок тегов + datalist нового тега);
        // пробелы нормализуем: Thymeleaf переносит атрибуты на новые строки
        MvcResult card = mockMvc.perform(get("/web/entries/" + entryId).session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("entry-view"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("tag-badge")))
                .andReturn();
        assertThat(html(card).replaceAll("\\s+", "")).contains(">work</a>");

        // Чип виден в списке (ссылка-фильтр ?tag=<id>)
        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(html(list).replaceAll("\\s+", "")).contains(">work</a>");
        assertThat(TAG_ID_IN_FILTER.matcher(html(list)).find()).isTrue();
    }

    // -- (b) привязка существующего тега к другой записи ------------------------

    @Test
    void attachExistingTagToAnotherEntryReusesTag() throws Exception {
        registerUser("reuser");
        var session = login("reuser");
        createTag(session, "work");
        String entry1 = createEntry(session, "Первая");
        String entry2 = createEntry(session, "Вторая");

        mockMvc.perform(post("/web/entries/" + entry1 + "/tags")
                        .session(session).with(csrf()).param("tagName", "work"))
                .andExpect(status().is3xxRedirection());
        // Разный регистр — тот же тег (case-insensitive поиск по name_lower)
        mockMvc.perform(post("/web/entries/" + entry2 + "/tags")
                        .session(session).with(csrf()).param("tagName", "WORK"))
                .andExpect(status().is3xxRedirection());

        assertThat(userTagCount("reuser")).isEqualTo(1);
        assertThat(entryTagIds(UUID.fromString(entry1))).hasSize(1);
        assertThat(entryTagIds(UUID.fromString(entry2))).hasSize(1);
    }

    // -- (c) отвязка ------------------------------------------------------------

    @Test
    void detachTagFromEntryRemovesOnlyLink() throws Exception {
        registerUser("detacher");
        var session = login("detacher");
        createTag(session, "temp");
        String entryId = createEntry(session, "Запись");
        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(session).with(csrf()).param("tagName", "temp"))
                .andExpect(status().is3xxRedirection());

        String tagId = firstTagId(session);
        mockMvc.perform(post("/web/entries/" + entryId + "/tags/" + tagId + "/delete")
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/" + entryId))
                .andExpect(flash().attribute("flashMessage", "Тег снят"));

        // Связь снята, сам тег остался (доступен на /web/tags)
        assertThat(entryTagIds(UUID.fromString(entryId))).isEmpty();
        assertThat(userTagCount("detacher")).isEqualTo(1);
    }

    // -- (d) /web/tags: создание, переименование, удаление свободного -----------

    @Test
    void tagsPageCreateRenameDeleteFreeTag() throws Exception {
        registerUser("tagadmin");
        var session = login("tagadmin");

        // Создание
        createTag(session, "alpha");
        mockMvc.perform(get("/web/tags").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("tags"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("alpha")));

        // Переименование
        String tagId = firstTagId(session);
        mockMvc.perform(post("/web/tags/" + tagId + "/rename")
                        .session(session).with(csrf()).param("name", "beta"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashMessage", "Тег переименован"));
        MvcResult afterRename = mockMvc.perform(get("/web/tags").session(session))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(html(afterRename)).contains("beta");
        assertThat(html(afterRename)).doesNotContain("alpha");

        // Удаление свободного тега
        mockMvc.perform(post("/web/tags/" + tagId + "/delete")
                        .session(session).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashMessage", "Тег удалён"));
        mockMvc.perform(get("/web/tags").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Тегов пока нет")));
    }

    // -- (e) удаление занятого тега → flash-ошибка, тег остаётся ------------------

    @Test
    void deleteReferencedTagShowsFlashErrorAndKeepsTag() throws Exception {
        registerUser("occupied");
        var session = login("occupied");
        createTag(session, "busy");
        String entryId = createEntry(session, "Запись");
        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(session).with(csrf()).param("tagName", "busy"))
                .andExpect(status().is3xxRedirection());

        String tagId = firstTagId(session);
        mockMvc.perform(post("/web/tags/" + tagId + "/delete")
                        .session(session).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/tags"))
                .andExpect(flash().attribute("flashError",
                        org.hamcrest.Matchers.containsString("записью")));

        // Тег не удалён
        assertThat(userTagCount("occupied")).isEqualTo(1);
    }

    // -- (f) дубль имени (разный регистр) → flash-ошибка --------------------------

    @Test
    void duplicateTagNameDifferentCaseShowsFlashError() throws Exception {
        registerUser("dupuser");
        var session = login("dupuser");
        createTag(session, "Work");

        mockMvc.perform(post("/web/tags")
                        .session(session).with(csrf()).param("name", "WORK"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/tags"))
                .andExpect(flash().attribute("flashError", "Тег уже существует"));

        assertThat(userTagCount("dupuser")).isEqualTo(1);
    }

    // -- (g) фильтр ?tag= показывает только помеченные записи + сброс ------------

    @Test
    void tagFilterShowsOnlyTaggedEntriesAndReset() throws Exception {
        registerUser("filterer");
        var session = login("filterer");
        String tagged = createEntry(session, "Помеченная");
        createEntry(session, "Непомеченная");
        mockMvc.perform(post("/web/entries/" + tagged + "/tags")
                        .session(session).with(csrf()).param("tagName", "only"))
                .andExpect(status().is3xxRedirection());

        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andReturn();
        Matcher matcher = TAG_ID_IN_FILTER.matcher(html(list));
        assertThat(matcher.find()).as("tag chip link with ?tag=").isTrue();
        String tagId = matcher.group(1);

        // Фильтр: только помеченная запись + индикатор + ссылка сброса
        MvcResult filtered = mockMvc.perform(get("/web/entries")
                        .session(session).param("tag", tagId))
                .andExpect(status().isOk())
                .andExpect(view().name("entries"))
                .andReturn();
        assertThat(html(filtered)).contains("Помеченная");
        assertThat(html(filtered)).doesNotContain("Непомеченная");
        assertThat(html(filtered)).contains("tag-filter");
        assertThat(html(filtered)).contains("only");

        // Сброс: без параметра — обе записи
        MvcResult reset = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(html(reset)).contains("Помеченная");
        assertThat(html(reset)).contains("Непомеченная");
    }

    // -- (h) невалидное имя тега → ошибка, не 500 ---------------------------------

    @Test
    void invalidTagNameRejectedWithout500() throws Exception {
        registerUser("invalidtag");
        var session = login("invalidtag");
        String entryId = createEntry(session, "Запись");

        // 65 символов — превышение длины (сервисная валидация)
        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(session).with(csrf())
                        .param("tagName", "x".repeat(65)))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashError",
                        org.hamcrest.Matchers.containsString("Некорректное имя тега")));

        // Запрещённые символы — regex (bean validation на форме /web/tags)
        mockMvc.perform(post("/web/tags")
                        .session(session).with(csrf()).param("name", "bad!tag"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashError", "Некорректное имя тега"));

        assertThat(userTagCount("invalidtag")).isZero();
    }

    // -- (i) CSRF: POST без токена отклоняется -----------------------------------

    @Test
    void tagPostsWithoutCsrfTokenAreRejected() throws Exception {
        registerUser("tagcsrf");
        var session = login("tagcsrf");

        mockMvc.perform(post("/web/tags")
                        .session(session).param("name", "nope"))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/web/entries/" + UUID.randomUUID() + "/tags")
                        .session(session).param("tagName", "nope"))
                .andExpect(status().isForbidden());
        assertThat(userTagCount("tagcsrf")).isZero();
    }

    // -- (j) чужая запись: привязка/отвязка тега → 404, не 500 -------------------

    @Test
    void tagOperationsOnOtherUsersEntryReturn404() throws Exception {
        registerUser("owneruser");
        registerUser("intruder");
        var ownerSession = login("owneruser");
        var intruderSession = login("intruder");
        String entryId = createEntry(ownerSession, "Чужая запись");

        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(intruderSession)
                        .with(csrf())
                        .param("tagName", "stolen"))
                .andExpect(status().isNotFound());

        mockMvc.perform(post("/web/entries/" + entryId + "/tags/" + UUID.randomUUID() + "/delete")
                        .session(intruderSession)
                        .with(csrf()))
                .andExpect(status().isNotFound());

        // Ни тег, ни привязка не созданы; владелец не затронут
        assertThat(userTagCount("intruder")).isZero();
        assertThat(entryTagIds(UUID.fromString(entryId))).isEmpty();
    }

    // -- Фаза 3: CSV export/import для пользователя -----------------------------

    private static final String CSV_HEADER = "name,url,username,password,note";

    private static byte[] csv(String... rows) {
        return String.join("\r\n", rows).concat("\r\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    /** multipart POST импорта без фиксированных ожиданий статуса. */
    private MvcResult performImport(org.springframework.mock.web.MockHttpSession session,
                                    byte[] content, String strategy,
                                    boolean dryRun, boolean failFast) throws Exception {
        var builder = multipart("/web/entries/import")
                .file(new org.springframework.mock.web.MockMultipartFile(
                        "file", "test.csv", "text/csv", content))
                .param("conflictStrategy", strategy);
        // session() на билдере возвращает базовый тип (Spring не генерализует
        // MockHttpServletRequestBuilder) — применяем отдельными statements
        builder.session(session);
        if (dryRun) {
            builder.param("dryRun", "true");
        }
        if (failFast) {
            builder.param("failFast", "true");
        }
        return mockMvc.perform(builder.with(csrf())).andReturn();
    }

    /** PRG-импорт (Фаза 4): POST → 302 на отчёт; follow GET — HTML отчёта. */
    private String importReportHtml(org.springframework.mock.web.MockHttpSession session,
                                    byte[] content, String strategy,
                                    boolean dryRun, boolean failFast) throws Exception {
        MvcResult post = performImport(session, content, strategy, dryRun, failFast);
        assertThat(post.getResponse().getStatus())
                .as("PRG: успешный POST-импорт обязан редиректить на отчёт")
                .isEqualTo(302);
        MvcResult reportGet = mockMvc.perform(get(post.getResponse().getHeader("Location"))
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("import-report"))
                .andReturn();
        return html(reportGet);
    }

    @Test
    void exportCsvReturnsOwnEntriesWithWarningAndDisposition() throws Exception {
        registerUser("exporter");
        registerUser("otherexporter");
        var session = login("exporter");
        createEntry(session, "Моя-экспорт-1");
        createEntry(session, "Моя-экспорт-2");
        var otherSession = login("otherexporter");
        createEntry(otherSession, "Чужая-экспорт");

        MvcResult result = mockMvc.perform(get("/web/entries/export").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("attachment")))
                .andReturn();

        String body = new String(result.getResponse().getContentAsByteArray(),
                StandardCharsets.UTF_8);
        String firstLine = body.substring(0, body.indexOf('\n')).trim();
        assertThat(firstLine).isEqualTo(CSV_HEADER);
        assertThat(body).contains("Моя-экспорт-1");
        assertThat(body).contains("Моя-экспорт-2");
        // Чужие записи в экспорт не попадают
        assertThat(body).doesNotContain("Чужая-экспорт");
    }

    @Test
    void exportCsvBomFlagControlsBomPrefix() throws Exception {
        registerUser("bomuser");
        var session = login("bomuser");
        createEntry(session, "BOM-запись");

        byte[] withBom = mockMvc.perform(get("/web/entries/export")
                        .session(session).param("bom", "true"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        assertThat(withBom.length).isGreaterThan(3);
        assertThat(withBom[0] & 0xFF).isEqualTo(0xEF);
        assertThat(withBom[1] & 0xFF).isEqualTo(0xBB);
        assertThat(withBom[2] & 0xFF).isEqualTo(0xBF);

        byte[] withoutBom = mockMvc.perform(get("/web/entries/export")
                        .session(session))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();
        assertThat(withoutBom.length).isGreaterThan(3);
        assertThat(withoutBom[0] & 0xFF).isNotEqualTo(0xEF);
    }

    @Test
    void importPageShowsWarningAndMultipartForm() throws Exception {
        registerUser("importpage");
        var session = login("importpage");
        mockMvc.perform(get("/web/entries/import").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("import"))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("multipart/form-data")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("alert-warning")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("пароли в открытом виде")));
    }

    @Test
    void importCreatesEntriesAndShowsReport() throws Exception {
        registerUser("importer1");
        var session = login("importer1");
        byte[] content = csv(CSV_HEADER,
                "Импорт-раз,https://imp1.example,u1,Pass-111,n1",
                "Импорт-два,https://imp2.example,u2,Pass-222,n2");

        MvcResult report = mockMvc.perform(multipart("/web/entries/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv", content))
                        .param("conflictStrategy", "skip")
                        .with(csrf())
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/import/report"))
                .andReturn();
        assertThat(report.getFlashMap().get("importReport")).isNotNull();
        MvcResult reportGet = mockMvc.perform(get("/web/entries/import/report")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("import-report"))
                .andReturn();
        String html = html(reportGet);
        assertThat(html).contains("data-metric=\"created\">2<");
        assertThat(html).contains("data-metric=\"failed\">0<");

        // Записи видны в списке
        mockMvc.perform(get("/web/entries").session(session))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Импорт-раз")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Импорт-два")));
    }

    @Test
    void importSkipStrategySkipsDuplicates() throws Exception {
        registerUser("importskip");
        var session = login("importskip");
        byte[] content = csv(CSV_HEADER,
                "Скип-1,https://skip.example,u1,Pass-111,n1",
                "Скип-2,https://skip.example,u2,Pass-222,n2");
        // Первый импорт с потреблением flash-отчёта (иначе второй GET отчёта
        // получит СТАРЫЙ flash: pending FlashMap матчится по пути)
        importReportHtml(session, content, "skip", false, false);

        String html = importReportHtml(session, content, "skip", false, false);
        assertThat(html).contains("data-metric=\"created\">0<");
        assertThat(html).contains("data-metric=\"skipped\">2<");

        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isEqualTo(2);
    }

    @Test
    void importUpsertUpdatesExistingEntries() throws Exception {
        registerUser("importupsert");
        var session = login("importupsert");
        byte[] original = csv(CSV_HEADER,
                "Апсерт-1,https://up.example,u1,Old-Pass-1,n1",
                "Апсерт-2,https://up.example,u2,Old-Pass-2,n2");
        // Потребляем flash первого импорта follow-GET (см. skip-тест)
        importReportHtml(session, original, "skip", false, false);

        byte[] changed = csv(CSV_HEADER,
                "Апсерт-1,https://up.example,u1,New-Pass-1,n1",
                "Апсерт-2,https://up.example,u2,New-Pass-2,n2");
        MvcResult report = performImport(session, changed, "upsert", false, false);
        assertThat(report.getResponse().getStatus()).isEqualTo(302);
        MvcResult reportGet = mockMvc.perform(get("/web/entries/import/report")
                        .session(session))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(html(reportGet)).contains("data-metric=\"updated\">2<");

        // Дублей не появилось: по-прежнему 2 записи
        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isEqualTo(2);
    }

    @Test
    void importDryRunDoesNotChangeAnything() throws Exception {
        registerUser("importdry");
        var session = login("importdry");
        byte[] content = csv(CSV_HEADER,
                "Драй-1,https://dry.example,u1,Pass-111,n1",
                "Драй-2,https://dry.example,u2,Pass-222,n2");

        MvcResult report = performImport(session, content, "skip", true, false);
        assertThat(report.getResponse().getStatus()).isEqualTo(302);
        MvcResult reportGet = mockMvc.perform(get("/web/entries/import/report")
                        .session(session))
                .andExpect(status().isOk())
                .andReturn();
        String html = html(reportGet);
        assertThat(html).contains("dry-run");
        assertThat(html).contains("data-metric=\"created\">2<");

        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isZero();
    }

    @Test
    void importInvalidRowFailsOnlyThatRow() throws Exception {
        registerUser("importfail");
        var session = login("importfail");
        byte[] content = csv(CSV_HEADER,
                "Валидная,https://ok.example,u1,Pass-111,n1",
                "Пустой-пароль,https://bad.example,u2,,n2");

        String html = importReportHtml(session, content, "skip", false, false);
        assertThat(html).contains("data-metric=\"created\">1<");
        assertThat(html).contains("data-metric=\"failed\">1<");
        // Номер строки с ошибкой — в таблице ошибок отчёта
        assertThat(html).contains("2</td>");
    }

    @Test
    void importFailFastCreatesNothing() throws Exception {
        registerUser("importff");
        var session = login("importff");
        byte[] content = csv(CSV_HEADER,
                "Валидная-фф,https://ok.example,u1,Pass-111,n1",
                "Битая-фф,https://bad.example,u2,,n2");

        // failFast: InvalidCsvException пробрасывается → flash + redirect (не 500);
        // транзакция сервиса откатывается — ничего не создано
        MvcResult result = performImport(session, content, "skip", false, true);
        assertThat(result.getResponse().getStatus()).isEqualTo(302);
        assertThat(result.getFlashMap().get("flashError").toString())
                .contains("Не удалось разобрать CSV");

        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isZero();
    }

    @Test
    void importPostWithoutCsrfTokenIsRejected() throws Exception {
        registerUser("importcsrf");
        var session = login("importcsrf");
        mockMvc.perform(multipart("/web/entries/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv",
                                csv(CSV_HEADER, "x,https://x.example,u,p,n")))
                        .session(session))
                .andExpect(status().isForbidden());
    }

    @Test
    void importGarbageFileShowsFlashAndRedirectsNot500() throws Exception {
        registerUser("importjunk");
        var session = login("importjunk");
        // Битый файл + строгий режим: сервис пробрасывает InvalidCsvException
        // (при failFast=false он сам погасит её в отчёт с ошибкой уровня файла).
        // Проверяем контроллерный flash-путь: 3xx + сообщение, не 500.
        byte[] garbage = new byte[]{(byte) 0xFF, (byte) 0xFE, 0x00, 0x01, 0x02};
        mockMvc.perform(multipart("/web/entries/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "junk.csv", "text/csv", garbage))
                        .param("failFast", "true")
                        .with(csrf())
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/import"))
                .andExpect(flash().attribute("flashError",
                        org.hamcrest.Matchers.containsString("Не удалось разобрать CSV")));
    }

    @Test
    void importGarbageWithoutFailFastRendersReportWithFileErrorNot500() throws Exception {
        registerUser("importjunk2");
        var session = login("importjunk2");
        // Одноколоночный «заголовок»: без failFast сервис гасит ошибку
        // уровня файла в отчёт → PRG → отчёт с failed=1
        byte[] garbage = "not a csv at all".getBytes(StandardCharsets.UTF_8);
        String html = importReportHtml(session, garbage, "skip", false, false);
        assertThat(html).contains("data-metric=\"failed\">1<");
    }

    // -- TP-фиксы фазы 3 ---------------------------------------------------------

    @Test
    void importPageAnonymousRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/web/entries/import"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
    }

    @Test
    void importEmptyFileShowsFlashAndRedirectsNot500() throws Exception {
        registerUser("importempty");
        var session = login("importempty");
        mockMvc.perform(multipart("/web/entries/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "empty.csv", "text/csv", new byte[0]))
                        .with(csrf())
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/import"))
                .andExpect(flash().attribute("flashError",
                        org.hamcrest.Matchers.containsString("Не удалось")));
    }

    @Test
    void importHeaderOnlyCsvRendersEmptyReport() throws Exception {
        registerUser("importheader");
        var session = login("importheader");
        MvcResult report = performImport(session, csv(CSV_HEADER), "skip", false, false);
        assertThat(report.getResponse().getStatus()).isEqualTo(302);
        MvcResult reportGet = mockMvc.perform(get("/web/entries/import/report")
                        .session(session))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(html(reportGet)).contains("data-metric=\"total\">0<");
        assertThat(html(reportGet)).contains("data-metric=\"created\">0<");
    }

    @Test
    void exportEmptyVaultReturnsHeaderOnlyCsvWithWarning() throws Exception {
        registerUser("exportempty");
        var session = login("exportempty");
        MvcResult result = mockMvc.perform(get("/web/entries/export").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(header().string("X-Vault-Export-Warning",
                        "csv-contains-plaintext-passwords"))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("attachment")))
                .andReturn();
        String body = new String(result.getResponse().getContentAsByteArray(),
                StandardCharsets.UTF_8).trim();
        // Header-only: ровно строка заголовка и ничего больше
        assertThat(body).isEqualTo(CSV_HEADER);
    }

    // -- PRG: F5-безопасность (Фаза 4) -------------------------------------------

    @Test
    void importReportGetWithoutFlashRedirectsToForm() throws Exception {
        registerUser("f5user");
        var session = login("f5user");
        // Прямой GET отчёта без предшествующего POST (F5/закладка) — на форму
        mockMvc.perform(get("/web/entries/import/report").session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/import"));
    }

    // -- Фаза 4: админ CSV export/import -----------------------------------------

    @Test
    void adminExportCsvTargetsUserVaultWithVaultUserFilename() throws Exception {
        registerUser("adm-target");
        var targetSession = login("adm-target");
        createEntry(targetSession, "Целевая-запись");
        createAdmin("adm-exporter");
        var adminSession = login("adm-exporter");
        createEntry(adminSession, "Запись-админа");

        MvcResult result = mockMvc.perform(get("/web/admin/users/"
                        + userIdOf("adm-target") + "/vault/export")
                        .session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/csv"))
                .andExpect(header().string("Content-Disposition",
                        org.hamcrest.Matchers.containsString("vault-user-")))
                .andReturn();
        String body = new String(result.getResponse().getContentAsByteArray(),
                StandardCharsets.UTF_8);
        assertThat(body).contains("Целевая-запись");
        // Записи самого админа в чужой экспорт не попадают
        assertThat(body).doesNotContain("Запись-админа");
    }

    @Test
    void nonAdminForbiddenOnAdminVaultExport() throws Exception {
        registerUser("plainexporter");
        registerUser("exportvictim");
        var plainSession = login("plainexporter");

        mockMvc.perform(get("/web/admin/users/"
                        + userIdOf("exportvictim") + "/vault/export")
                        .session(plainSession))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminExportUnknownUserShowsFlashAndRedirects() throws Exception {
        createAdmin("adm-unknown");
        var adminSession = login("adm-unknown");

        mockMvc.perform(get("/web/admin/users/" + UUID.randomUUID() + "/vault/export")
                        .session(adminSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/users"))
                .andExpect(flash().attribute("flashError", "Пользователь не найден"));
    }

    @Test
    void adminImportCreatesEntriesForTargetUser() throws Exception {
        registerUser("adm-imp-target");
        createAdmin("adm-importer");
        var adminSession = login("adm-importer");
        UUID targetId = userIdOf("adm-imp-target");

        byte[] content = csv(CSV_HEADER,
                "Админ-импорт-1,https://ai1.example,u1,Pass-111,n1",
                "Админ-импорт-2,https://ai2.example,u2,Pass-222,n2");
        mockMvc.perform(multipart("/web/admin/users/" + targetId + "/vault/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv", content))
                        .param("conflictStrategy", "skip")
                        .with(csrf())
                        .session(adminSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(
                        "/web/admin/users/" + targetId + "/vault/import/report"));

        mockMvc.perform(get("/web/admin/users/" + targetId + "/vault/import/report")
                        .session(adminSession))
                .andExpect(status().isOk())
                .andExpect(view().name("import-report"))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-metric=\"created\">2<")));

        // Записи появились именно у target
        var targetSession = login("adm-imp-target");
        mockMvc.perform(get("/web/entries").session(targetSession))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Админ-импорт-1")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Админ-импорт-2")));
    }

    @Test
    void adminImportDryRunChangesNothingForTarget() throws Exception {
        registerUser("adm-dry-target");
        createAdmin("adm-dry-admin");
        var adminSession = login("adm-dry-admin");
        UUID targetId = userIdOf("adm-dry-target");

        byte[] content = csv(CSV_HEADER,
                "Драй-админ,https://dry-admin.example,u1,Pass-111,n1");
        mockMvc.perform(multipart("/web/admin/users/" + targetId + "/vault/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv", content))
                        .param("conflictStrategy", "skip")
                        .param("dryRun", "true")
                        .with(csrf())
                        .session(adminSession))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/web/admin/users/" + targetId + "/vault/import/report")
                        .session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-metric=\"created\">1<")));

        // У target ничего не изменилось
        var targetSession = login("adm-dry-target");
        mockMvc.perform(get("/web/entries").session(targetSession))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    // -- Фаза 5: тест-харднинг ------------------------------------------------------

    @Test
    void adminReportGetWithoutFlashRedirectsToAdminImportForm() throws Exception {
        registerUser("adm-rep-target");
        createAdmin("adm-rep-admin");
        var adminSession = login("adm-rep-admin");
        UUID targetId = userIdOf("adm-rep-target");
        mockMvc.perform(get("/web/admin/users/" + targetId + "/vault/import/report")
                        .session(adminSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(
                        "/web/admin/users/" + targetId + "/vault/import"));
    }

    @Test
    void adminImportUnknownUserShowsFlashAndRedirects() throws Exception {
        createAdmin("adm-unk2");
        var adminSession = login("adm-unk2");
        byte[] content = csv(CSV_HEADER, "X,https://x.example,u,p,n");
        mockMvc.perform(multipart("/web/admin/users/" + UUID.randomUUID() + "/vault/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv", content))
                        .param("conflictStrategy", "skip")
                        .with(csrf())
                        .session(adminSession))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/users"))
                .andExpect(flash().attribute("flashError", "Пользователь не найден"));
    }

    @Test
    void adminCanExportAndImportDisabledUserVault() throws Exception {
        registerUser("adm-disabled");
        var targetSession = login("adm-disabled");
        createEntry(targetSession, "Заблокированная-запись");
        createAdmin("adm-support");
        var adminSession = login("adm-support");
        UUID targetId = userIdOf("adm-disabled");

        // Блокируем target через AdminService (аудит USER_DISABLED пишется)
        var adminEntity = userRepository.findByUsername("adm-support").orElseThrow();
        adminService.disableUser(targetId, adminEntity);

        // B4: экспорт сейфа отключённого пользователя — легитимный
        // support-сценарий (ROLE_ADMIN + аудит с actor/target)
        mockMvc.perform(get("/web/admin/users/" + targetId + "/vault/export")
                        .session(adminSession))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Заблокированная-запись")));

        // Импорт в его сейф тоже работает (логин target заблокирован —
        // проверяем через репозиторий)
        byte[] content = csv(CSV_HEADER, "Импорт-отключ,https://off.example,u1,Pass-111,n1");
        mockMvc.perform(multipart("/web/admin/users/" + targetId + "/vault/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "test.csv", "text/csv", content))
                        .param("conflictStrategy", "skip")
                        .with(csrf())
                        .session(adminSession))
                .andExpect(status().is3xxRedirection());
        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isEqualTo(2);
    }

    @Test
    void renameTagToExistingNameShowsFlashButCaseOnlyRenameSucceeds() throws Exception {
        registerUser("renameclash");
        var session = login("renameclash");
        createTag(session, "personal");
        createTag(session, "work");
        // firstTagId — по nameLower: personal первый
        String tagId = firstTagId(session);

        // Переименование в занятое имя (другой регистр) → flash-ошибка
        mockMvc.perform(post("/web/tags/" + tagId + "/rename")
                        .session(session).with(csrf()).param("name", "WORK"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashError", "Тег уже существует"));

        // Case-only переименование того же тега — успех (не конфликт сам с собой)
        mockMvc.perform(post("/web/tags/" + tagId + "/rename")
                        .session(session).with(csrf()).param("name", "Personal"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashMessage", "Тег переименован"));
        mockMvc.perform(get("/web/tags").session(session))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Personal")));
        assertThat(userTagCount("renameclash")).isEqualTo(2);
    }

    @Test
    void importCsvWithExtraTagsColumnIgnoresItSilently() throws Exception {
        registerUser("tagcol");
        var session = login("tagcol");
        // 6-я колонка tags — лишние колонки после 5-й тихо отбрасываются
        byte[] content = csv("name,url,username,password,note,tags",
                "Тегоколонка,https://tags.example,u1,Pass-111,n1,sometag");
        String html = importReportHtml(session, content, "skip", false, false);
        assertThat(html).contains("data-metric=\"created\">1<");
        // Теги из CSV не создаются
        assertThat(userTagCount("tagcol")).isZero();
    }

    @Test
    void importRejectsWhenCumulativeCapExceeded() throws Exception {
        registerUser("capuser");
        var session = login("capuser");
        createEntry(session, "Существующая");
        // 1 существующая + 10000 строк = 10001 > MAX_EXPORT_ROWS (10000):
        // консервативный пре-чек отклоняет весь импорт ДО обработки
        StringBuilder rows = new StringBuilder(CSV_HEADER).append("\r\n");
        for (int i = 0; i < 10_000; i++) {
            rows.append("Кап-").append(i).append(",https://cap.example,u")
                    .append(i).append(",Pass-").append(i).append(",\r\n");
        }
        MvcResult post = performImport(session,
                rows.toString().getBytes(StandardCharsets.UTF_8), "skip", false, false);
        assertThat(post.getResponse().getStatus()).isEqualTo(302);
        assertThat(post.getResponse().getHeader("Location"))
                .isEqualTo("/web/entries/import");
        assertThat(String.valueOf(post.getFlashMap().get("flashError")))
                .contains("10 МБ");
        long count = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        assertThat(count).isEqualTo(1);
    }

    @Test
    void tagFilterWithGarbageShowsEmptyPageNot500() throws Exception {
        registerUser("taggarbage");
        var session = login("taggarbage");
        createEntry(session, "Обычная-запись");
        mockMvc.perform(get("/web/entries")
                        .param("tag", "%%%мусор%%%").session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("entries"))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    @Test
    void tagFilterWithUnknownUuidShowsEmptyPage() throws Exception {
        registerUser("tagunknown");
        var session = login("tagunknown");
        createEntry(session, "Обычная-запись");
        mockMvc.perform(get("/web/entries")
                        .param("tag", UUID.randomUUID().toString()).session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    @Test
    void pageBeyondRangeClampsToLastPage() throws Exception {
        registerUser("paginator");
        var session = login("paginator");
        for (int i = 0; i <= 20; i++) {
            createEntry(session, "Пагинация-" + i);
        }
        // 21 запись / 20 на страницу → 2 страницы; page=999 → кламп к последней
        mockMvc.perform(get("/web/entries")
                        .param("page", "999").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Пагинация-20")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("2 / 2")));
    }

    // -- Фаза 5 (fix B12): E2E web-smoke round-trip -------------------------

    @Test
    void fullRoundTripExportDeleteImportReveal() throws Exception {
        registerUser("roundtrip");
        var session = login("roundtrip");
        String marker = "RoundTrip-Marker-9k7p!";

        // Создание записи с уникальным паролем-маркером
        mockMvc.perform(post("/web/entries")
                        .session(session)
                        .with(csrf())
                        .param("name", "Раундтрип")
                        .param("site", "https://roundtrip.example")
                        .param("login", "rt-user")
                        .param("password", marker)
                        .param("notes", "rt-note"))
                .andExpect(status().is3xxRedirection());
        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        java.util.regex.Matcher m = UUID_PATH.matcher(html(list));
        assertThat(m.find()).as("round-trip entry link").isTrue();
        String entryId = m.group(1);

        // Экспорт (без BOM)
        byte[] csvBytes = mockMvc.perform(get("/web/entries/export").session(session))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray();

        // Удаление записи
        mockMvc.perform(post("/web/entries/" + entryId + "/delete")
                        .session(session).with(csrf()))
                .andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/web/entries").session(session))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));

        // Импорт того же CSV → создана 1 запись (PRG + отчёт)
        mockMvc.perform(multipart("/web/entries/import")
                        .file(new org.springframework.mock.web.MockMultipartFile(
                                "file", "roundtrip.csv", "text/csv", csvBytes))
                        .param("conflictStrategy", "skip")
                        .with(csrf())
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries/import/report"));
        mockMvc.perform(get("/web/entries/import/report").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-metric=\"created\">1<")));

        // Новый id записи
        MvcResult list2 = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        java.util.regex.Matcher m2 = UUID_PATH.matcher(html(list2));
        assertThat(m2.find()).as("re-imported entry link").isTrue();
        String newId = m2.group(1);

        // Reveal: исходный пароль-маркер пережил экспорт → импорт
        mockMvc.perform(post("/web/entries/" + newId + "/reveal")
                        .session(session).with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString(marker)));
    }

    // -- Фаза 6: явный select-фильтр по тегу ----------------------------------

    /** (a) Select присутствует с опциями созданных тегов (label = name (N)). */
    @Test
    void selectFilterShowsUserTagsWithCounts() throws Exception {
        registerUser("selfilter");
        var session = login("selfilter");
        String entryId = createEntry(session, "Фильтр-запись");
        createTag(session, "work");
        createTag(session, "home");
        mockMvc.perform(post("/web/entries/" + entryId + "/tags")
                        .session(session).with(csrf()).param("tagName", "work"))
                .andExpect(status().is3xxRedirection());

        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        String html = html(list);
        assertThat(html).contains("Все теги");
        assertThat(html).contains("work (1)");
        assertThat(html).contains("home (0)");
        // (F5) Опции отсортированы по name_lower: home < work
        assertThat(html.indexOf("home (0)")).isLessThan(html.indexOf("work (1)"));
    }

    /** (b)+(d) Выбор тега → отфильтрованный список; select отражает выбор. */
    @Test
    void selectFilterAppliesAndReflectsSelection() throws Exception {
        registerUser("selfilter2");
        var session = login("selfilter2");
        String tagged = createEntry(session, "Помеченная-селект");
        createEntry(session, "Непомеченная-селект");
        createTag(session, "only");
        mockMvc.perform(post("/web/entries/" + tagged + "/tags")
                        .session(session).with(csrf()).param("tagName", "only"))
                .andExpect(status().is3xxRedirection());

        // Выбор тега (submit GET-формы = GET ?tag=<id>) → только помеченная
        String tagId = firstTagId(session);
        MvcResult filtered = mockMvc.perform(get("/web/entries")
                        .session(session).param("tag", tagId))
                .andExpect(status().isOk())
                .andReturn();
        String html = html(filtered);
        assertThat(html).contains("Помеченная-селект");
        assertThat(html).doesNotContain("Непомеченная-селект");
        // (d/A3) th:selected отражает активный фильтр: selected сразу после value
        // (пробелы нормализуем — Thymeleaf сохраняет переносы между атрибутами)
        assertThat(html.replaceAll("\\s+", ""))
                .contains("value=\"" + tagId + "\"selected");
        assertThat(html).contains("only (1)");
    }

    /** (c) «Все теги» (пустой tag) → полный список, без индикатора фильтра. */
    @Test
    void selectFilterAllTagsShowsFullListWithoutIndicator() throws Exception {
        registerUser("selfilter3");
        var session = login("selfilter3");
        String tagged = createEntry(session, "Селект-вторая");
        createEntry(session, "Селект-первая");
        createTag(session, "mark");
        mockMvc.perform(post("/web/entries/" + tagged + "/tags")
                        .session(session).with(csrf()).param("tagName", "mark"))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/web/entries")
                        .session(session).param("tag", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Селект-вторая")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Селект-первая")))
                // Индикатор «Тег: ✕» не рендерится — фильтр не активен
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("tag-filter\""))));
    }

    /** (e) У пользователя без тегов select не рендерится. */
    @Test
    void selectFilterAbsentForUserWithoutTags() throws Exception {
        registerUser("selfilter4");
        var session = login("selfilter4");
        createEntry(session, "Без-тегов");
        mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("tag-filter-form"))));
    }

    /** (F1-i) Чужой tagId: подсказка, без индикатора, пустой список. */
    @Test
    void tagFilterWithForeignTagIdShowsHintAndEmptyList() throws Exception {
        registerUser("tagowner1");
        var ownerSession = login("tagowner1");
        createTag(ownerSession, "foreign");
        String foreignTagId = firstTagId(ownerSession);

        registerUser("taguser2");
        var session = login("taguser2");
        createEntry(session, "Моя-запись");

        mockMvc.perform(get("/web/entries")
                        .session(session).param("tag", foreignTagId))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Тег не найден")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("class=\"tag-filter\""))))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    /** (F1-ii) Удалённый tagId: то же поведение, что у чужого. */
    @Test
    void tagFilterWithDeletedTagIdShowsHintAndEmptyList() throws Exception {
        registerUser("tagdeleter");
        var session = login("tagdeleter");
        createEntry(session, "Моя-запись");
        createTag(session, "gone");
        String tagId = firstTagId(session);
        mockMvc.perform(post("/web/tags/" + tagId + "/delete")
                        .session(session).with(csrf()))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/web/entries")
                        .session(session).param("tag", tagId))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Тег не найден")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.not(
                                org.hamcrest.Matchers.containsString("class=\"tag-filter\""))))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Записей пока нет")));
    }
}
