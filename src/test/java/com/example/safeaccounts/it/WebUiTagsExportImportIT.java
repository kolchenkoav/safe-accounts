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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
                tagRepository.findAllByUser_Id(userIdOf(username)).size());
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
                .andExpect(flash().attribute("flashMessage", "Тег снят с записи"));

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
}
