package com.example.safeaccounts.it;

import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

/**
 * Интеграционные тесты веб-интерфейса (Task-11).
 * PostgreSQL поднимается через Testcontainers; учетные данные — синтетические
 * тестовые значения только в тестовом профиле (AGENTS.md).
 * <p>
 * Критерии приемки Task-11:
 * 1. Можно войти через браузер.
 * 2. Можно создать/посмотреть/изменить/удалить запись.
 * 3. Чужие записи недоступны.
 * 4. CSRF защита работает.
 * 5. Веб-интерфейс не ломает API.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class WebUiIT {

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
    AuditEventRepository auditEventRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    TransactionTemplate transactionTemplate;

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

    /** Регистрирует пользователя через API и возвращает имя. */
    private String registerUser(String username) throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content("{\"username\":\"%s\",\"password\":\"%s\"}"
                                .formatted(username, PASSWORD)))
                .andExpect(status().isCreated());
        return username;
    }

    /** Регистрирует и логинится через веб-форму; возвращает сессию. */
    private MvcResult loginViaWeb(String username) throws Exception {
        return mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"))
                .andReturn();
    }

    // -- 1. Логин через браузер -------------------------------------------------


    @Test
    void loginPageIsPublic() throws Exception {
        mockMvc.perform(get("/web/login"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("safe-accounts")));
    }

    @Test
    void rootShowsLoginPageForUnauthenticated() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().isOk())
                .andExpect(view().name("login"));
    }

    @Test
    void loginSuccessCreatesSessionAndRedirectsToEntries() throws Exception {
        registerUser("webuser1");
        mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", "webuser1")
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"));
    }

    @Test
    void loginFailureShowsNeutralError() throws Exception {
        registerUser("webuser2");
        mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", "webuser2")
                        .param("password", "Wr0ng-Passw0rd!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/login?error"));

        // Страница с ошибкой рендерится и не раскрывает причину.
        mockMvc.perform(get("/web/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Неверное имя пользователя или пароль")));
    }

    @Test
    void logoutInvalidatesSession() throws Exception {
        registerUser("webuser3");
        MvcResult login = loginViaWeb("webuser3");
        MvcResult logout = mockMvc.perform(get("/logout")
                        .session((org.springframework.mock.web.MockHttpSession) login.getRequest().getSession())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/login?logout"))
                .andReturn();

        // После выхода защищенная страница снова требует логин.
        mockMvc.perform(get("/web/entries")
                        .session((org.springframework.mock.web.MockHttpSession) logout.getRequest().getSession()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
    }

    /**
     * Баг-фикс: форма выхода в шаблонах отправляет POST /logout с CSRF-токеном;
     * раньше POST попадал только в GET-маппинг контроллера и падал с 500.
     */
    @Test
    void logoutViaHttpPostFormRedirectsToLoginAndInvalidatesSession() throws Exception {
        registerUser("webuser4");
        MvcResult login = loginViaWeb("webuser4");

        MvcResult logout = mockMvc.perform(post("/logout")
                        .session((org.springframework.mock.web.MockHttpSession) login.getRequest().getSession())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/login?logout"))
                .andReturn();

        // Повторный доступ с той же сессией запрещен: редирект на логин.
        mockMvc.perform(get("/web/entries")
                        .session((org.springframework.mock.web.MockHttpSession) logout.getRequest().getSession()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
    }

    /** POST /logout без CSRF-токена отклоняется (CSRF-защита сохранена). */
    @Test
    void logoutWithoutCsrfTokenIsRejected() throws Exception {
        registerUser("webuser5");
        MvcResult login = loginViaWeb("webuser5");

        mockMvc.perform(post("/logout")
                        .session((org.springframework.mock.web.MockHttpSession) login.getRequest().getSession()))
                .andExpect(status().isForbidden());
    }

    // -- 2. CRUD записей через веб ----------------------------------------------

    private MvcResult createEntry(MockHttpSessionHolder session, String site,
                                  String login, String password) throws Exception {
        return mockMvc.perform(post("/web/entries")
                        .session(session.session())
                        .with(csrf())
                        .param("site", site)
                        .param("login", login)
                        .param("password", password)
                        .param("notes", "note-value"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"))
                .andReturn();
    }

    /** Обертка над MockHttpSession для удобной передачи в хелперы. */
    static final class MockHttpSessionHolder {
        private final org.springframework.mock.web.MockHttpSession session;

        MockHttpSessionHolder(org.springframework.mock.web.MockHttpSession session) {
            this.session = session;
        }

        org.springframework.mock.web.MockHttpSession session() {
            return session;
        }
    }

    private MockHttpSessionHolder login(String username) throws Exception {
        MvcResult loginResult = loginViaWeb(username);
        return new MockHttpSessionHolder(
                (org.springframework.mock.web.MockHttpSession) loginResult.getRequest().getSession());
    }

    private String firstEntryId(MockHttpSessionHolder holder) throws Exception {
        MvcResult list = mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("entries"))
                .andReturn();
        String html = list.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        // Извлекаем id из ссылки на просмотр записи /web/entries/{uuid}
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("/web/entries/([0-9a-fA-F-]{36})")
                .matcher(html);
        assertThat(matcher.find()).as("entry link in list").isTrue();
        return matcher.group(1);
    }

    @Test
    void fullCrudCycleThroughWeb() throws Exception {
        registerUser("webcrud");
        MockHttpSessionHolder holder = login("webcrud");

        // CREATE
        createEntry(holder, "https://example.com", "alice", ENTRY_PASSWORD);

        // LIST: пароль в списке отсутствует
        MvcResult list = mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        String id = firstEntryId(holder);

        // VIEW: пароль скрыт по умолчанию
        MvcResult view = mockMvc.perform(get("/web/entries/" + id).session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("entry-view"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        // REVEAL: пароль показывается только по явному действию
        mockMvc.perform(post("/web/entries/" + id + "/reveal")
                        .session(holder.session())
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(ENTRY_PASSWORD)));

        // EDIT: старый пароль не подставляется в форму
        MvcResult editForm = mockMvc.perform(get("/web/entries/" + id + "/edit")
                        .session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        // UPDATE
        mockMvc.perform(post("/web/entries/" + id + "/edit")
                        .session(holder.session())
                        .with(csrf())
                        .param("site", "https://example.com")
                        .param("login", "alice")
                        .param("password", "New-Pass-456!")
                        .param("notes", "updated"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"));

        // Пароль после обновления — новый
        mockMvc.perform(post("/web/entries/" + id + "/reveal")
                        .session(holder.session())
                        .with(csrf()))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("New-Pass-456!")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))));

        // DELETE
        mockMvc.perform(post("/web/entries/" + id + "/delete")
                        .session(holder.session())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"));

        mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    // -- 3. Чужие записи недоступны ----------------------------------------------

    @Test
    void otherUsersEntriesNotAccessible() throws Exception {
        registerUser("webowner");
        registerUser("webintruder");

        MockHttpSessionHolder owner = login("webowner");
        createEntry(owner, "https://secret.example", "owner", ENTRY_PASSWORD);
        String id = firstEntryId(owner);

        // Чужой пользователь не видит запись ни в списке...
        MockHttpSessionHolder intruder = login("webintruder");
        MvcResult list = mockMvc.perform(get("/web/entries").session(intruder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Записей пока нет")))
                .andReturn();

        // ...ни в просмотре (404-подобный нейтральный ответ), ни в reveal,
        // ни в edit, ни в delete.
        mockMvc.perform(get("/web/entries/" + id).session(intruder.session()))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/web/entries/" + id + "/reveal")
                        .session(intruder.session())
                        .with(csrf()))
                .andExpect(status().isNotFound());
        mockMvc.perform(get("/web/entries/" + id + "/edit").session(intruder.session()))
                .andExpect(status().isNotFound());
        mockMvc.perform(post("/web/entries/" + id + "/delete")
                        .session(intruder.session())
                        .with(csrf()))
                .andExpect(status().isNotFound());
    }

    @Test
    void unauthenticatedAccessRedirectsToLogin() throws Exception {
        mockMvc.perform(get("/web/entries"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
        mockMvc.perform(get("/web/entries/new"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
    }

    // -- 4. CSRF ------------------------------------------------------------------

    @Test
    void postWithoutCsrfTokenIsRejected() throws Exception {
        registerUser("webcsrf");
        MockHttpSessionHolder holder = login("webcsrf");

        // POST без CSRF-токена отклоняется (403).
        mockMvc.perform(post("/web/entries")
                        .session(holder.session())
                        .param("site", "https://x.example")
                        .param("login", "a")
                        .param("password", ENTRY_PASSWORD))
                .andExpect(status().isForbidden());

        // CSRF также защищает логин-форму.
        mockMvc.perform(post("/web/login")
                        .param("username", "webcsrf")
                        .param("password", PASSWORD))
                .andExpect(status().isForbidden());
    }

    @Test
    void csrfTokenAvailableOnFormPages() throws Exception {
        registerUser("webform");
        MockHttpSessionHolder holder = login("webform");

        MvcResult form = mockMvc.perform(get("/web/entries/new").session(holder.session()))
                .andExpect(status().isOk())
                .andReturn();
        String html = form.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        // В форме логина и формах записей присутствует скрытый CSRF-инпут.
        assertThat(html).contains("_csrf");
    }

    // -- 5. API не сломан ----------------------------------------------------------

    @Test
    void apiStillWorksWithBearerTokenWhileWebUsesSession() throws Exception {
        // Регистрация + API-логин с выпуском Bearer-токена — как раньше (Task-04).
        registerUser("mixeduser");
        String token = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"username\":\"mixeduser\",\"password\":\"%s\"}".formatted(PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        token = com.fasterxml.jackson.databind.json.JsonMapper.builder().build()
                .readTree(token).get("accessToken").asText();

        // Bearer-доступ к API: CSRF не требуется, сессия не создается.
        mockMvc.perform(post("/api/vault")
                        .header("Authorization", "Bearer " + token)
                        .contentType("application/json")
                        .content("{\"site\":\"https://api.example\",\"login\":\"api\","
                                + "\"password\":\"%s\",\"notes\":null}".formatted(ENTRY_PASSWORD)))
                .andExpect(status().isCreated());

        mockMvc.perform(get("/api/vault")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // API остался stateless: POST без Bearer-токена — 401, а не redirect на веб-логин.
        mockMvc.perform(post("/api/vault")
                        .contentType("application/json")
                        .content("{\"site\":\"x\",\"login\":\"y\",\"password\":\"z\"}"))
                .andExpect(status().isUnauthorized());
    }
}
