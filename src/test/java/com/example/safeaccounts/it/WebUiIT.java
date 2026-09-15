package com.example.safeaccounts.it;

import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.example.safeaccounts.service.UserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
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
    @Autowired
    UserService userService;

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
        return loginViaWeb(username, PASSWORD);
    }

    /** Логинится через веб-форму с указанным паролем; возвращает результат. */
    private MvcResult loginViaWeb(String username, String password) throws Exception {
        return mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", password))
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

    private MvcResult createEntry(MockHttpSessionHolder session, String name, String site,
                                  String login, String password) throws Exception {
        return mockMvc.perform(post("/web/entries")
                        .session(session.session())
                        .with(csrf())
                        .param("name", name)
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

        // CREATE (поле name обязательно — Фаза 1)
        createEntry(holder, "Моя запись", "https://example.com", "alice", ENTRY_PASSWORD);

        // LIST: name виден в списке, пароль в списке отсутствует
        MvcResult list = mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Моя запись")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        String id = firstEntryId(holder);

        // VIEW: пароль скрыт по умолчанию
        MvcResult view = mockMvc.perform(get("/web/entries/" + id).session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("entry-view"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Моя запись")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        // REVEAL: пароль показывается только по явному действию
        mockMvc.perform(post("/web/entries/" + id + "/reveal")
                        .session(holder.session())
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(ENTRY_PASSWORD)));

        // EDIT: форма предзаполнена текущим name, старый пароль не подставляется
        MvcResult editForm = mockMvc.perform(get("/web/entries/" + id + "/edit")
                        .session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Моя запись")))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(ENTRY_PASSWORD))))
                .andReturn();

        // UPDATE: меняется и name
        mockMvc.perform(post("/web/entries/" + id + "/edit")
                        .session(holder.session())
                        .with(csrf())
                        .param("name", "Переименованная запись")
                        .param("site", "https://example.com")
                        .param("login", "alice")
                        .param("password", "New-Pass-456!")
                        .param("notes", "updated"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"));

        // После обновления на карточке — новое name и новый пароль, старого пароля нет
        mockMvc.perform(post("/web/entries/" + id + "/reveal")
                        .session(holder.session())
                        .with(csrf()))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Переименованная запись")))
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

    /**
     * Поле «Название» обязательно (Фаза 1): сабмит без name не создает запись
     * и не падает 500 — форма перерисовывается с ошибкой валидации.
     */
    @Test
    void createWithoutNameShowsValidationErrorAndDoesNotCreateEntry() throws Exception {
        registerUser("webnoname");
        MockHttpSessionHolder holder = login("webnoname");

        // POST без name: не 500, форма перерисовывается с ошибкой валидации.
        mockMvc.perform(post("/web/entries")
                        .session(holder.session())
                        .with(csrf())
                        .param("site", "https://example.com")
                        .param("login", "alice")
                        .param("password", ENTRY_PASSWORD)
                        .param("notes", "note-value"))
                .andExpect(status().isOk())
                .andExpect(view().name("entry-form"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("alert-error")));

        // Запись не создана.
        mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Записей пока нет")));
    }

    // -- 3. Чужие записи недоступны ----------------------------------------------

    @Test
    void otherUsersEntriesNotAccessible() throws Exception {
        registerUser("webowner");
        registerUser("webintruder");

        MockHttpSessionHolder owner = login("webowner");
        createEntry(owner, "Чужая запись", "https://secret.example", "owner", ENTRY_PASSWORD);
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
                    .content("{\"name\":\"API запись\",\"site\":\"https://api.example\",\"login\":\"api\","
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

    // -- 6. Веб-раздел администратора (Task-12) ----------------------------------

    /** Создает администратора напрямую через UserService (для веб-админки). */
    private String createAdmin(String username) {
        userService.register(username, PASSWORD, "ROLE_ADMIN");
        return username;
    }

    private UUID userIdOf(String username) {
        return userRepository.findByUsername(username).orElseThrow().getId();
    }

    /** Админ видит раздел админки и ссылку «Админка» в навигации. */
    @Test
    void adminSeesAdminSectionAndNavLink() throws Exception {
        createAdmin("webadm1");
        MockHttpSessionHolder admin = login("webadm1");

        mockMvc.perform(get("/web/entries").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("/web/admin/users")));

        mockMvc.perform(get("/web/admin/users").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-users"))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("Создать пользователя")));
        mockMvc.perform(get("/web/admin/audit").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-audit"));
        mockMvc.perform(get("/web/admin/crypto").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-crypto"));
    }

    /** Обычному пользователю раздел недоступен (403), ссылки в навигации нет. */
    @Test
    void regularUserGetsForbiddenOnAdminPagesAndSeesNoNavLink() throws Exception {
        registerUser("webplain1");
        MockHttpSessionHolder user = login("webplain1");

        mockMvc.perform(get("/web/entries").session(user.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("/web/admin/users"))));

        mockMvc.perform(get("/web/admin/users").session(user.session()))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/web/admin/audit").session(user.session()))
                .andExpect(status().isForbidden());
        // POST-формы админки тоже закрыты.
        mockMvc.perform(post("/web/admin/users")
                        .session(user.session())
                        .with(csrf())
                        .param("username", "hax")
                        .param("password", PASSWORD)
                        .param("role", "ROLE_ADMIN"))
                .andExpect(status().isForbidden());
    }

    /** Аноним перенаправляется на логин, а не получает 403. */
    @Test
    void anonymousIsRedirectedToLoginForAdminPages() throws Exception {
        mockMvc.perform(get("/web/admin/users"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
        mockMvc.perform(get("/web/admin/audit"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
        mockMvc.perform(get("/web/admin/crypto"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/web/login"));
    }

    /** Создание пользователя через форму: новый пользователь может войти. */
    @Test
    void createUserViaWebFormThenNewUserCanLogin() throws Exception {
        createAdmin("webadm2");
        MockHttpSessionHolder admin = login("webadm2");

        mockMvc.perform(post("/web/admin/users")
                        .session(admin.session())
                        .with(csrf())
                        .param("username", "webcreated")
                        .param("password", PASSWORD)
                        .param("role", "ROLE_USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/users"))
                .andExpect(flash().attributeExists("flashMessage"));

        // Пароль никогда не возвращается в HTML страницы админки.
        mockMvc.perform(get("/web/admin/users").session(admin.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString(PASSWORD))));

        assertThat(auditEventRepository.findAll())
                .anyMatch(e -> "USER_CREATED_BY_ADMIN".equals(e.getType()));

        // Новый пользователь может залогиниться через веб.
        login("webcreated");
    }

    /** Disable блокирует вход, enable возвращает доступ. */
    @Test
    void disableBlocksLoginAndEnableRestoresAccess() throws Exception {
        registerUser("webtoggle");
        createAdmin("webadm3");
        MockHttpSessionHolder admin = login("webadm3");
        UUID id = userIdOf("webtoggle");

        mockMvc.perform(post("/web/admin/users/{id}/disable", id)
                        .session(admin.session())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/users"))
                .andExpect(flash().attributeExists("flashMessage"));

        // Отключенный пользователь не может войти (нейтральный редирект с ?error).
        mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", "webtoggle")
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/login?error"));

        mockMvc.perform(post("/web/admin/users/{id}/enable", id)
                        .session(admin.session())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        // Доступ возвращен.
        login("webtoggle");
    }

    /** Сброс пароля через форму: старый пароль не работает, новый работает. */
    @Test
    void resetPasswordViaWebInvalidatesOldPassword() throws Exception {
        registerUser("webreset");
        createAdmin("webadm4");
        MockHttpSessionHolder admin = login("webadm4");
        UUID id = userIdOf("webreset");

        mockMvc.perform(post("/web/admin/users/{id}/reset-password", id)
                        .session(admin.session())
                        .with(csrf())
                        .param("newPassword", "Br4nd-New-Pass!"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/users"))
                .andExpect(flash().attributeExists("flashMessage"));

        // Новый пароль не подставляется в HTML (никогда).
        mockMvc.perform(get("/web/admin/users").session(admin.session()))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("Br4nd-New-Pass!"))));

        assertThat(auditEventRepository.findAll())
                .anyMatch(e -> "USER_RESET_PASSWORD".equals(e.getType()));

        // Старый пароль больше не работает.
        mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", "webreset")
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/login?error"));

        // Новый пароль работает.
        loginViaWeb("webreset", "Br4nd-New-Pass!");
    }

    /** Смена роли: повышение дает доступ к админке; своя роль — нейтральный запрет. */
    @Test
    void changeRolePromotesUserAndBlocksSelfChange() throws Exception {
        registerUser("webpromote");
        createAdmin("webadm5");
        MockHttpSessionHolder admin = login("webadm5");
        UUID targetId = userIdOf("webpromote");
        UUID adminId = userIdOf("webadm5");

        // Повышение до ROLE_ADMIN.
        mockMvc.perform(post("/web/admin/users/{id}/change-role", targetId)
                        .session(admin.session())
                        .with(csrf())
                        .param("role", "ROLE_ADMIN"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attributeExists("flashMessage"));

        assertThat(userRepository.findById(targetId).orElseThrow().getRole())
                .isEqualTo("ROLE_ADMIN");
        assertThat(auditEventRepository.findAll())
                .anyMatch(e -> "USER_ROLE_CHANGED".equals(e.getType()));

        // Повышенный пользователь теперь видит раздел админки.
        MockHttpSessionHolder promoted = login("webpromote");
        mockMvc.perform(get("/web/admin/users").session(promoted.session()))
                .andExpect(status().isOk());

        // Смена СОБСТВЕННОЙ роли запрещена: нейтральная ошибка, роль не изменилась.
        mockMvc.perform(post("/web/admin/users/{id}/change-role", adminId)
                        .session(admin.session())
                        .with(csrf())
                        .param("role", "ROLE_USER"))
                .andExpect(status().is3xxRedirection())
                .andExpect(flash().attribute("flashError",
                        "Операция отклонена: нельзя изменить роль собственной учетной записи"));

        assertThat(userRepository.findById(adminId).orElseThrow().getRole())
                .isEqualTo("ROLE_ADMIN");
    }

    /** Страница аудита рендерится с фильтром type и действительно фильтрует. */
    @Test
    void auditPageRendersWithTypeFilter() throws Exception {
        createAdmin("webadm6");
        MockHttpSessionHolder admin = login("webadm6");

        // Логин админа уже записал LOGIN_SUCCESS; создаем пользователя — USER_CREATED_BY_ADMIN.
        mockMvc.perform(post("/web/admin/users")
                        .session(admin.session())
                        .with(csrf())
                        .param("username", "webaudit")
                        .param("password", PASSWORD)
                        .param("role", "ROLE_USER"))
                .andExpect(status().is3xxRedirection());

        mockMvc.perform(get("/web/admin/audit")
                        .session(admin.session())
                        .param("type", "USER_CREATED_BY_ADMIN"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin-audit"))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("USER_CREATED_BY_ADMIN")));

        // Фильтр работает: события другого типа в выдачу не попадают.
        MvcResult filtered = mockMvc.perform(get("/web/admin/audit")
                        .session(admin.session())
                        .param("type", "USER_CREATED_BY_ADMIN"))
                .andReturn();
        String html = filtered.getResponse()
                .getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        assertThat(html).doesNotContain("LOGIN_SUCCESS");
    }

    /** Rewrap DEKs через веб: результат в flash-сообщении + события KEY_ROTATION_*. */
    @Test
    void rewrapDeksViaWebReturnsResultAndWritesAudit() throws Exception {
        createAdmin("webadm7");
        MockHttpSessionHolder admin = login("webadm7");

        mockMvc.perform(post("/web/admin/crypto/rewrap-deks")
                        .session(admin.session())
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/admin/crypto"))
                .andExpect(flash().attributeExists("flashMessage"));

        assertThat(auditEventRepository.findAll())
                .anyMatch(e -> "KEY_ROTATION_STARTED".equals(e.getType()));
        assertThat(auditEventRepository.findAll())
                .anyMatch(e -> "KEY_ROTATION_COMPLETED".equals(e.getType()));
    }

    // -- Тема оформления: тёмная по умолчанию, светлая — opt-in ----------------

    /** На логине (без общей навигации) есть дефолтная тёмная тема и переключатель. */
    @Test
    void loginPageHasDarkThemeByDefaultAndThemeToggle() throws Exception {
        mockMvc.perform(get("/web/login"))
                .andExpect(status().isOk())
                // Тёмная тема — по умолчанию: атрибут задан в разметке
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-theme=\"dark\"")))
                // Тема применяется из <head> как можно раньше (анти-FOUC), без inline-скриптов
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("/web/theme.js")))
                // Кнопка-переключатель присутствует и на логине
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-theme-toggle")));
    }

    /** На странице записей есть дефолтная тёмная тема и кнопка-переключатель. */
    @Test
    void entriesPageHasDarkThemeByDefaultAndThemeToggle() throws Exception {
        registerUser("themuser");
        MockHttpSessionHolder session = login("themuser");
        mockMvc.perform(get("/web/entries").session(session.session()))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-theme=\"dark\"")))
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("data-theme-toggle")));
    }

    /** Скрипт темы отдается как статика без аутентификации (нужен на логине). */
    @Test
    void themeJsIsServedWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/web/theme.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(
                        org.hamcrest.Matchers.containsString("localStorage")));
    }

    // -- Отложенные фиксы фазы 1 (B2/B5) -----------------------------------------

    /**
     * Границы поля name (фикс B2): ровно 256 — создается; 257 и только
     * пробелы — повторный рендер формы (200 + alert-error), запись не создается.
     */
    @ParameterizedTest
    @MethodSource("entryNameBoundaryCases")
    void entryNameBoundaries(String name, boolean expectCreated) throws Exception {
        registerUser("namebounds");
        MockHttpSessionHolder holder = login("namebounds");

        MvcResult result = mockMvc.perform(post("/web/entries")
                        .session(holder.session())
                        .with(csrf())
                        .param("name", name)
                        .param("site", "https://example.com")
                        .param("login", "alice")
                        .param("password", ENTRY_PASSWORD)
                        .param("notes", ""))
                .andReturn();

        long entries = transactionTemplate.execute(tx -> vaultEntryRepository.count());
        if (expectCreated) {
            assertThat(result.getResponse().getStatus()).isEqualTo(302);
            assertThat(entries).isEqualTo(1);
        } else {
            assertThat(result.getResponse().getStatus()).isEqualTo(200);
            assertThat(htmlOf(result)).contains("alert-error");
            assertThat(entries).isZero();
        }
    }

    static java.util.stream.Stream<Arguments> entryNameBoundaryCases() {
        return java.util.stream.Stream.of(
                Arguments.of("x".repeat(256), true),
                Arguments.of("x".repeat(257), false),
                Arguments.of("   ", false)
        );
    }

    /**
     * XSS (фикс B5): name с "<script>" экранируется Thymeleaf в списке
     * и на карточке; сырого "<script>" в ответе нет.
     */
    @Test
    void entryNameWithScriptTagIsEscapedInHtml() throws Exception {
        registerUser("xssuser");
        MockHttpSessionHolder holder = login("xssuser");
        createEntry(holder, "<script>alert(1)</script>", "https://example.com",
                "alice", ENTRY_PASSWORD);

        MvcResult list = mockMvc.perform(get("/web/entries").session(holder.session()))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(htmlOf(list)).contains("&lt;script&gt;");
        assertThat(htmlOf(list)).doesNotContain("<script>");

        String id = firstEntryId(holder);
        MvcResult view = mockMvc.perform(get("/web/entries/" + id).session(holder.session()))
                .andExpect(status().isOk())
                .andReturn();
        assertThat(htmlOf(view)).contains("&lt;script&gt;");
        assertThat(htmlOf(view)).doesNotContain("<script>");
    }

    private static String htmlOf(MvcResult result)
            throws java.io.UnsupportedEncodingException {
        return result.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
    }
}
