package com.example.safeaccounts.it;

import com.microsoft.playwright.Browser;
import com.microsoft.playwright.BrowserContext;
import com.microsoft.playwright.BrowserType;
import com.microsoft.playwright.Page;
import com.microsoft.playwright.Playwright;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Минимальные браузерные E2E (опц. Фаза 3 плана
 * feat-password-generator-copy): реальный chromium headless против
 * RANDOM_PORT-инстанса. Никакого полного CRUD — только генератор и
 * копирование.
 *
 * <p><b>ВНИМАНИЕ:</b> первое использование Playwright скачивает браузеры
 * (~150 МБ в {@code %LOCALAPPDATA%\ms-playwright} / {@code ~/.cache/ms-playwright})
 * — нужен доступ к CDN Playwright.
 *
 * <p><b>Включение:</b> только при {@code BROWSER_E2E=true} (env) — обычный
 * {@code mvnw verify} и CI его не гоняют (в CI-образе нет браузеров и
 * зависимостей chromium). Локальный прогон:
 * {@code $env:BROWSER_E2E='true'; .\mvnw "-Dit.test=BrowserE2EIT" verify}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("it")
@Testcontainers
@EnabledIfEnvironmentVariable(named = "BROWSER_E2E", matches = "true")
@DisabledIfEnvironmentVariable(named = "CI", matches = ".*")
class BrowserE2EIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Typed-Entry-Pass-9!";

    @LocalServerPort
    int port;

    @Autowired
    TestRestTemplate rest;

    @Autowired
    TransactionTemplate transactionTemplate;

    @Autowired
    com.example.safeaccounts.repository.AuditEventRepository auditEventRepository;

    @Autowired
    com.example.safeaccounts.repository.VaultEntryRepository vaultEntryRepository;

    @Autowired
    com.example.safeaccounts.repository.UserRepository userRepository;

    static Playwright playwright;
    static Browser browser;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser = playwright.chromium()
                .launch(new BrowserType.LaunchOptions().setHeadless(true));
    }

    @AfterAll
    static void closeBrowser() {
        if (browser != null) {
            browser.close();
        }
        if (playwright != null) {
            playwright.close();
        }
    }

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
            vaultEntryRepository.deleteAll();
            userRepository.deleteAll();
        });
    }

    private String base() {
        return "http://localhost:" + port;
    }

    private void registerViaApi(String username) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        rest.postForEntity("/api/auth/register",
                new HttpEntity<>("{\"username\":\"" + username
                        + "\",\"password\":\"" + PASSWORD + "\"}", headers),
                String.class);
    }

    /** Логин через веб-форму (CSRF подставляется формой автоматически). */
    private void login(Page page, String username) {
        registerViaApi(username);
        page.navigate(base() + "/web/login");
        page.fill("input[name=username]", username);
        page.fill("input[name=password]", PASSWORD);
        page.click("button[type=submit]");
        page.waitForURL("**/web/entries");
    }

    /** Создаёт запись через UI с фиксированным паролем, возвращает путь карточки. */
    private String createEntryViaUi(Page page, String name) {
        page.navigate(base() + "/web/entries/new");
        page.fill("#name", name);
        page.fill("#site", "https://example.com");
        page.fill("#login", "bob-login");
        page.fill("input[data-password-field]", ENTRY_PASSWORD);
        page.click("button:has-text('Создать')");
        page.waitForURL("**/web/entries");
        String href = page.getAttribute("table a:has-text('Открыть')", "href");
        return href == null ? "" : href;
    }

    /** (a) Генератор: клик -> поле непусто, длина 20 (default), reveal возвращает пароль. */
    @Test
    void generatorFlowCreatesEntryWithGeneratedPassword() {
        registerViaApi("e2e-gen");
        Page page = browser.newPage();

        page.navigate(base() + "/web/login");
        page.fill("input[name=username]", "e2e-gen");
        page.fill("input[name=password]", PASSWORD);
        page.click("button[type=submit]");
        page.waitForURL("**/web/entries");

        page.navigate(base() + "/web/entries/new");
        page.fill("#name", "Playwright запись");
        page.fill("#site", "https://example.com");
        page.fill("#login", "pw-user");
        page.click("[data-generate-password]");
        String generated = page.inputValue("input[data-password-field]");
        assertThat(generated).isNotEmpty();
        assertThat(generated.length()).isEqualTo(20);
        // после генерации пароль показан открыто (глаз в состоянии «Скрыть»)
        assertThat(page.getAttribute("input[data-password-field]", "type")).isEqualTo("text");

        page.click("button:has-text('Создать')");
        page.waitForURL("**/web/entries");
        page.click("table a:has-text('Открыть')");
        page.click("button:has-text('Показать пароль')");
        assertThat(page.textContent("[data-secret-value]")).isEqualTo(generated);
        page.close();
    }

    /** (b) Кнопки копирования: видимость до/после reveal, тост, содержимое буфера. */
    @Test
    void copyButtonsVisibilityToastAndClipboardContent() {
        Page page = browser.newPage();
        BrowserContext context = page.context();
        // localhost — secure context; даём chromium права на чтение буфера
        context.grantPermissions(List.of("clipboard-read", "clipboard-write"));

        login(page, "e2e-copy");
        String cardPath = createEntryViaUi(page, "Playwright копирование");
        page.navigate(base() + cardPath);

        // до reveal: логин-кнопка есть, пароль-кнопки нет (rendered absence)
        assertThat(page.locator("[data-copy-field=\"login\"]").count()).isEqualTo(1);
        assertThat(page.locator("[data-copy-field=\"password\"]").count()).isZero();

        page.click("[data-copy-field=\"login\"]");
        page.waitForSelector(".toast");
        // navigator.clipboard.writeText асинхронен — короткая пауза на промис
        page.waitForTimeout(300);
        String clipboard = (String) page.evaluate("navigator.clipboard.readText()");
        assertThat(clipboard).isEqualTo("bob-login");

        page.click("button:has-text('Показать пароль')");
        assertThat(page.locator("[data-copy-field=\"password\"]").count()).isEqualTo(1);
        page.close();
    }
}
