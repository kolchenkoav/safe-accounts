package com.example.safeaccounts.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * TP B1-REST: доказательство, что oversized multipart (&gt;11 МБ) на
 * POST /api/vault/import отдаёт 413 ProblemDetail, а не 500.
 * <p>
 * Фикс — {@code spring.servlet.multipart.resolve-lazily: true}: multipart
 * парсится при резолве аргументов контроллера (обработчик уже смаплен),
 * поэтому package-scoped ApiExceptionHandler(@ExceptionHandler(
 * MaxUploadSizeExceededException) → 413) достижим. Раньше исключение
 * бросалось в DispatcherServlet.checkMultipart ДО getHandler — advice был
 * мёртв, REST отдавал 500.
 * <p>
 * Отдельный класс с RANDOM_PORT + TestRestTemplate (реальный сетевой стек,
 * реальный multipart-резолвер Tomcat — MockMvc не применяет его лимиты).
 * Без @AutoConfigureMockMvc.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("it")
@Testcontainers
class OversizeUploadIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    @Autowired
    TestRestTemplate rest;

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Регистрация через API + логин → Bearer-токен (реальный сетевой путь). */
    private String registerAndLogin(String username) throws Exception {
        HttpHeaders json = new HttpHeaders();
        json.setContentType(MediaType.APPLICATION_JSON);
        rest.exchange("/api/auth/register", HttpMethod.POST,
                new HttpEntity<>("{\"username\":\"%s\",\"password\":\"%s\"}"
                        .formatted(username, PASSWORD), json), String.class);
        ResponseEntity<String> login = rest.exchange("/api/auth/login", HttpMethod.POST,
                new HttpEntity<>("{\"username\":\"%s\",\"password\":\"%s\"}"
                        .formatted(username, PASSWORD), json), String.class);
        assertThat(login.getStatusCode().value()).isEqualTo(200);
        return JSON.readTree(login.getBody()).get("accessToken").asText();
    }

    private HttpEntity<MultiValueMap<String, Object>> multipartEntity(
            String token, byte[] content, String filename) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);
        headers.setBearerAuth(token);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new ByteArrayResource(content) {
            @Override
            public String getFilename() {
                return filename;
            }
        });
        body.add("conflictStrategy", "skip");
        return new HttpEntity<>(body, headers);
    }

    @Test
    void oversizeMultipartReturns413ProblemDetailNot500() throws Exception {
        String token = registerAndLogin("oversize-user");

        // 11.5 МБ мусора — выше multipart-лимита (11 МБ); массив в памяти
        byte[] big = new byte[11_500_000];
        Arrays.fill(big, (byte) 'x');

        ResponseEntity<String> response = rest.exchange("/api/vault/import",
                HttpMethod.POST, multipartEntity(token, big, "big.csv"), String.class);

        // После resolve-lazily исключение достижимо для advice → 413, не 500
        assertThat(response.getStatusCode().value())
                .as("oversized multipart must be 413 (ProblemDetail), not 500")
                .isEqualTo(413);
        assertThat(response.getHeaders().getContentType())
                .as("RFC 7807 ProblemDetail")
                .isNotNull();
    }

    @Test
    void normalSizeCsvImportIsNot413() throws Exception {
        String token = registerAndLogin("normal-import-user");

        // ~10 КБ валидного CSV — под лимитами, обычный отчёт импорта
        String row = "Импорт,https://import.example,user,Pass-123,"
                + "a".repeat(9000) + "\r\n";
        byte[] csv = ("name,url,username,password,note\r\n" + row)
                .getBytes(StandardCharsets.UTF_8);

        ResponseEntity<String> response = rest.exchange("/api/vault/import",
                HttpMethod.POST, multipartEntity(token, csv, "small.csv"), String.class);

        assertThat(response.getStatusCode().value())
                .as("normal-size CSV must not be rejected as too large")
                .isEqualTo(200);
        assertThat(response.getBody()).contains("totalRows");
    }

    // -- Фаза 4: web-цепочка >11MB → error-page вместо whitelabel ----------------

    /**
     * Web-сценарий на реальном Tomcat: POST /web/entries/import с файлом
     * >11 МБ. CsrfFilter читает _csrf из multipart → Tomcat парсит тело →
     * MaxUploadSizeExceededException ДО DispatcherServlet (advice мёртв).
     * ErrorPageConfig (Tomcat error-page) диспатчит на
     * /web/error/file-too-large: осознанно отвечаем 413 с тематической
     * HTML-страницей — whitelabel-500 больше нет.
     */
    @Test
    void oversizeWebImportShowsErrorPageNotWhitelabel() throws Exception {
        String username = "web-big-user";
        HttpHeaders json = new HttpHeaders();
        json.setContentType(MediaType.APPLICATION_JSON);
        rest.exchange("/api/auth/register", HttpMethod.POST,
                new HttpEntity<>("{\"username\":\"%s\",\"password\":\"%s\"}"
                        .formatted(username, PASSWORD), json), String.class);

        // Сессия + CSRF из реальной формы логина (cookie вручную: TestRestTemplate
        // не хранит состояние)
        ResponseEntity<String> loginPage = rest.getForEntity("/web/login", String.class);
        String csrf = extractCsrf(loginPage.getBody());
        String cookie = sessionCookie(loginPage);
        assertThat(cookie).as("JSESSIONID on login page").isNotNull();

        HttpHeaders form = new HttpHeaders();
        form.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        form.add(HttpHeaders.COOKIE, cookie);
        ResponseEntity<String> login = rest.exchange("/web/login", HttpMethod.POST,
                new HttpEntity<>("_csrf=" + csrf + "&username=" + username
                        + "&password=" + PASSWORD, form), String.class);
        assertThat(login.getStatusCode().value()).isEqualTo(302);
        String session = sessionCookie(login) != null ? sessionCookie(login) : cookie;

        byte[] big = new byte[11_500_000];
        Arrays.fill(big, (byte) 'x');
        HttpHeaders multipartHeaders = new HttpHeaders();
        multipartHeaders.setContentType(MediaType.MULTIPART_FORM_DATA);
        multipartHeaders.add(HttpHeaders.COOKIE, session);
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        body.add("file", new ByteArrayResource(big) {
            @Override
            public String getFilename() {
                return "big.csv";
            }
        });
        // Именно чтение _csrf из multipart триггерит ранний Tomcat-парсинг
        body.add("_csrf", csrf);
        body.add("conflictStrategy", "skip");

        ResponseEntity<String> response = rest.exchange("/web/entries/import",
                HttpMethod.POST, new HttpEntity<>(body, multipartHeaders), String.class);

        // Никакого whitelabel-500. Два допустимых исхода (зависит от того, где
        // именно упал multipart-парсинг):
        //  1) 302 — Spring-резолвер у контроллера → WebExceptionAdvice →
        //     PRG-flash «Файл слишком большой (лимит 10 МБ)...» на форму;
        //  2) 413 — Tomcat упал раньше (фильтр) → error-dispatch на
        //     /web/error/file-too-large (тематическая HTML-страница).
        int code = response.getStatusCode().value();
        assertThat(code)
                .as("oversized web import must not produce whitelabel-500")
                .isIn(302, 413);
        if (code == 302) {
            // НЕ редирект на логин (сессия валидна), а на форму импорта
            assertThat(response.getHeaders().getLocation().getPath())
                    .isEqualTo("/web/entries/import");
            HttpHeaders followHeaders = new HttpHeaders();
            followHeaders.add(HttpHeaders.COOKIE, session);
            ResponseEntity<String> formPage = rest.exchange("/web/entries/import",
                    HttpMethod.GET, new HttpEntity<>(followHeaders), String.class);
            assertThat(formPage.getBody()).contains("10 МБ");
        } else {
            assertThat(response.getBody()).contains("10 МБ");
        }
    }

    private static String sessionCookie(ResponseEntity<?> response) {
        var cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        if (cookies == null) {
            return null;
        }
        // Последний JSESSIONID: после логина Spring Security меняет id сессии
        // (защита от session fixation) — актуальная кука приходит последней
        String latest = null;
        for (String cookie : cookies) {
            if (cookie.startsWith("JSESSIONID")) {
                latest = cookie.split(";", 2)[0];
            }
        }
        return latest;
    }

    private static String extractCsrf(String html) {
        Matcher matcher = Pattern.compile("name=\"_csrf\"\\s+value=\"([^\"]+)\"")
                .matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException("_csrf not found on login page");
        }
        return matcher.group(1);
    }
}
