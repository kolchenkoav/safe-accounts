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
}
