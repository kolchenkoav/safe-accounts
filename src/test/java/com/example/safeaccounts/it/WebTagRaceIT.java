package com.example.safeaccounts.it;

import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.example.safeaccounts.service.TagService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * DIAGNOSTIC IT for the review of commit 277f3c0 (TagService race retry).
 * Real PostgreSQL via Testcontainers, real transactions, no mocks.
 *
 * Contract under review (TP MAJOR-1 fix): when two concurrent requests try to
 * create the SAME NEW tag (same user, same name_lower), the loser of the
 * UNIQUE(user_id, name_lower) race must NOT get a 500 / unhandled exception;
 * attachOrCreate must reuse the winner tag, createTag must throw
 * TagAlreadyExistsException.
 *
 * Two scenarios:
 *  1) realistic HTTP race: two sessions, CyclicBarrier, two entries,
 *     same brand-new tag name, both POST /web/entries/{id}/tags;
 *  2) deterministic: an uncommitted conflicting INSERT is held open in another
 *     transaction while attachOrCreate runs, forcing the
 *     catch(DataIntegrityViolationException) + re-find path inside the SAME
 *     transaction (the exact pattern claimed to work by the fix).
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("it")
@Testcontainers
class WebTagRaceIT {

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
    TransactionTemplate transactionTemplate;
    @Autowired
    UserRepository userRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    AuditEventRepository auditEventRepository;
    @Autowired
    TagRepository tagRepository;
    @Autowired
    TagService tagService;

    private static final String PASSWORD = "Str0ng-Passw0rd!";
    private static final String ENTRY_PASSWORD = "Entry-Pass-123!";

    @BeforeEach
    void cleanDatabase() {
        transactionTemplate.executeWithoutResult(status -> {
            auditEventRepository.deleteAll();
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

    private MockHttpSession loginSession(String username) throws Exception {
        MvcResult r = mockMvc.perform(post("/web/login")
                        .with(csrf())
                        .param("username", username)
                        .param("password", PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"))
                .andReturn();
        return (MockHttpSession) r.getRequest().getSession();
    }

    private void createEntry(MockHttpSession session, String name) throws Exception {
        mockMvc.perform(post("/web/entries")
                        .session(session)
                        .with(csrf())
                        .param("name", name)
                        .param("site", "https://race.example")
                        .param("login", "user")
                        .param("password", ENTRY_PASSWORD)
                        .param("notes", "race"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/web/entries"));
    }

    /** Distinct entry ids visible on the list page (order as displayed). */
    private LinkedHashSet<String> entryIds(MockHttpSession session) throws Exception {
        MvcResult list = mockMvc.perform(get("/web/entries").session(session))
                .andExpect(status().isOk())
                .andReturn();
        String html = list.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("/web/entries/([0-9a-fA-F-]{36})").matcher(html);
        LinkedHashSet<String> ids = new LinkedHashSet<>();
        while (m.find()) {
            ids.add(m.group(1));
        }
        return ids;
    }

    private static final class Outcome {
        final int status;
        final Throwable error;
        final String flashError;

        Outcome(int status, Throwable error, String flashError) {
            this.status = status;
            this.error = error;
            this.flashError = flashError;
        }

        @Override
        public String toString() {
            if (error != null) {
                return describe(error);
            }
            return "HTTP " + status + (flashError == null ? "" : " flashError=" + flashError);
        }
    }

    private static String describe(Throwable t) {
        StringBuilder sb = new StringBuilder();
        for (Throwable c = t; c != null; c = c.getCause()) {
            sb.append(c.getClass().getName()).append(": ")
                    .append(String.valueOf(c.getMessage()).replace('\n', ' '))
                    .append(" <- ");
        }
        return sb.toString();
    }

    /** POST /web/entries/{id}/tags capturing the real outcome (status/exception). */
    private Outcome attachTag(MockHttpSession session, String entryId, String tagName) {
        try {
            MvcResult r = mockMvc.perform(post("/web/entries/{id}/tags", entryId)
                            .session(session)
                            .with(csrf())
                            .param("tagName", tagName))
                    .andReturn();
            Object flash = r.getFlashMap() == null ? null : r.getFlashMap().get("flashError");
            return new Outcome(r.getResponse().getStatus(), null,
                    flash == null ? null : flash.toString());
        } catch (Throwable t) {
            return new Outcome(-1, t, null);
        }
    }

    // -- 1. realistic HTTP race -------------------------------------------------

    @Test
    void concurrentHttpAttachOfSameNewTagNameMustNotProduce500() throws Exception {
        String username = "tagrace-http";
        registerUser(username);
        MockHttpSession sessionA = loginSession(username);
        MockHttpSession sessionB = loginSession(username);
        createEntry(sessionA, "Race entry A");
        createEntry(sessionB, "Race entry B");

        LinkedHashSet<String> ids = entryIds(sessionA);
        assertThat(ids.size()).as("two entries expected on the list page").isGreaterThanOrEqualTo(2);
        Iterator<String> it = ids.iterator();
        String entryA = it.next();
        String entryB = it.next();
        String tagName = "race-" + UUID.randomUUID();

        CyclicBarrier barrier = new CyclicBarrier(2);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Outcome> fa = pool.submit(() -> {
                barrier.await(60, TimeUnit.SECONDS);
                return attachTag(sessionA, entryA, tagName);
            });
            Future<Outcome> fb = pool.submit(() -> {
                barrier.await(60, TimeUnit.SECONDS);
                return attachTag(sessionB, entryB, tagName);
            });
            Outcome a = fa.get(180, TimeUnit.SECONDS);
            Outcome b = fb.get(180, TimeUnit.SECONDS);
            System.out.println("[WebTagRaceIT] http race A: " + a);
            System.out.println("[WebTagRaceIT] http race B: " + b);

            assertThat(a.error).as("thread A: %s", a).isNull();
            assertThat(b.error).as("thread B: %s", b).isNull();
            assertThat(a.status).as("thread A: %s", a).isBetween(300, 399);
            assertThat(b.status).as("thread B: %s", b).isBetween(300, 399);
        } finally {
            pool.shutdownNow();
        }
    }

    // -- 2. deterministic forced catch(DIVe)+re-find path -----------------------

    @Test
    void deterministicUniqueViolationMustBeResolvedInsideSameTransaction() throws Exception {
        String username = "tagrace-det";
        registerUser(username);
        MockHttpSession session = loginSession(username);
        createEntry(session, "Race deterministic");
        String entryId = entryIds(session).iterator().next();
        User actor = userRepository.findByUsername(username).orElseThrow();
        String tagName = "det-" + UUID.randomUUID();
        Tag winnerTag = Tag.create(UUID.randomUUID(), actor, tagName, Instant.now());

        CountDownLatch inserted = new CountDownLatch(1);
        CountDownLatch commit = new CountDownLatch(1);
        ExecutorService blockerPool = Executors.newSingleThreadExecutor();
        ScheduledExecutorService releaser = Executors.newSingleThreadScheduledExecutor();
        try {
            Future<?> blocker = blockerPool.submit(() ->
                    transactionTemplate.executeWithoutResult(tx -> {
                        tagRepository.saveAndFlush(winnerTag);
                        inserted.countDown();
                        try {
                            if (!commit.await(60, TimeUnit.SECONDS)) {
                                System.out.println("[WebTagRaceIT] blocker: commit latch timeout");
                            }
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }));
            assertThat(inserted.await(60, TimeUnit.SECONDS))
                    .as("blocker tx must flush its INSERT first").isTrue();
            // Release the blocker commit while attachOrCreate is expected to be
            // blocked on the unique index entry; 1500 ms is ample head start for
            // requireOwnedEntry + find (both before the INSERT).
            releaser.schedule(commit::countDown, 1500, TimeUnit.MILLISECONDS);

            Tag result = null;
            Throwable failure = null;
            try {
                result = tagService.attachOrCreate(actor, UUID.fromString(entryId), tagName);
            } catch (Throwable t) {
                failure = t;
            }
            System.out.println("[WebTagRaceIT] deterministic outcome: "
                    + (failure == null ? "OK, tagId=" + result.getId() : describe(failure)));
            blocker.get(60, TimeUnit.SECONDS);

            assertThat(failure)
                    .as("attachOrCreate must resolve the unique violation: %s",
                            failure == null ? "OK" : describe(failure))
                    .isNull();
            assertThat(result).isNotNull();
            assertThat(result.getId())
                    .as("loser must reuse the winner tag")
                    .isEqualTo(winnerTag.getId());
        } finally {
            blockerPool.shutdownNow();
            releaser.shutdownNow();
        }
    }

    // -- 3. advice ordering probe ------------------------------------------------

    @Autowired
    org.springframework.context.ApplicationContext applicationContext;

    /**
     * Fix-2 effectiveness probe (fix cycle 2: скоупы вместо порядка).
     * Ранее глобальный @RestControllerAdvice (ApiExceptionHandler) с catch-all
     * Exception.class перехватывал и web-контроллеры — web-scoped advice был
     * мёртвым кодом. Решение — непересекающиеся скоупы пакетов: порядок бинов
     * больше не влияет. Проба проверяет, что оба advice ограничены своими
     * пакетами и не перекрываются.
     */
    @Test
    void controllerAdvicesAreScopedToTheirPackagesSoWebAdviceCanFire() {
        org.springframework.web.bind.annotation.ControllerAdvice apiAdvice =
                applicationContext.findAnnotationOnBean("apiExceptionHandler",
                        org.springframework.web.bind.annotation.ControllerAdvice.class);
        org.springframework.web.bind.annotation.ControllerAdvice webAdvice =
                applicationContext.findAnnotationOnBean("webExceptionAdvice",
                        org.springframework.web.bind.annotation.ControllerAdvice.class);

        assertThat(apiAdvice)
                .as("apiExceptionHandler must exist")
                .isNotNull();
        assertThat(webAdvice)
                .as("webExceptionAdvice must exist")
                .isNotNull();
        assertThat(apiAdvice.basePackageClasses())
                .as("apiExceptionHandler (catch-all Exception.class) must be scoped "
                        + "to the api package only")
                .containsExactly(com.example.safeaccounts.api.VaultController.class);
        assertThat(webAdvice.basePackageClasses())
                .as("webExceptionAdvice must be scoped to the web package")
                .containsExactly(com.example.safeaccounts.web.WebVaultController.class);
    }}
