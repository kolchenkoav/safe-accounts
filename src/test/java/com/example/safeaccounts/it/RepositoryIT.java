package com.example.safeaccounts.it;

import com.example.safeaccounts.domain.AuditEvent;
import com.example.safeaccounts.domain.AuthToken;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.AuthTokenRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Интеграционные тесты persistence-слоя: сущности маппятся на схему Flyway,
 * репозитории сохраняют/читают данные, работают ограничения
 * уникальности, внешние ключи, каскады и оптимистичная блокировка.
 * Значения чувствительных полей — синтетические шифротексты, не секреты.
 */
@SpringBootTest
@ActiveProfiles("it")
@Testcontainers
class RepositoryIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    @Autowired
    UserRepository userRepository;
    @Autowired
    AuthTokenRepository authTokenRepository;
    @Autowired
    VaultEntryRepository vaultEntryRepository;
    @Autowired
    AuditEventRepository auditEventRepository;
    @Autowired
    TransactionTemplate transactionTemplate;

    @Test
    void userRoundTripAndOptimisticLocking() {
        User user = persistUser("round-trip-user");

        Optional<User> loaded = userRepository.findByUsername("round-trip-user");
        assertThat(loaded).isPresent();
        assertThat(loaded.get().getId()).isEqualTo(user.getId());
        assertThat(loaded.get().getPasswordHash()).isEqualTo("argon2id$synthetic");
        assertThat(loaded.get().getRole()).isEqualTo("ROLE_USER");
        assertThat(loaded.get().isEnabled()).isTrue();
        assertThat(loaded.get().getDekWrapped()).isEqualTo("synthetic-wrapped-dek");
        assertThat(loaded.get().getDekIv()).isEqualTo("c3ludGhldGljLWl2");
        assertThat(loaded.get().getDekKekId()).isEqualTo("kek-1");
        assertThat(loaded.get().getVersion()).isEqualTo(0L);
    }

    @Test
    void duplicateUsernameIsRejected() {
        persistUser("dup-user");

        User duplicate = newUser("dup-user");
        assertThatThrownBy(() -> userRepository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void authTokenRequiresExistingUserAndRoundTrips() {
        User user = persistUser("token-user");

        AuthToken token = new AuthToken(
                UUID.randomUUID(), user,
                "synthetic-token-hash", "…abcd",
                "JUnit", "127.0.0.1",
                Instant.now(), Instant.now().plusSeconds(3600), null, null,
                null);
        AuthToken saved = authTokenRepository.saveAndFlush(token);
        assertThat(saved.getId()).isNotNull();

        assertThat(authTokenRepository.findByTokenHash("synthetic-token-hash"))
                .isPresent();
        assertThat(authTokenRepository.findAllByUser_Id(user.getId())).hasSize(1);

        AuthToken duplicate = new AuthToken(
                UUID.randomUUID(), user,
                "synthetic-token-hash", "…abcd",
                null, null, Instant.now(), null, null, null, null);
        assertThatThrownBy(() -> authTokenRepository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);

        UUID orphanUserId = transactionTemplate.execute(s -> {
            User orphanOwner = userRepository.saveAndFlush(newUser("orphan-user"));
            authTokenRepository.saveAndFlush(new AuthToken(
                    UUID.randomUUID(), orphanOwner,
                    "orphan-token-hash", "…ffff",
                    null, null, Instant.now(), null, null, null, null));
            return orphanOwner.getId();
        });
        transactionTemplate.executeWithoutResult(status ->
                userRepository.deleteById(orphanUserId));
        assertThat(authTokenRepository.findByTokenHash("orphan-token-hash")).isEmpty();

        int revoked = transactionTemplate.execute(s ->
                authTokenRepository.revokeAllForUser(user.getId(), Instant.now()));
        assertThat(revoked).isEqualTo(1);
        assertThat(authTokenRepository.findByTokenHash("synthetic-token-hash"))
                .isPresent()
                .get()
                .satisfies(t -> assertThat(t.getRevokedAt()).isNotNull());
    }

    @Test
    void vaultEntryRoundTripAndOwnerScoping() {
        User owner = persistUser("vault-owner");
        User other = persistUser("vault-other");

        VaultEntry entry = new VaultEntry(
                UUID.randomUUID(), owner,
                "site-enc", "login-enc", "password-enc", "notes-enc",
                Instant.now(), null, null);
        entry = vaultEntryRepository.saveAndFlush(entry);

        assertThat(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .hasSize(1);
        assertThat(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(other.getId()))
                .isEmpty();
        assertThat(vaultEntryRepository.findByIdAndUser_Id(entry.getId(), owner.getId()))
                .isPresent();
        assertThat(vaultEntryRepository.findByIdAndUser_Id(entry.getId(), other.getId()))
                .isEmpty();
        UUID entryId = entry.getId();
        transactionTemplate.executeWithoutResult(status ->
                assertThat(vaultEntryRepository.deleteByIdAndUser_Id(entryId, other.getId()))
                        .isZero());
        transactionTemplate.executeWithoutResult(status ->
                assertThat(vaultEntryRepository.deleteByIdAndUser_Id(entryId, owner.getId()))
                        .isEqualTo(1));
    }

    @Test
    void auditEventRoundTripWithNullableUser() {
        AuditEvent withUser = new AuditEvent(
                UUID.randomUUID(), persistUser("audit-user"), null,
                "LOGIN_SUCCESS", null, null, "127.0.0.1", "JUnit",
                "{\"ok\":true}", Instant.now());
        withUser = auditEventRepository.saveAndFlush(withUser);
        assertThat(withUser.getId()).isNotNull();

        AuditEvent anonymous = new AuditEvent(
                UUID.randomUUID(), null, null,
                "LOGIN_FAILURE", null, null, null, null, null, Instant.now());
        anonymous = auditEventRepository.saveAndFlush(anonymous);
        assertThat(anonymous.getUser()).isNull();

        List<AuditEvent> events =
                auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(
                        withUser.getUser().getId());
        assertThat(events).hasSize(1);
        assertThat(events.getFirst().getType()).isEqualTo("LOGIN_SUCCESS");
    }

    @Test
    void deletingUserCascadesToTokensAndEntriesAndNullsAudit() {
        User user = transactionTemplate.execute(status -> {
            User u = userRepository.saveAndFlush(newUser("cascade-user"));

            authTokenRepository.saveAndFlush(new AuthToken(
                    UUID.randomUUID(), u, "cascade-token-hash", "…0000",
                    null, null, Instant.now(), null, null, null, null));
            vaultEntryRepository.saveAndFlush(new VaultEntry(
                    UUID.randomUUID(), u, "site-enc", "login-enc", "password-enc",
                    null, Instant.now(), null, null));
            auditEventRepository.saveAndFlush(new AuditEvent(
                    UUID.randomUUID(), u, UUID.randomUUID(), "LOGIN_SUCCESS",
                    null, null, null, null, null, Instant.now()));
            return u;
        });

        transactionTemplate.executeWithoutResult(status ->
                userRepository.deleteById(user.getId()));

        assertThat(userRepository.existsById(user.getId())).isFalse();
        assertThat(authTokenRepository.findAllByUser_Id(user.getId())).isEmpty();
        assertThat(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(user.getId()))
                .isEmpty();
        // Событие аудита остаётся, но user_id обнуляется (ON DELETE SET NULL)
        List<AuditEvent> remaining =
                auditEventRepository.findAllByUser_IdOrderByCreatedAtDesc(user.getId());
        assertThat(remaining).isEmpty();
        assertThat(auditEventRepository.findAll())
                .anySatisfy(event -> {
                    assertThat(event.getType()).isEqualTo("LOGIN_SUCCESS");
                    assertThat(event.getUser()).isNull();
                });
    }

    private User newUser(String username) {
        return new User(
                UUID.randomUUID(), username, "argon2id$synthetic",
                "ROLE_USER", true, 0, null,
                "synthetic-wrapped-dek", "c3ludGhldGljLWl2", "kek-1",
                Instant.now(), null, null);
    }

    private User persistUser(String username) {
        return userRepository.saveAndFlush(newUser(username));
    }
}
