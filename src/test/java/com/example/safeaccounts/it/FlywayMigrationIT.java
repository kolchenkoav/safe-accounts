package com.example.safeaccounts.it;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Проверяет, что Flyway применяет все миграции на чистом PostgreSQL 16
 * и создаёт ровно ожидаемую схему (таблицы, колонки, индексы, ограничения).
 * Hibernate validate проверяется самим фактом успешного старта контекста
 * (ddl-auto=validate).
 */
@SpringBootTest
@ActiveProfiles("it")
@Testcontainers
class FlywayMigrationIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    @Autowired
    DataSource dataSource;

    @Test
    void allExpectedTablesExist() throws SQLException {
        Set<String> tables = queryOneColumn(
                "SELECT table_name FROM information_schema.tables" +
                        " WHERE table_schema = 'public' ORDER BY table_name");
        assertThat(tables).contains(
                "users", "auth_tokens", "vault_entries", "audit_events",
                "tags", "vault_entry_tags");
    }

    @Test
    void usersTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'users' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "id", "username", "password_hash", "role", "enabled",
                "failed_attempts", "locked_until",
                "dek_wrapped", "dek_iv", "dek_kek_id",
                "created_at", "updated_at", "version");
    }

    @Test
    void authTokensTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'auth_tokens' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "id", "user_id", "token_hash", "token_hint", "user_agent", "ip_address",
                "created_at", "expires_at", "last_used_at", "revoked_at", "version");
    }

    @Test
    void vaultEntriesTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'vault_entries' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "id", "user_id",
                "name_enc",
                "site_enc", "login_enc", "password_enc", "notes_enc",
                "created_at", "updated_at", "version");
    }

    @Test
    void vaultEntriesNameColumnIsNotNull() throws SQLException {
        // После V2 name_enc обязательно NOT NULL.
        Set<String> nullable = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'vault_entries'" +
                        " AND column_name = 'name_enc' AND is_nullable = 'YES'");
        assertThat(nullable).isEmpty();
    }

    @Test
    void tagsTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'tags' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "id", "user_id", "name", "name_lower", "created_at");
    }

    @Test
    void vaultEntryTagsTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'vault_entry_tags' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "vault_entry_id", "tag_id");
    }

    @Test
    void auditEventsTableHasExpectedColumns() throws SQLException {
        Set<String> columns = queryOneColumn(
                "SELECT column_name FROM information_schema.columns" +
                        " WHERE table_schema = 'public' AND table_name = 'audit_events' ORDER BY column_name");
        assertThat(columns).containsExactlyInAnyOrder(
                "id", "user_id", "token_id", "type", "object_type", "object_id",
                "ip_address", "user_agent", "details_json", "created_at");
    }

    @Test
    void requiredIndexesExist() throws SQLException {
        Set<String> indexes = queryOneColumn(
                "SELECT indexname FROM pg_indexes" +
                        " WHERE schemaname = 'public' ORDER BY indexname");
        assertThat(indexes).contains(
                "idx_vault_entries_user_id",
                "idx_audit_events_user_id",
                "idx_audit_events_created_at",
                "idx_auth_tokens_user_id",
                "idx_tags_user_name_lower",
                "idx_tags_user_id",
                "idx_vet_entry",
                "idx_vet_tag");
    }

    @Test
    void uniqueConstraintsExist() throws SQLException {
        Set<String> constraints = queryOneColumn(
                "SELECT conname FROM pg_constraint" +
                        " WHERE conrelid IN ('users'::regclass, 'auth_tokens'::regclass)" +
                        " AND contype = 'u' ORDER BY conname");
        assertThat(constraints).contains("uk_users_username", "uk_auth_tokens_token_hash");
    }

    @Test
    void foreignKeysWithCascadeExist() throws SQLException {
        // auth_tokens.user_id и vault_entries.user_id: ON DELETE CASCADE;
        // audit_events.user_id: nullable, ON DELETE SET NULL.
        Set<String> cascadeActions = queryOneColumn("""
                SELECT DISTINCT (confdeltype::text)
                  FROM pg_constraint
                 WHERE conname IN ('fk_auth_tokens_user', 'fk_vault_entries_user')
                """);
        assertThat(cascadeActions).containsExactly("c");

        Set<String> auditActions = queryOneColumn("""
                SELECT confdeltype::text
                  FROM pg_constraint
                 WHERE conname = 'fk_audit_events_user'
                """);
        assertThat(auditActions).containsExactly("n");
    }

    @Test
    void tagsAndJoinForeignKeysAreCascade() throws SQLException {
        // fk_tags_user, fk_vet_entry, fk_vet_tag — ON DELETE CASCADE.
        Set<String> actions = queryOneColumn("""
                SELECT conname || '=' || confdeltype::text
                  FROM pg_constraint
                 WHERE conname IN ('fk_tags_user', 'fk_vet_entry', 'fk_vet_tag')
                 ORDER BY conname
                """);
        assertThat(actions).containsExactly("fk_tags_user=c", "fk_vet_entry=c", "fk_vet_tag=c");
    }

    @Test
    void nameBackfillCopiesSiteEnc() throws SQLException {
        // Симулируем «старую» запись (созданную до V2): прямой INSERT в vault_entries
        // с name_enc, явно заполненным значением site_enc (как делает бэкфилл V2).
UUID userId;
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO users (id, username, password_hash, role, enabled," +
                             " failed_attempts, dek_wrapped, dek_iv, dek_kek_id," +
                             " created_at, updated_at, version)" +
                             " VALUES (?, ?, 'h', 'ROLE_USER', true, 0, 'w', 'i', 'k'," +
                             " ?, ?, 0)")) {
            userId = UUID.randomUUID();
            ps.setObject(1, userId);
            ps.setObject(2, "backfill-user-" + userId);
            ps.setTimestamp(3, Timestamp.from(Instant.now()));
            ps.setTimestamp(4, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
        String siteEnc = "site-enc-value";
        try (Connection c = dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO vault_entries (id, user_id, name_enc, site_enc," +
                             " login_enc, password_enc, notes_enc, created_at, updated_at, version)" +
                             " VALUES (?, ?, ?, ?, 'l', 'p', null, ?, ?, 0)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, userId);
            ps.setString(3, siteEnc);
            ps.setString(4, siteEnc);
ps.setTimestamp(5, Timestamp.from(Instant.now()));
            ps.setTimestamp(6, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
        Set<String> rows = queryOneColumn(
                "SELECT name_enc FROM vault_entries WHERE user_id = '" + userId + "'");
        assertThat(rows).containsExactly(siteEnc);
    }

    private Set<String> queryOneColumn(String sql) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            Set<String> result = new LinkedHashSet<>();
            while (resultSet.next()) {
                result.add(resultSet.getString(1));
            }
            return result;
        }
    }
}