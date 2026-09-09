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
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.LinkedHashSet;
import java.util.Set;

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
        assertThat(tables).contains("users", "auth_tokens", "vault_entries", "audit_events");
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
                "id", "user_id", "site_enc", "login_enc", "password_enc", "notes_enc",
                "created_at", "updated_at", "version");
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
                "idx_auth_tokens_user_id");
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
