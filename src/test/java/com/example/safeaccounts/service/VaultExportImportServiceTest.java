package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.CryptoProperties;
import com.example.safeaccounts.crypto.KeyManager;
import com.example.safeaccounts.crypto.WrappedDek;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import com.example.safeaccounts.service.csv.ConflictStrategy;
import com.example.safeaccounts.service.csv.CsvExportRow;
import com.example.safeaccounts.service.csv.CsvParser;
import com.example.safeaccounts.service.csv.CsvWriter;
import com.example.safeaccounts.service.csv.ExportPayload;
import com.example.safeaccounts.service.csv.ImportError;
import com.example.safeaccounts.service.csv.ImportReport;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import com.example.safeaccounts.service.csv.PayloadTooLargeException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.security.access.AccessDeniedException;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты сервиса экспорта/импорта CSV ({@link VaultExportImportService}).
 * <p>
 * Без Testcontainers и без БД — все репозитории замоканы. Криптография —
 * настоящая ({@link AesGcmCryptoService}) с фиксированным тестовым KEK.
 * <p>
 * Покрывает: конфликты SKIP/UPSERT, dryRun, failFast, лимиты MAX_EXPORT_ROWS
 * и MAX_CSV_BYTES, owner-check, аудит с агрегатами и без секретов.
 */
@ExtendWith(MockitoExtension.class)
class VaultExportImportServiceTest {

    @Mock
    VaultEntryRepository vaultEntryRepository;
    @Mock
    TagRepository tagRepository;
    @Mock
    UserRepository userRepository;
    @Mock
    AuditService auditService;

    private VaultExportImportService service;
    private AesGcmCryptoService cryptoService;
    private SecretKey ownerDek;
    private User owner;
    private User admin;
    private User other;
    private final CsvParser csvParser = new CsvParser();
    private final CsvWriter csvWriter = new CsvWriter();

    private static final Instant FIXED_INSTANT = Instant.parse("2025-01-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        CryptoProperties props = new CryptoProperties();
        props.setMasterKeyBase64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY");
        Environment environment = org.mockito.Mockito.mock(Environment.class);
        KeyManager keyManager = new KeyManager(props, environment);
        keyManager.afterPropertiesSet();
        cryptoService = new AesGcmCryptoService(keyManager);

        Clock fixedClock = Clock.fixed(FIXED_INSTANT, ZoneOffset.UTC);
        service = new VaultExportImportService(
                vaultEntryRepository, tagRepository, userRepository,
                cryptoService, auditService, fixedClock,
                csvParser, csvWriter);

        ownerDek = cryptoService.generateDek();
        WrappedDek wrapped = cryptoService.wrapDek(ownerDek);
        owner = new User(UUID.randomUUID(), "alice", "hash", "ROLE_USER", true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                FIXED_INSTANT, null, null);
        admin = new User(UUID.randomUUID(), "root", "hash", "ROLE_ADMIN", true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                FIXED_INSTANT, null, null);
        other = new User(UUID.randomUUID(), "bob", "hash", "ROLE_USER", true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                FIXED_INSTANT, null, null);
    }

    // -- owner-check ----------------------------------------------------------

@Test
    void nonAdminCannotExportOtherUser() {
        // No stubbing: requireOwnerOrAdmin throws before any repository call.
        assertThatThrownBy(() -> service.export(owner, other, false))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void nonAdminCannotImportToOtherUser() {
        byte[] csv = simpleCsv();
        assertThatThrownBy(() -> service.importFromCsv(owner, other, csv,
                ConflictStrategy.SKIP, false, false))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void adminCanExportOtherUser() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(other.getId()))
                .thenReturn(List.of());
        ExportPayload payload = service.export(admin, other, false);
        assertThat(payload.rows()).isZero();
        verify(auditService).record(eq(admin), eq(AuditService.VAULT_EXPORTED),
                eq(null), any(Map.class));
    }

    @Test
    void adminCanImportToOtherUser() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(other.getId()))
                .thenReturn(List.of());
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));
        byte[] csv = simpleCsv();
        ImportReport report = service.importFromCsv(admin, other, csv,
                ConflictStrategy.SKIP, false, false);
        assertThat(report.created()).isEqualTo(1);
        assertThat(report.failed()).isZero();
        verify(auditService).record(eq(admin), eq(AuditService.VAULT_IMPORTED),
                eq(null), any(Map.class));
    }

    @Test
    void nullActorThrows() {
        assertThatThrownBy(() -> service.export(null, owner, false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullTargetThrows() {
        assertThatThrownBy(() -> service.export(owner, null, false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // -- экспорт --------------------------------------------------------------

    @Test
    void exportWritesCsvAndAuditWithAggregates() {
        VaultEntry e1 = encryptedEntry("Gmail", "https://gmail.com", "alice", "S3cret", "");
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of(e1));

        ExportPayload payload = service.export(owner, owner, false);
        assertThat(payload.rows()).isEqualTo(1);
        assertThat(payload.csv()).isNotEmpty();
        assertThat(payload.bom()).isFalse();
        assertThat(payload.sha256()).hasSize(64); // hex of SHA-256

        String csvText = new String(payload.csv(), java.nio.charset.StandardCharsets.UTF_8);
        assertThat(csvText).startsWith("name,url,username,password,note\r\n");
        assertThat(csvText).contains("Gmail,https://gmail.com,alice,S3cret,");

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(auditService).record(eq(owner), eq(AuditService.VAULT_EXPORTED),
                eq(null), captor.capture());
        Map<String, Object> details = captor.getValue();
        assertThat(details).containsEntry("entryCount", 1);
        assertThat(details).containsEntry("actor", "alice");
        assertThat(details).containsEntry("target", "alice");
        assertThat(details).containsEntry("bom", false);
        assertThat(details).containsKey("csvSha256");
        assertThat(details).containsKey("csvBytes");
        assertSecretFieldsAbsent(details);
    }

    @Test
    void exportWithBomIncludesBomFlagAndBytes() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());
        ExportPayload payload = service.export(owner, owner, true);
        assertThat(payload.bom()).isTrue();
        assertThat(payload.csv()[0] & 0xFF).isEqualTo(0xEF);
    }

    @Test
    void exportTooManyRowsThrowsPayloadTooLarge() {
        List<VaultEntry> many = new ArrayList<>(VaultExportImportService.MAX_EXPORT_ROWS + 1);
        for (int i = 0; i < VaultExportImportService.MAX_EXPORT_ROWS + 1; i++) {
            many.add(encryptedEntry("n" + i, "u", "l", "p", ""));
        }
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(many);

        assertThatThrownBy(() -> service.export(owner, owner, false))
                .isInstanceOf(PayloadTooLargeException.class);
    }

    @Test
    void exportEmptyReturnsHeaderOnly() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());
        ExportPayload payload = service.export(owner, owner, false);
        assertThat(payload.rows()).isZero();
        assertThat(new String(payload.csv(), java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("name,url,username,password,note\r\n");
    }

    // -- импорт ---------------------------------------------------------------

@Test
    void importCsvCreatesNewEntries() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

        byte[] csv = simpleCsv("Gmail", "https://gmail.com", "alice", "p1", "n1");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);

        assertThat(report.totalRows()).isEqualTo(1);
        assertThat(report.created()).isEqualTo(1);
        assertThat(report.updated()).isZero();
        assertThat(report.skipped()).isZero();
        assertThat(report.failed()).isZero();
        assertThat(report.errors()).isEmpty();
        assertThat(report.dryRun()).isFalse();
        verify(vaultEntryRepository, times(1)).saveAndFlush(any());
        verifyAuditWithoutSecrets(1, 1, 0, 0, false, ConflictStrategy.SKIP);
    }

    @Test
    void importSkipConflictCountsSkipped() {
        VaultEntry existing = encryptedEntry("Gmail", "https://gmail.com", "alice", "old-pass", "");
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of(existing));

        byte[] csv = simpleCsv("Gmail", "https://gmail.com", "alice", "new-pass", "n");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);

        assertThat(report.created()).isZero();
        assertThat(report.updated()).isZero();
        assertThat(report.skipped()).isEqualTo(1);
        assertThat(report.failed()).isZero();
        verify(vaultEntryRepository, never()).saveAndFlush(any());
        verifyAuditWithoutSecrets(1, 0, 0, 1, false, ConflictStrategy.SKIP);
    }

    @Test
    void importUpsertConflictCountsUpdated() {
        VaultEntry existing = encryptedEntry("Gmail", "https://gmail.com", "alice", "old-pass", "");
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of(existing));
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

        byte[] csv = simpleCsv("Gmail2", "https://gmail.com", "alice", "new-pass", "n");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.UPSERT, false, false);

        assertThat(report.updated()).isEqualTo(1);
        assertThat(report.created()).isZero();
        assertThat(report.skipped()).isZero();
        verify(vaultEntryRepository, times(1)).saveAndFlush(any());
        verifyAuditWithoutSecrets(1, 0, 1, 0, false, ConflictStrategy.UPSERT);
    }

    @Test
    void importDryRunDoesNotPersist() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());

        byte[] csv = simpleCsv("Gmail", "https://gmail.com", "alice", "p", "n");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, true, false);

        assertThat(report.created()).isEqualTo(1);
        assertThat(report.dryRun()).isTrue();
        verify(vaultEntryRepository, never()).saveAndFlush(any());
        // Аудит всё равно пишется (план, п.5.3).
        verifyAuditWithoutSecrets(1, 1, 0, 0, true, ConflictStrategy.SKIP);
    }

    @Test
    void importDryRunUpsertDoesNotMutateExistingEntry() {
        // Существующая запись с зашифрованными полями; её *Enc-снимок запоминаем.
        VaultEntry existing = encryptedEntry(
                "Gmail", "https://gmail.com", "alice", "old-pass", "");
        String beforePasswordEnc = existing.getPasswordEnc();
        String beforeNameEnc = existing.getNameEnc();
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of(existing));

        byte[] csv = simpleCsv("Gmail2", "https://gmail.com", "alice", "new-pass", "n");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.UPSERT, true, false);

        // Контракт отчёта сохранён.
        assertThat(report.updated()).isEqualTo(1);
        assertThat(report.created()).isZero();
        assertThat(report.dryRun()).isTrue();

        // Persistence-методы НЕ вызывались (важно: иначе Hibernate dirty-check
        // может протащить мутацию в БД на commit).
        verify(vaultEntryRepository, never()).saveAndFlush(any());
        verify(vaultEntryRepository, never()).save(any());
        verify(vaultEntryRepository, never()).delete(any());

        // Управляемая JPA-сущность не была мутирована: шифротексты те же.
        assertThat(existing.getPasswordEnc()).isEqualTo(beforePasswordEnc);
        assertThat(existing.getNameEnc()).isEqualTo(beforeNameEnc);

        // Аудит с dryRun=true всё равно пишется.
        verifyAuditWithoutSecrets(1, 0, 1, 0, true, ConflictStrategy.UPSERT);
    }

    @Test
    void importFailFastRollsBackOnInvalidRow() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());

        // Вторая строка без name.
        String csvText = "name,url,username,password,note\r\n"
                + "Gmail,https://gmail.com,alice,p,n\r\n"
                + ",u,u,p,n\r\n";
        byte[] csv = csvText.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertThatThrownBy(() -> service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, true))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void importFailFastFalseCollectsErrorsAndAppliesValidOnes() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

        String csvText = "name,url,username,password,note\r\n"
                + "Gmail,https://gmail.com,alice,p,n\r\n"
                + ",u,u,p,n\r\n"  // invalid: blank name
                + "Work,u,u,p,n\r\n";
        byte[] csv = csvText.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);

        assertThat(report.totalRows()).isEqualTo(3);
        assertThat(report.created()).isEqualTo(2);
        assertThat(report.failed()).isEqualTo(1);
        assertThat(report.errors()).hasSize(1);
        assertThat(report.errors().get(0).row()).isEqualTo(2);
        assertThat(report.errors().get(0).reason()).contains("name");
    }

    @Test
    void importInvalidHeaderFailsFast() {
        String bad = "wrong,header,here\r\n";
        byte[] csv = bad.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertThatThrownBy(() -> service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, true, true))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void importInvalidHeaderNotFailFastReturnsReport() {
        String bad = "wrong,header,here\r\n";
        byte[] csv = bad.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);
        assertThat(report.failed()).isEqualTo(1);
        assertThat(report.totalRows()).isZero();
        assertThat(report.errors().get(0).row()).isZero();
    }

    @Test
    void importPayloadTooLarge() {
        byte[] huge = new byte[VaultExportImportService.MAX_CSV_BYTES + 1];
        assertThatThrownBy(() -> service.importFromCsv(owner, owner, huge,
                ConflictStrategy.SKIP, false, false))
                .isInstanceOf(PayloadTooLargeException.class);
    }

    @Test
    void importTooManyRowsFailsFast() {
        StringBuilder sb = new StringBuilder("name,url,username,password,note\r\n");
        for (int i = 0; i < VaultExportImportService.MAX_EXPORT_ROWS + 1; i++) {
            sb.append("n").append(i).append(",u,u,p,n\r\n");
        }
        byte[] csv = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertThatThrownBy(() -> service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, true, true))
                .isInstanceOf(PayloadTooLargeException.class);
    }

    @Test
    void importTooManyRowsNotFailFastReportsError() {
        StringBuilder sb = new StringBuilder("name,url,username,password,note\r\n");
        for (int i = 0; i < VaultExportImportService.MAX_EXPORT_ROWS + 1; i++) {
            sb.append("n").append(i).append(",u,u,p,n\r\n");
        }
        byte[] csv = sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);

        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);
        assertThat(report.failed()).isEqualTo(1);
        assertThat(report.errors().get(0).row()).isZero();
    }

    @Test
    void importBlankPasswordFailsValidation() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());

        byte[] csv = simpleCsv("name", "u", "l", "", "");
        ImportReport report = service.importFromCsv(owner, owner, csv,
                ConflictStrategy.SKIP, false, false);
        assertThat(report.failed()).isEqualTo(1);
        assertThat(report.errors().get(0).reason()).contains("password");
    }

    @Test
    void importNullCsvThrows() {
        assertThatThrownBy(() -> service.importFromCsv(owner, owner, null,
                ConflictStrategy.SKIP, false, false))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void importRecordsSha256() {
        when(vaultEntryRepository.findAllByUser_IdOrderByCreatedAtAsc(owner.getId()))
                .thenReturn(List.of());
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

        byte[] csv = simpleCsv("Gmail", "https://gmail.com", "alice", "p", "n");
        service.importFromCsv(owner, owner, csv, ConflictStrategy.SKIP, false, false);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(auditService).record(eq(owner), eq(AuditService.VAULT_IMPORTED),
                eq(null), captor.capture());
        Map<String, Object> details = captor.getValue();
        assertThat(details).containsKey("csvSha256");
        assertThat(((String) details.get("csvSha256"))).hasSize(64);
        assertThat(details).containsKey("csvBytes");
        assertSecretFieldsAbsent(details);
    }

    // -- helpers --------------------------------------------------------------

    private VaultEntry encryptedEntry(String name, String site, String login,
                                      String password, String notes) {
        return new VaultEntry(
                UUID.randomUUID(),
                owner,
                cryptoService.encrypt(name, ownerDek),
                cryptoService.encrypt(site, ownerDek),
                cryptoService.encrypt(login, ownerDek),
                cryptoService.encrypt(password, ownerDek),
                notes.isEmpty() ? null : cryptoService.encrypt(notes, ownerDek),
                FIXED_INSTANT,
                null,
                null);
    }

    private byte[] simpleCsv() {
        return simpleCsv("Gmail", "https://gmail.com", "alice", "p", "n");
    }

    private byte[] simpleCsv(String name, String site, String login, String password, String notes) {
        CsvExportRow row = new CsvExportRow(name, site, login, password, notes);
        return csvWriter.write(List.of(row), false);
    }

    @SuppressWarnings("unchecked")
    private void verifyAuditWithoutSecrets(int totalRows, int created, int updated,
                                           int skipped, boolean dryRun,
                                           ConflictStrategy strategy) {
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(auditService, times(1)).record(eq(owner), eq(AuditService.VAULT_IMPORTED),
                eq(null), captor.capture());
        Map<String, Object> details = captor.getValue();
        assertThat(details).containsEntry("actor", "alice");
        assertThat(details).containsEntry("target", "alice");
        assertThat(details).containsEntry("totalRows", totalRows);
        assertThat(details).containsEntry("created", created);
        assertThat(details).containsEntry("updated", updated);
        assertThat(details).containsEntry("skipped", skipped);
        assertThat(details).containsEntry("dryRun", dryRun);
        assertThat(details).containsEntry("strategy", strategy.name());
        assertSecretFieldsAbsent(details);
    }

    private void assertSecretFieldsAbsent(Map<String, Object> details) {
        List<String> forbiddenKeys = List.of(
                "password", "csv", "name", "note", "login", "site",
                "username", "url", "body", "payload");
        for (String key : forbiddenKeys) {
            assertThat(details)
                    .as("details must not contain key '%s'", key)
                    .doesNotContainKey(key);
        }
        // Защита от случайного сериализованного CSV.
        for (Object value : details.values()) {
            assertThat(value).isNotInstanceOf(byte[].class);
        }
        // Значения известных CSV-полей не должны появляться ни в одном value.
        String allSerialized = details.toString();
        assertThat(allSerialized)
                .doesNotContain("S3cret")
                .doesNotContain("alice@gmail.com");
    }
}