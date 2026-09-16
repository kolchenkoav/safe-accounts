package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Экспорт и импорт сейфа в CSV (Google Chrome Password Manager формат).
 * <p>
 * Правила безопасности (AGENTS.md / Task-07 / Task-08):
 * <ul>
 *   <li>все чувствительные поля (name, site, login, password, notes)
 *       перед сохранением шифруются AES-256-GCM; в БД plaintext нет;</li>
 *   <li>DEK разворачивается из wrapped-формы через
 *       {@link AesGcmCryptoService#unwrapDek};</li>
 *   <li>owner-check: actor может действовать только над своими записями
 *       либо над записями любого пользователя, если actor — ROLE_ADMIN;</li>
 *   <li>CSV создаётся в открытом виде (plaintext-пароли) — это требование
 *       совместимости с Chrome. Никакая расшифрованная секретная информация
 *       не логируется и не пишется в {@code details} аудита. В аудите
 *       фиксируются только sha256 канонизированного CSV и агрегаты;</li>
 *   <li>аудит {@code VAULT_EXPORTED} / {@code VAULT_IMPORTED} пишется всегда
 *       (включая {@code dryRun=true}) без CSV/расшифрованных значений;</li>
 *   <li>IV уникален для каждой операции шифрования (SecureRandom внутри
 *       {@link AesGcmCryptoService});</li>
 *   <li>ошибки расшифровки возвращают нейтральное исключение без утечки деталей.</li>
 * </ul>
 * <p>
 * Теги в CSV не включаются (формат Chrome их не поддерживает); при импорте
 * колонка {@code tags} (если встретится в стороннем экспорте) тихо
 * игнорируется — существующие теги записей не затрагиваются.
 */
@Service
public class VaultExportImportService {

    static final Logger log = LoggerFactory.getLogger(VaultExportImportService.class);

    /** Максимум строк данных в одном экспорте. Превышение → 413. */
    public static final int MAX_EXPORT_ROWS = 10_000;

    /** Максимум размера CSV-байтов в одном импорте. Превышение → 413. */
    public static final int MAX_CSV_BYTES = 10 * 1024 * 1024;

    /** Допустимые границы значений (для валидации в импорте). */
    static final int MAX_NAME_LEN = 256;
    static final int MAX_URL_LEN = 2048;
    static final int MAX_USERNAME_LEN = 2048;
    static final int MAX_PASSWORD_LEN = 4096;
    static final int MAX_NOTE_LEN = 8192;

    private final VaultEntryRepository vaultEntryRepository;
    private final TagRepository tagRepository; // зарезервирован для будущих фаз
    private final UserRepository userRepository; // зарезервирован для будущих фаз
    private final AesGcmCryptoService cryptoService;
    private final AuditService auditService;
    private final Clock clock;
    private final CsvParser csvParser;
    private final CsvWriter csvWriter;

    public VaultExportImportService(VaultEntryRepository vaultEntryRepository,
                                    TagRepository tagRepository,
                                    UserRepository userRepository,
                                    AesGcmCryptoService cryptoService,
                                    AuditService auditService,
                                    Clock clock,
                                    CsvParser csvParser,
                                    CsvWriter csvWriter) {
        this.vaultEntryRepository = vaultEntryRepository;
        this.tagRepository = tagRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.auditService = auditService;
        this.clock = clock;
        this.csvParser = csvParser;
        this.csvWriter = csvWriter;
    }

    // -- экспорт -------------------------------------------------------------

    /**
     * Экспортирует все записи пользователя в CSV (Google Chrome Password Manager формат).
     * <p>
     * Owner-check: {@code actor == target} или {@code actor} — администратор.
     * При нарушении — {@link AccessDeniedException}.
     *
     * @param actor      инициатор запроса (для аудита и owner-check)
     * @param target     пользователь, чей сейф экспортируется
     * @param includeBom {@code true} — добавить UTF-8 BOM
     * @return байты CSV + sha256 + количество строк + флаг BOM
     * @throws PayloadTooLargeException если у пользователя больше {@value #MAX_EXPORT_ROWS} записей
     * @throws AccessDeniedException    если actor не имеет права на target
     */
    @Transactional
    public ExportPayload export(User actor, User target, boolean includeBom) {
        requireOwnerOrAdmin(actor, target);

        List<VaultEntry> entries = vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(target.getId());
        if (entries.size() > MAX_EXPORT_ROWS) {
            // Решение пользователя (план, раздел 5 п.5): отказ 413 без обрезки.
            throw new PayloadTooLargeException(
                    "Too many entries to export: " + entries.size()
                            + " > " + MAX_EXPORT_ROWS);
        }

        SecretKey dek = unwrapDek(target);
        List<CsvExportRow> rows = new ArrayList<>(entries.size());
        for (VaultEntry entry : entries) {
            rows.add(toRow(entry, dek));
        }

        byte[] csv = csvWriter.write(rows, includeBom);
        String sha256 = sha256Canonical(csv);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("target", target.getUsername());
        details.put("entryCount", rows.size());
        details.put("csvSha256", sha256);
        details.put("csvBytes", csv.length);
        details.put("bom", includeBom);
        auditService.record(actor, AuditService.VAULT_EXPORTED, null, details);

        log.info("Vault exported: actor={}, target={}, entryCount={}, bytes={}",
                actor.getUsername(), target.getUsername(), rows.size(), csv.length);

        return new ExportPayload(csv, sha256, rows.size(), includeBom);
    }

    // -- импорт --------------------------------------------------------------

    /**
     * Максимум ошибок в отчёте импорта (Фаза 5): сверх — сентинел
     * «… ещё N ошибок (показаны первые 100)»; счётчик failed остаётся точным.
     */
    static final int MAX_IMPORT_ERRORS = 100;

    /**
     * Импортирует записи из CSV.
     * <p>
     * Транзакционный: при {@code failFast=true} первая ошибка откатывает все
     * изменения; при {@code failFast=false} (default) ошибки накапливаются в
     * {@code errors[]}, валидные строки применяются. При {@code dryRun=true}
     * никаких изменений в БД не делается (но отчёт и аудит возвращаются).
     *
     * @throws PayloadTooLargeException асимметрично (fix B4):
     *                                  csv.length &gt; {@value #MAX_CSV_BYTES} —
     *                                  всегда; строк в файле &gt;
     *                                  {@value #MAX_EXPORT_ROWS} — мягко:
     *                                  ImportError(row=0, "too many rows") в
     *                                  отчёте (жёсткое исключение только при
     *                                  failFast; dryRun работает);
     *                                  cumulative (existing + rows &gt;
     *                                  {@value #MAX_EXPORT_ROWS}) — ВСЕГДА
     *                                  жёсткое исключение, включая dryRun
     *                                  (консервативен: при skip реальный
     *                                  прирост меньше)
     * @throws InvalidCsvException      при невалидном заголовке/парсинге и
     *                                  {@code failFast=true}
     * @throws AccessDeniedException    если actor не имеет права на target
     */
    @Transactional
    public ImportReport importFromCsv(User actor, User target, byte[] csvBytes,
                                      ConflictStrategy strategy, boolean dryRun,
                                      boolean failFast) {
        requireOwnerOrAdmin(actor, target);
        if (csvBytes == null) {
            throw new InvalidCsvException("CSV payload is null");
        }
        if (csvBytes.length > MAX_CSV_BYTES) {
            throw new PayloadTooLargeException(
                    "CSV payload too large: " + csvBytes.length + " > " + MAX_CSV_BYTES);
        }

        String sha256 = sha256Canonical(csvBytes);
        List<CsvExportRow> rows;
        try {
            rows = csvParser.parseDataRows(csvBytes);
        } catch (InvalidCsvException e) {
            if (failFast) {
                throw e;
            }
            return finalizeImport(actor, target, strategy, dryRun, sha256, csvBytes.length,
                    List.of(), List.of(new ImportError(0, "invalid csv: " + e.getMessage())),
                    0, 0, 0, 0, 1);
        }

        if (rows.size() > MAX_EXPORT_ROWS) {
            // Тот же лимит, что и для экспорта: защита от массивной записи.
            if (failFast) {
                throw new PayloadTooLargeException(
                        "Too many rows to import: " + rows.size() + " > " + MAX_EXPORT_ROWS);
            }
            return finalizeImport(actor, target, strategy, dryRun, sha256, csvBytes.length,
                    List.of(), List.of(new ImportError(0,
                            "too many rows: " + rows.size() + " > " + MAX_EXPORT_ROWS)),
                    rows.size(), 0, 0, 0, 1);
        }

        // Фаза 5 (B5): консервативный cumulative-cap. ПРЕ-чек до обработки:
        // существующие записи target + строки файла не должны превышать лимит
        // сейфа. Осознанно консервативен: при skip реальные дубли пропускаются
        // (реальный прирост меньше), а dryRun показывает тот же отказ —
        // защита от раздувания сейфа массовым импортом важнее точности
        // оценки прироста. REST — 413 (PayloadTooLargeException), web — flash.
        long existingEntries = vaultEntryRepository.countByUser_Id(target.getId());
        if (existingEntries + rows.size() > MAX_EXPORT_ROWS) {
            throw new PayloadTooLargeException(
                    "Cumulative vault limit exceeded: existing entries ("
                            + existingEntries + ") + CSV rows (" + rows.size()
                            + ") > " + MAX_EXPORT_ROWS);
        }

        SecretKey dek = unwrapDek(target);
        Map<String, VaultEntry> conflictIndex = buildConflictIndex(target, dek);

        int created = 0;
        int updated = 0;
        int skipped = 0;
        int failed = 0;
        List<ImportError> errors = new ArrayList<>();
        Instant now = clock.instant();

        for (int i = 0; i < rows.size(); i++) {
            int rowNumber = i + 1; // 1-based, исключая заголовок
            CsvExportRow row = rows.get(i);
            try {
                validate(row);
            } catch (InvalidCsvException e) {
                failed++;
                errors.add(new ImportError(rowNumber, "invalid row: " + e.getMessage()));
                if (failFast) {
                    throw new InvalidCsvException(
                            "Row " + rowNumber + ": " + e.getMessage(), e);
                }
                continue;
            }

            String key = conflictKey(row);
            VaultEntry conflict = conflictIndex.get(key);

            if (conflict != null && strategy == ConflictStrategy.SKIP) {
                skipped++;
                continue;
            }

            try {
                if (conflict != null) {
                    // dryRun: НЕ мутируем управляемую JPA-сущность. Иначе
                    // Hibernate на commit сделает UPDATE через dirty-checking,
                    // что нарушает контракт dry-run (план, раздел 2.5).
                    if (!dryRun) {
                        applyUpdate(conflict, row, dek, now);
                        vaultEntryRepository.saveAndFlush(conflict);
                    }
                    updated++;
                } else {
                    VaultEntry entry = buildNew(target, row, dek, now);
                    if (!dryRun) {
                        vaultEntryRepository.saveAndFlush(entry);
                    }
                    created++;
                }
            } catch (RuntimeException e) {
                failed++;
                errors.add(new ImportError(rowNumber,
                        "db error: " + e.getClass().getSimpleName()));
                if (failFast) {
                    throw e;
                }
            }
        }

        // Фаза 5: в отчёте — первые MAX_IMPORT_ERRORS ошибок + сентинел;
        // failed остаётся точным (REST-схема отчёта стабильна).
        List<ImportError> reportedErrors = errors;
        if (errors.size() > MAX_IMPORT_ERRORS) {
            int hidden = errors.size() - MAX_IMPORT_ERRORS;
            List<ImportError> capped =
                    new ArrayList<>(errors.subList(0, MAX_IMPORT_ERRORS));
            capped.add(new ImportError(0, "... ещё " + hidden + " ошибок (показаны первые "
                    + MAX_IMPORT_ERRORS + ")"));
            reportedErrors = capped;
        }

        return finalizeImport(actor, target, strategy, dryRun, sha256, csvBytes.length,
                List.of(), reportedErrors, rows.size(), created, updated, skipped, failed);
    }

    // -- internals -----------------------------------------------------------

    /**
     * Финализация импорта: формирует отчёт, пишет аудит, логирует агрегаты.
     * При {@code dryRun=true} — никаких изменений в БД не сделано, но событие
     * VAULT_IMPORTED всё равно пишется (решение пользователя, план, п.5.3).
     */
    private ImportReport finalizeImport(User actor, User target,
                                        ConflictStrategy strategy, boolean dryRun,
                                        String sha256, int bytes,
                                        List<CsvExportRow> applied,
                                        List<ImportError> errors,
                                        int totalRows, int created, int updated,
                                        int skipped, int failed) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("target", target.getUsername());
        details.put("totalRows", totalRows);
        details.put("created", created);
        details.put("updated", updated);
        details.put("skipped", skipped);
        details.put("failed", failed);
        details.put("strategy", strategy.name());
        details.put("csvSha256", sha256);
        details.put("csvBytes", bytes);
        details.put("dryRun", dryRun);
        auditService.record(actor, AuditService.VAULT_IMPORTED, null, details);

        log.info("Vault imported: actor={}, target={}, total={}, created={}, updated={}, "
                        + "skipped={}, failed={}, dryRun={}",
                actor.getUsername(), target.getUsername(), totalRows, created, updated,
                skipped, failed, dryRun);

        return new ImportReport(totalRows, created, updated, skipped, failed,
                List.copyOf(errors), clock.instant(), dryRun);
    }

    /** Расшифровывает все поля записи для CSV-строки. Не логирует plaintext. */
    private CsvExportRow toRow(VaultEntry entry, SecretKey dek) {
        return new CsvExportRow(
                safeDecrypt(entry.getNameEnc(), dek),
                safeDecrypt(entry.getSiteEnc(), dek),
                safeDecrypt(entry.getLoginEnc(), dek),
                safeDecrypt(entry.getPasswordEnc(), dek),
                entry.getNotesEnc() == null ? "" : safeDecrypt(entry.getNotesEnc(), dek));
    }

    /**
     * Безопасная расшифровка: при ошибке возвращает пустую строку. Ошибка
     * расшифровки при экспорте логируется (без секретов), но не прерывает
     * выдачу — пользователь всё равно получает CSV со всеми «хорошими»
     * записями.
     */
    private String safeDecrypt(String containerBase64, SecretKey dek) {
        try {
            return cryptoService.decrypt(containerBase64, dek);
        } catch (RuntimeException e) {
            log.warn("Failed to decrypt field during export; row will have empty value");
            return "";
        }
    }

    /** Карта конфликтов по паре (site, username) → запись. */
    private Map<String, VaultEntry> buildConflictIndex(User target, SecretKey dek) {
        Map<String, VaultEntry> idx = new HashMap<>();
        for (VaultEntry entry : vaultEntryRepository
                .findAllByUser_IdOrderByCreatedAtAsc(target.getId())) {
            try {
                String site = cryptoService.decrypt(entry.getSiteEnc(), dek);
                String login = cryptoService.decrypt(entry.getLoginEnc(), dek);
                idx.put((site == null ? "" : site).toLowerCase()
                        + "\u0001" + (login == null ? "" : login).toLowerCase(), entry);
            } catch (RuntimeException e) {
                // Битая запись пропускается.
                log.warn("Skipping undecryptable entry when building conflict index");
            }
        }
        return idx;
    }

    /** Ключ конфликта — пара (site, username) в нижнем регистре. */
    private String conflictKey(CsvExportRow row) {
        return (row.url() == null ? "" : row.url()).toLowerCase()
                + "\u0001" + (row.username() == null ? "" : row.username()).toLowerCase();
    }

    /** Сервисная валидация одной строки CSV. */
    private void validate(CsvExportRow row) {
        if (row.name() == null || row.name().isBlank()) {
            throw new InvalidCsvException("name is blank");
        }
        if (row.name().length() > MAX_NAME_LEN) {
            throw new InvalidCsvException("name too long");
        }
        if (row.url() != null && row.url().length() > MAX_URL_LEN) {
            throw new InvalidCsvException("url too long");
        }
        if (row.username() == null || row.username().isBlank()) {
            throw new InvalidCsvException("username is blank");
        }
        if (row.username().length() > MAX_USERNAME_LEN) {
            throw new InvalidCsvException("username too long");
        }
        if (row.password() == null || row.password().isBlank()) {
            throw new InvalidCsvException("password is blank");
        }
        if (row.password().length() > MAX_PASSWORD_LEN) {
            throw new InvalidCsvException("password too long");
        }
        if (row.note() != null && row.note().length() > MAX_NOTE_LEN) {
            throw new InvalidCsvException("note too long");
        }
    }

    /** Перешифровывает поля существующей записи новыми IV. */
    private void applyUpdate(VaultEntry entry, CsvExportRow row, SecretKey dek, Instant now) {
        String nameEnc = cryptoService.encrypt(nullToEmpty(row.name()), dek);
        String siteEnc = cryptoService.encrypt(nullToEmpty(row.url()), dek);
        String loginEnc = cryptoService.encrypt(row.username(), dek);
        String passwordEnc = cryptoService.encrypt(row.password(), dek);
        String notesEnc = (row.note() == null || row.note().isEmpty())
                ? null
                : cryptoService.encrypt(row.note(), dek);
        entry.updateEncrypted(nameEnc, siteEnc, loginEnc, passwordEnc, notesEnc, now);
    }

    /** Создаёт новую запись (id генерируется здесь, createdAt = now). */
    private VaultEntry buildNew(User target, CsvExportRow row, SecretKey dek, Instant now) {
        String nameEnc = cryptoService.encrypt(nullToEmpty(row.name()), dek);
        String siteEnc = cryptoService.encrypt(nullToEmpty(row.url()), dek);
        String loginEnc = cryptoService.encrypt(row.username(), dek);
        String passwordEnc = cryptoService.encrypt(row.password(), dek);
        String notesEnc = (row.note() == null || row.note().isEmpty())
                ? null
                : cryptoService.encrypt(row.note(), dek);
        return new VaultEntry(
                UUID.randomUUID(),
                target,
                nameEnc,
                siteEnc,
                loginEnc,
                passwordEnc,
                notesEnc,
                now,
                null,
                null);
    }

    private void requireOwnerOrAdmin(User actor, User target) {
        if (actor == null || target == null) {
            throw new IllegalArgumentException("actor and target must be non-null");
        }
        boolean isOwner = actor.getId() != null && actor.getId().equals(target.getId());
        boolean isAdmin = "ROLE_ADMIN".equals(actor.getRole());
        if (!isOwner && !isAdmin) {
            throw new AccessDeniedException("Cannot access another user's vault");
        }
    }

    private SecretKey unwrapDek(User owner) {
        return cryptoService.unwrapDek(new WrappedDek(
                owner.getDekWrapped(), owner.getDekIv(), owner.getDekKekId()));
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    /** SHA-256 от CSV с нормализацией CRLF → LF (для стабильности хэша). */
    private String sha256Canonical(byte[] csv) {
        try {
            byte[] normalized = new String(csv, StandardCharsets.UTF_8)
                    .replace("\r\n", "\n")
                    .getBytes(StandardCharsets.UTF_8);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(normalized);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 гарантированно есть в JDK.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}