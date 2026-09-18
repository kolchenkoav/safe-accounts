package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.ScanRateLimitedException;
import com.example.safeaccounts.service.VaultExportImportService;
import com.example.safeaccounts.service.VaultScanService;
import com.example.safeaccounts.service.VaultService;
import com.example.safeaccounts.service.csv.ConflictStrategy;
import com.example.safeaccounts.service.csv.CsvFilenames;
import com.example.safeaccounts.service.csv.ExportPayload;
import com.example.safeaccounts.service.csv.ImportReport;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

/**
 * CRUD API записей сейфа (Task-05), экспорт/импорт (Task-07/08, Фаза 5).
 * Контроллер тонкий: вся бизнес-логика и шифрование — в {@link VaultService}
 * и {@link VaultExportImportService}.
 * <p>
 * Безопасность: пароли в списках не возвращаются; расшифрованный пароль
 * отдается только при явном {@code ?reveal=true} и только владельцу.
 * Пароли и шифротексты никогда не логируются.
 */
@RestController
@RequestMapping("/api/vault")
public class VaultController {

    /** Заголовок-предупреждение о plaintext-паролях в CSV (план, раздел 5 п.7). */
    static final String EXPORT_WARNING_HEADER = "X-Vault-Export-Warning";

    /** Значение заголовка (фиксированное — для интеграторов и мониторинга). */
    static final String EXPORT_WARNING_VALUE = "csv-contains-plaintext-passwords";

    /** Имя multipart-поля для CSV-файла. */
    static final String IMPORT_FILE_PART = "file";

    private final VaultService vaultService;
    private final VaultExportImportService exportImportService;
    private final VaultScanService scanService;

    public VaultController(VaultService vaultService,
                           VaultExportImportService exportImportService,
                           VaultScanService scanService) {
        this.vaultService = vaultService;
        this.exportImportService = exportImportService;
        this.scanService = scanService;
    }

    /** Список записей текущего пользователя (без паролей и notes). */
    @GetMapping
    public PageResponse<VaultEntryListItemResponse> list(
            @AuthenticationPrincipal AuthUser principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<VaultService.ListItem> items = vaultService.list(currentUser(principal), page, size);
        return new PageResponse<>(
                items.getNumber(),
                items.getSize(),
                items.getTotalElements(),
                items.getTotalPages(),
                items.getContent().stream()
                        .map(i -> new VaultEntryListItemResponse(
                                i.id(), i.name(), i.site(), i.login(),
                                i.createdAt(), i.updatedAt(),
                                i.version() == null ? 0L : i.version()))
                        .toList());
    }

    /** Создание записи: все чувствительные поля шифруются DEK владельца. */
    @PostMapping
    public ResponseEntity<VaultEntryDetailResponse> create(
            @AuthenticationPrincipal AuthUser principal,
            @Valid @RequestBody VaultEntryCreateRequest request) {
        VaultService.CreatedEntry created = vaultService.create(
                currentUser(principal),
                request.name(),
                request.site(), request.login(), request.password(), request.notes());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(VaultEntryDetailResponse.withoutPassword(
                        created.entry().getId(),
                        created.name(),
                        created.site(),
                        created.login(),
                        request.notes(),
                        created.entry().getCreatedAt(),
                        created.entry().getUpdatedAt(),
                        0L));
    }

    /**
     * Детальный просмотр записи владельца. Пароль возвращается только при
     * {@code ?reveal=true}; факт reveal фиксируется в аудите.
     */
    @GetMapping("/{id}")
    public VaultEntryDetailResponse get(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @RequestParam(defaultValue = "false") boolean reveal) {
        VaultService.DecryptedEntry entry = vaultService.get(currentUser(principal), id, reveal);
        return new VaultEntryDetailResponse(
                id,
                entry.name(),
                entry.site(),
                entry.login(),
                entry.password(),
                entry.notes(),
                entry.createdAt() != null ? entry.createdAt() : null,
                entry.updatedAt(),
                0L);
    }

    /** Обновление записи владельца: поля перешифровываются новыми IV. */
    @PutMapping("/{id}")
    public VaultEntryDetailResponse update(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @Valid @RequestBody VaultEntryUpdateRequest request) {
        VaultService.UpdatedEntry updated = vaultService.update(
                currentUser(principal),
                id,
                request.name(),
                request.site(), request.login(), request.password(), request.notes());
        return new VaultEntryDetailResponse(
                id,
                updated.name(),
                updated.site(),
                updated.login(),
                null,
                request.notes(),
                updated.entry().getCreatedAt(),
                updated.entry().getUpdatedAt(),
                updated.entry().getVersion() == null ? 0L : updated.entry().getVersion());
    }

    /** Удаление записи владельца. Чужая запись неотличима от несуществующей (404). */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id) {
        vaultService.delete(currentUser(principal), id);
        return ResponseEntity.noContent().build();
    }

    // -- export / import (Task-07 / Task-08, Фаза 5) -------------------------

    /**
     * Экспорт собственного сейфа в CSV (Google Chrome Password Manager формат).
     * <p>
     * Заголовок {@code X-Vault-Export-Warning: csv-contains-plaintext-passwords}
     * обязателен (план 5 п.7). Имя файла — {@code vault-<username>-<ISO8601>.csv},
     * без двоеточий и точек в timestamp (для совместимости с Windows-клиентами).
     */
    @GetMapping("/export")
    public ResponseEntity<byte[]> export(
            @AuthenticationPrincipal AuthUser principal,
            @RequestParam(defaultValue = "false") boolean bom) {
        User actor = currentUser(principal);
        ExportPayload payload = exportImportService.export(actor, actor, bom);

        String filename = CsvFilenames.forUser(actor.getUsername(), Instant.now());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("text/csv; charset=utf-8"));
        headers.set(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"");
        headers.add(EXPORT_WARNING_HEADER, EXPORT_WARNING_VALUE);
        // Длина тела известна заранее.
        headers.setContentLength(payload.csv().length);
        // Plaintext-экспорт не должен кэшироваться (паритет с web, Фаза 5).
        headers.setCacheControl("no-store");
        return new ResponseEntity<>(payload.csv(), headers, HttpStatus.OK);
    }

    /**
     * Импорт CSV в собственный сейф.
     * <p>
     * multipart/form-data: {@code file} (CSV, обязательно), {@code conflictStrategy}
     * ({@code skip|upsert}, default {@code skip}).
     * Query: {@code ?dryRun=true|false}, {@code ?failFast=true|false}.
     */
    @PostMapping(path = "/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImportReport> importCsv(
            @AuthenticationPrincipal AuthUser principal,
            @RequestPart(IMPORT_FILE_PART) MultipartFile file,
            @RequestParam(defaultValue = "skip") String conflictStrategy,
            @RequestParam(defaultValue = "false") boolean dryRun,
            @RequestParam(defaultValue = "false") boolean failFast) throws IOException {
        User actor = currentUser(principal);
        ConflictStrategy strategy = parseConflictStrategy(conflictStrategy);
        if (file == null || file.isEmpty()) {
            throw new InvalidCsvException("CSV file is empty");
        }
        byte[] csvBytes = file.getBytes();
        ImportReport report = exportImportService.importFromCsv(
                actor, actor, csvBytes, strategy, dryRun, failFast);
        return ResponseEntity.ok(report);
    }

    /** Пользователь из Bearer-principal (User — LAZY, данные уже зафиксированы). */
    private static User currentUser(AuthUser principal) {
        return principal.user();
    }

    /**
     * Простой пагинированный ответ без зависимости от Spring Data в контракте API.
     * P5/A2: обе формы (здесь и в api.PageResponse) 5-полевые и идентичные;
     * nested оставлен для минимизации churn — унификация использования
     * (один record на оба контроллера) — отдельная задача, сейчас не делалась.
     */
    public record PageResponse<T>(
            int page,
            int size,
            long totalElements,
            int totalPages,
            List<T> content) {
    }

    /** Сканер слабых паролей (G2): классификация + синхронизация тега weak-password. */
    @PostMapping("/scan")
    public VaultScanService.ScanReport scan(@AuthenticationPrincipal AuthUser principal) {
        User actor = currentUser(principal);
        return scanService.scan(actor, actor);
    }

    // -- export/import helpers ------------------------------------------------

    /**
     * Нейтральная часть имени файла из username: только [A-Za-z0-9._-].
     * Остальные символы заменяются на {@code _}.
     */
    static String safeFilenamePart(String value) {
        return CsvFilenames.safeFilenamePart(value);
    }

    /** ISO-8601 compact (без {@code :} и {@code .}): {@code 20250612T100000Z}. */
    static String compactTimestamp(Instant instant) {
        return CsvFilenames.compactTimestamp(instant);
    }

    /** Парсит {@code conflictStrategy} из multipart-параметра. */
    static ConflictStrategy parseConflictStrategy(String value) {
        if (value == null || value.isBlank()) {
            return ConflictStrategy.SKIP;
        }
        String normalized = value.trim().toLowerCase(java.util.Locale.ROOT);
        return switch (normalized) {
            case "skip" -> ConflictStrategy.SKIP;
            case "upsert" -> ConflictStrategy.UPSERT;
            default -> throw new IllegalArgumentException(
                    "conflictStrategy must be 'skip' or 'upsert', got: " + value);
        };
    }
}
