package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.WrappedDek;
import com.example.safeaccounts.security.RateLimiter;
import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Сканер слабых паролей (G2, план feat-weak-password-scan §3.3).
 *
 * <p>Порционно читает записи владельца (пагинация), расшифровывает пароли
 * DEK'ом владельца (паттерн {@code VaultService.get}, reveal), считает
 * повторное использование (SHA-256 расшифрованного пароля — в памяти скана,
 * в логи/отчёт не пишется), классифицирует через
 * {@link WeakPasswordEvaluator#evaluate} и синхронизирует служебный тег
 * {@link #WEAK_PASSWORD_TAG_NAME}: ставится слабым, снимается у тех, кто
 * стал сильным — точный diff, идемпотентно.
 *
 * <p>Лимит {@link #MAX_SCAN_ENTRIES} согласован с MAX_EXPORT_ROWS (10 000):
 * при превышении скан останавливается, в отчёте {@code truncated=true}.
 *
 * <p>Безопасность: пароли и причины не логируются; в аудит
 * ({@code VAULT_SCANNED}) пишутся только агрегаты (actor, target, scanned,
 * weak, tagged, untagged, truncated, durationMs).
 */
@Service
public class VaultScanService {

    private static final Logger log = LoggerFactory.getLogger(VaultScanService.class);

    /** Служебный per-user тег слабых записей (решение §7.3 плана). */
    public static final String WEAK_PASSWORD_TAG_NAME = "weak-password";

    /**
     * Кэш последнего скана (G2-отчёт, план feat-weak-password-report §2.2):
     * targetUserId → снимок отчёта. Single-instance — как RateLimiter; при
     * горизонтальном масштабировании нужен общий кэш. Инвалидация — только
     * новый скан (правки записей НЕ инвалидируют: отчёт — снимок, честность
     * обеспечивает scannedAt). Ключ кэша — TARGET: admin-скан пишет под
     * target'а, чтобы сам target видел свой отчёт.
     */
    private final java.util.concurrent.ConcurrentHashMap<UUID, CachedScan> lastScanByTarget =
            new java.util.concurrent.ConcurrentHashMap<>();

    /** Снимок последнего скана: отчёт + время + полные строки слабых записей. */
    public record CachedScan(ScanReport report, java.time.Instant scannedAt,
                             List<WeakEntry> weakEntries) {
    }

    /** Лимит записей скана — согласован с MAX_EXPORT_ROWS (10 000). */
    public static final int MAX_SCAN_ENTRIES = 10_000;

    private static final int PAGE_SIZE = 500;

    private final VaultEntryRepository vaultEntryRepository;
    private final TagService tagService;
    private final AesGcmCryptoService cryptoService;
    private final WeakPasswordEvaluator evaluator;
    private final ScanProperties scanProperties;
    private final AuditService auditService;
    private final RateLimiter rateLimiter;
    private final org.springframework.transaction.support.TransactionTemplate transactionTemplate;
    private final com.example.safeaccounts.service.csv.CsvWriter csvWriter;

    public VaultScanService(VaultEntryRepository vaultEntryRepository,
                            TagService tagService,
                            AesGcmCryptoService cryptoService,
                            WeakPasswordEvaluator evaluator,
                            ScanProperties scanProperties,
                            AuditService auditService,
                            RateLimiter rateLimiter,
                            org.springframework.transaction.support.TransactionTemplate transactionTemplate,
                            com.example.safeaccounts.service.csv.CsvWriter csvWriter) {
        this.vaultEntryRepository = vaultEntryRepository;
        this.tagService = tagService;
        this.cryptoService = cryptoService;
        this.evaluator = evaluator;
        this.scanProperties = scanProperties;
        this.auditService = auditService;
        this.rateLimiter = rateLimiter;
        this.transactionTemplate = transactionTemplate;
        this.csvWriter = csvWriter;
    }

    /** Слабая запись в отчёте: расшифрованные метаданные + причины (без пароля).
     *  score = null, если пароль длиннее гварда zxcvbn (не измерялся). */
    public record WeakEntry(UUID id, String name, String site, String login,
                            List<String> reasons, Integer score,
                            int passwordLength, int reuseCount) {
    }

    /**
     * @param scanned    сколько записей просмотрено
     * @param weakCount  сколько признаны слабыми
     * @param tagged     сколько тегов поставлено в этом скане
     * @param untagged   сколько тегов снято в этом скане
     * @param truncated  true, если лимит записей превышен
     * @param weakEntries слабые записи (name расшифрован — только владельцу/админу)
     */
    public record ScanReport(int scanned, int weakCount, int tagged, int untagged,
                             int failed, boolean truncated,
                             List<WeakEntry> weakEntries) {
    }

    /**
     * Последний скан сейфа target (кэш сервиса); пусто — скан ещё не запускался.
     */
    public java.util.Optional<CachedScan> lastScan(User target) {
        return java.util.Optional.ofNullable(lastScanByTarget.get(target.getId()));
    }

    /**
     * Скан сейфа {@code target} от лица {@code actor} (self или ADMIN).
     * Чтение/расшифровка/оценка — ВНЕ транзакции (репозитории авто-коммит
     * чтения); транзакция — только на фазу синхронизации тегов (fix MAJOR
     * «одна TX»: расшифровка 10k записей не держит TX/коннект).
     */
    public ScanReport scan(User actor, User target) {
        // Квота скана ПОСЛЕ аутентификации (Bearer-запросы на фазе фильтра ещё
        // не аутентифицированы — SecurityContext пуст): ключ user:<target>;
        // бакет BUCKET_SCAN (1/60 c по умолчанию). У админ-скана лимит — на
        // сканируемый сейф (защита операции, а не админа).
        var decision = rateLimiter.tryAcquireWithRetryAfter(
                "user:" + target.getUsername(), RateLimiter.BUCKET_SCAN);
        if (!decision.allowed()) {
            throw new ScanRateLimitedException(decision.retryAfterSeconds());
        }
        long startNanos = System.nanoTime();

        var dek = cryptoService.unwrapDek(new WrappedDek(
                target.getDekWrapped(), target.getDekIv(), target.getDekKekId()));
        Tag weakTag = tagService.findOrCreateByName(target, WEAK_PASSWORD_TAG_NAME);

        // Текущее множество помеченных (до скана) — для точного diff.
        Set<UUID> currentlyTagged = new HashSet<>();
        Pageable taggedPageable = PageRequest.of(0, 500);
        Page<VaultEntry> taggedPage;
        do {
            taggedPage = vaultEntryRepository.findAllByUser_IdAndTags_Id(
                    target.getId(), weakTag.getId(), taggedPageable);
            taggedPage.getContent().forEach(e -> currentlyTagged.add(e.getId()));
            taggedPageable = taggedPage.nextOrLastPageable();
        } while (taggedPage.hasNext());

        // Проход по страницам: расшифровка + reuse-детект (в памяти скана).
        // ВНЕ транзакции: чтения авто-коммитны, ошибки конкретной записи —
        // в счётчик failed, скан продолжается (TP MINOR).
        List<VaultEntry> scannedEntries = new ArrayList<>();
        List<String> decryptedPasswords = new ArrayList<>();
        Map<String, Integer> reuseCounts = new HashMap<>();
        boolean truncated = false;
        int scanned = 0;
        int failed = 0;
        int pageIndex = 0;
        Page<VaultEntry> page;
        do {
        // Пагинация с детерминированным Sort (createdAt, id) — TP: без него
        // конкурентные изменения дают дубли/пропуски между страницами.
            page = vaultEntryRepository.findAllByUser_Id(target.getId(),
                    PageRequest.of(pageIndex++, PAGE_SIZE,
                            org.springframework.data.domain.Sort.by(
                                    org.springframework.data.domain.Sort.Order.asc("createdAt"),
                                    org.springframework.data.domain.Sort.Order.asc("id"))));
            for (VaultEntry entry : page.getContent()) {
                if (scanned >= MAX_SCAN_ENTRIES) {
                    truncated = true;
                    break;
                }
                try {
                    String password = cryptoService.decrypt(entry.getPasswordEnc(), dek);
                    scannedEntries.add(entry);
                    decryptedPasswords.add(password);
                    reuseCounts.merge(sha256Hex(password), 1, Integer::sum);
                    scanned++;
                } catch (RuntimeException e) {
                    // Не логируем содержимое: только факт ошибки конкретной записи.
                    failed++;
                    log.warn("Vault scan: skip entry {} of target {}: decrypt failed",
                            entry.getId(), target.getUsername());
                }
            }
            if (truncated) {
                break;
            }
        } while (page.hasNext());

        // Классификация + расшифровка метаданных только для слабых.
        WeakScanConfig cfg = new WeakScanConfig(scanProperties.getWeakScore());
        Set<UUID> weakIds = new HashSet<>();
        List<WeakEntry> weakEntries = new ArrayList<>();
        for (int i = 0; i < scannedEntries.size(); i++) {
            VaultEntry entry = scannedEntries.get(i);
            String password = decryptedPasswords.get(i);
            var evalResult = evaluator.evaluateDetailed(
                    password, reuseCounts.getOrDefault(sha256Hex(password), 0), cfg);
            if (!evalResult.reasons().isEmpty()) {
                weakIds.add(entry.getId());
                String name = cryptoService.decrypt(entry.getNameEnc(), dek);
                String site = cryptoService.decrypt(entry.getSiteEnc(), dek);
                String login = cryptoService.decrypt(entry.getLoginEnc(), dek);
                weakEntries.add(new WeakEntry(entry.getId(), name, site, login,
                        List.copyOf(evalResult.reasons()), evalResult.score(),
                        password.length(),
                        reuseCounts.getOrDefault(sha256Hex(password), 0)));
            }
        }

        // Точный diff: ставим слабым, у исправившихся снимаем — в ТРАНЗАКЦИИ
        // (TransactionTemplate; entities пере-загружаются managed, т.к. чтение
        // шло вне TX). Пакетная обработка по 500 id.
        int tagged = 0;
        int untagged = 0;
        Set<UUID> scannedIds = new HashSet<>();
        for (VaultEntry entry : scannedEntries) {
            scannedIds.add(entry.getId());
        }
        List<UUID> toAttach = scannedEntries.stream()
                .filter(e -> weakIds.contains(e.getId())
                        && !currentlyTagged.contains(e.getId()))
                .map(VaultEntry::getId)
                .toList();
        List<UUID> toDetach = currentlyTagged.stream()
                .filter(id -> scannedIds.contains(id) && !weakIds.contains(id))
                .toList();
        List<UUID> attachIds = new ArrayList<>(toAttach);
        List<UUID> detachIds = new ArrayList<>(toDetach);
        transactionTemplate.executeWithoutResult(status -> {
            for (int from = 0; from < attachIds.size(); from += PAGE_SIZE) {
                vaultEntryRepository.findAllById(
                                attachIds.subList(from, Math.min(from + PAGE_SIZE, attachIds.size())))
                        .forEach(e -> {
                            if (target.getId().equals(e.getUser().getId())) {
                                e.getTags().add(weakTag);
                            }
                        });
            }
            for (int from = 0; from < detachIds.size(); from += PAGE_SIZE) {
                vaultEntryRepository.findAllById(
                                detachIds.subList(from, Math.min(from + PAGE_SIZE, detachIds.size())))
                        .forEach(e -> {
                            if (target.getId().equals(e.getUser().getId())) {
                                e.getTags().remove(weakTag);
                            }
                        });
            }
        });
        tagged = attachIds.size();
        untagged = detachIds.size();

        long durationMs = (System.nanoTime() - startNanos) / 1_000_000L;
        log.info("Vault scanned: actor={}, target={}, scanned={}, weak={}, tagged={}, "
                        + "untagged={}, failed={}, truncated={}, durationMs={}",
                actor.getUsername(), target.getUsername(), scanned, weakIds.size(),
                tagged, untagged, failed, truncated, durationMs);
        auditService.record(actor, AuditService.VAULT_SCANNED, null, "User",
                target.getId().toString(),
                Map.of("actor", actor.getUsername(),
                        "target", target.getUsername(),
                        "scanned", scanned,
                        "weak", weakIds.size(),
                        "tagged", tagged,
                        "untagged", untagged,
                        "failed", failed,
                        "truncated", truncated,
                        "durationMs", durationMs));

        // Кэш последнего скана — ПОД TARGET (admin-скан пишет под target'а).
        lastScanByTarget.put(target.getId(), new CachedScan(
                new ScanReport(scanned, weakIds.size(), tagged, untagged,
                        failed, truncated, List.copyOf(weakEntries)),
                java.time.Instant.now(), List.copyOf(weakEntries)));

        return lastScanByTarget.get(target.getId()).report();
    }

    /**
     * Собирает байты CSV полного отчёта скана (преамбула-агрегаты `#`,
     * колонки name,url,username,reasons,score,password_length,reuse_count,
     * entry_id — БЕЗ паролей) + пишет аудит VAULT_SCAN_REPORT_EXPORTED
     * (actor, target, weakCount, csvSha256, bytes, bom — только агрегаты).
     */
    public ScanCsvFile buildReportCsv(CachedScan cached,
                                      com.example.safeaccounts.domain.User actor,
                                      com.example.safeaccounts.domain.User target,
                                      boolean adminFilename, boolean bom) {
        var report = cached.report();
        java.util.List<java.util.List<String>> rows = new java.util.ArrayList<>();
        rows.add(java.util.List.of("# Отчёт по слабым паролям"));
        rows.add(java.util.List.of("# scanned_at: " + cached.scannedAt().toString()));
        rows.add(java.util.List.of("# проверено: " + report.scanned()));
        rows.add(java.util.List.of("# слабых: " + report.weakCount()));
        rows.add(java.util.List.of("# помечено: " + report.tagged()));
        rows.add(java.util.List.of("# снято: " + report.untagged()));
        rows.add(java.util.List.of("# ошибок чтения: " + report.failed()));
        rows.add(java.util.List.of("# неполный скан: " + (report.truncated() ? "да" : "нет")));
        rows.add(java.util.List.of("name", "url", "username", "reasons", "score",
                "password_length", "reuse_count", "entry_id"));
        for (WeakEntry weak : cached.weakEntries()) {
            rows.add(java.util.List.of(
                    weak.name(),
                    weak.site() == null ? "" : weak.site(),
                    weak.login() == null ? "" : weak.login(),
                    String.join("; ", weak.reasons()),
                    weak.score() == null ? ">200" : String.valueOf(weak.score()),
                    String.valueOf(weak.passwordLength()),
                    String.valueOf(weak.reuseCount()),
                    weak.id().toString()));
        }
        byte[] csv = csvWriter.writeRows(rows, bom);

        String filename = adminFilename
                ? com.example.safeaccounts.service.csv.CsvFilenames
                        .forScanTargetUser(target.getUsername(), java.time.Instant.now())
                : com.example.safeaccounts.service.csv.CsvFilenames
                        .forScan(target.getUsername(), java.time.Instant.now());

        long bytes = csv.length;
        auditService.record(actor, AuditService.VAULT_SCAN_REPORT_EXPORTED, null,
                "User", target.getId().toString(),
                Map.of("actor", actor.getUsername(),
                        "target", target.getUsername(),
                        "weakCount", report.weakCount(),
                        "csvSha256", sha256Hex(new String(csv, StandardCharsets.UTF_8)),
                        "bytes", bytes,
                        "bom", bom));
        return new ScanCsvFile(csv, filename);
    }

    /** Готовый CSV-файл отчёта: байты + имя файла для Content-Disposition. */
    public record ScanCsvFile(byte[] csv, String filename) {
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
