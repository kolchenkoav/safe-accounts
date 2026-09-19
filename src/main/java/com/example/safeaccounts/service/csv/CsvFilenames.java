package com.example.safeaccounts.service.csv;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * HTTP-хелпер выгрузки CSV: имена файлов (filename в Content-Disposition)
 * и warning-заголовок ответа. Вызывают только контроллеры api и web; сам
 * экспортный сервис ({@code VaultExportImportService}) его не использует.
 * Размещён в {@code service.csv} как общая зона api и web (P5) — перенос
 * в отдельный пакет сочтён избыточным (потребовал бы правки AGENTS.md).
 */
public final class CsvFilenames {

    /** Заголовок-предупреждение о plaintext-паролях в выгружаемом CSV. */
    public static final String EXPORT_WARNING_HEADER = "X-Vault-Export-Warning";
    public static final String EXPORT_WARNING_VALUE = "csv-contains-plaintext-passwords";

    private CsvFilenames() {
    }

    /** Собственный сейф пользователя: {@code vault-<username>-<timestamp>.csv}. */
    public static String forUser(String username, Instant now) {
        return "vault-" + safeFilenamePart(username) + "-" + compactTimestamp(now) + ".csv";
    }

    /** Административный экспорт чужого сейфа: {@code vault-user-<username>-<timestamp>.csv}. */
    public static String forTargetUser(String username, Instant now) {
        return "vault-user-" + safeFilenamePart(username) + "-" + compactTimestamp(now)
                + ".csv";
    }

    /** Отчёт скана слабых паролей: {@code scan-report-<username>-<timestamp>.csv}. */
    public static String forScanReport(String username, Instant now) {
        return "scan-report-" + safeFilenamePart(username) + "-" + compactTimestamp(now)
                + ".csv";
    }

    /**
     * Нейтральная часть имени файла из username: только [A-Za-z0-9._-]
     * (остальное → {@code _}). Кириллица и разделители путей безопасно
     * заменяются; «..» невозможен какPathComponent (точки сохраняются,
     * но без слэшей путь наверх не строится).
     */
    public static String safeFilenamePart(String value) {
        if (value == null || value.isEmpty()) {
            return "user";
        }
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    /** ISO-8601 compact без «:» и «.» (Windows-совместимо): {@code 20250612T100000Z}. */
    public static String compactTimestamp(Instant instant) {
        return DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                .withZone(ZoneOffset.UTC)
                .format(instant);
    }
}
