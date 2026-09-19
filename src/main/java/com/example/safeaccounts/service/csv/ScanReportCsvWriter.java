package com.example.safeaccounts.service.csv;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

/**
 * CSV-экспорт отчёта скана слабых паролей (G2, возврат фичи из revert
 * 564d121 как нормальная фича). Формат: преамбула-агрегаты строками
 * {@code # ...} (комментарий), затем заголовок и строки слабых записей.
 *
 * <p><b>Безопасность:</b> колонок с паролем НЕТ (только метаданные и
 * причины) — поэтому в отличие от vault-export предупреждение
 * {@code X-Vault-Export-Warning} на этот файл НЕ ставится; Cache-Control:
 * no-store сохранён (данные сейфа). RFC 4180: экранирование через
 * {@link #escape(String)} (запятая/кавычка/перевод строки).
 */
@Component
public class ScanReportCsvWriter {

    private static final DateTimeFormatter TS = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

    static final String HEADER = "name,url,username,reasons,score,password_length,"
            + "reuse_count,entry_id";

    /**
     * @param username  имя владельца сейфа (для преамбулы)
     * @param scannedAt время скана (для преамбулы)
     * @param scanned   агрегат: проверено
     * @param weakCount агрегат: слабых
     * @param tagged    агрегат: помечено
     * @param untagged  агрегат: снято
     * @param failed    агрегат: ошибок расшифровки
     * @param truncated агрегат: лимит записей превышен
     * @param weakEntries слабые записи (name/site/login/reasons/score/…)
     * @param includeBom true — начать вывод с UTF-8 BOM (для Excel)
     * @return UTF-8 байты готового CSV
     */
    public byte[] write(String username, Instant scannedAt, int scanned, int weakCount,
                        int tagged, int untagged, int failed, boolean truncated,
                        List<VaultScanWeakRow> weakEntries, boolean includeBom) {
        StringBuilder sb = new StringBuilder();
        // Префамбула-агрегаты: строки '#' (не колонки данных).
        sb.append("# Weak password scan report\r\n");
        sb.append("# target,").append(escape(username)).append("\r\n");
        sb.append("# scanned_at,").append(escape(TS.format(scannedAt))).append("\r\n");
        sb.append("# scanned,").append(scanned).append("\r\n");
        sb.append("# weak,").append(weakCount).append("\r\n");
        sb.append("# tagged,").append(tagged).append("\r\n");
        sb.append("# untagged,").append(untagged).append("\r\n");
        sb.append("# failed,").append(failed).append("\r\n");
        sb.append("# truncated,").append(truncated).append("\r\n");
        // Примечание о снимке: записи, изменённые ПОСЛЕ скана, не отражены.
        sb.append("# Снимок отчёта: ").append(TS.format(scannedAt)).append(
                "; записи, изменённые после скана, в файле не отражены\r\n");
        sb.append(HEADER).append("\r\n");
        for (VaultScanWeakRow row : weakEntries) {
            sb.append(escape(guardFormula(row.name()))).append(',');
            sb.append(escape(guardFormula(row.site()))).append(',');
            sb.append(escape(guardFormula(row.username()))).append(',');
            sb.append(escape(guardFormula(String.join("; ", row.reasons())))).append(',');
            sb.append(row.score() == null ? "" : String.valueOf(row.score())).append(',');
            sb.append(row.passwordLength()).append(',');
            sb.append(row.reuseCount()).append(',');
            sb.append(row.entryId()).append("\r\n");
        }
        byte[] body = sb.toString().getBytes(StandardCharsets.UTF_8);
        if (includeBom) {
            byte[] out = new byte[CsvWriter.BOM.length + body.length];
            System.arraycopy(CsvWriter.BOM, 0, out, 0, CsvWriter.BOM.length);
            System.arraycopy(body, 0, out, CsvWriter.BOM.length, body.length);
            return out;
        }
        return body;
    }

    /** RFC 4180-экранирование (тот же алгоритм, что в {@code CsvWriter}). */
    static String escape(String value) {
        if (value == null) {
            return "";
        }
        boolean mustQuote = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ',' || c == '"' || c == '\n' || c == '\r') {
                mustQuote = true;
                break;
            }
        }
        if (!mustQuote) {
            return value;
        }
        StringBuilder sb = new StringBuilder(value.length() + 4);
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"') {
                sb.append('"').append('"');
            } else {
                sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Formula-injection гвард (CSV Tool Injection): ячейки, начинающиеся
     * с = + - @ TAB, Excel интерпретирует как формулы (например,
     * {@code =WEBSERVICE(...)} — экзфильтрация данных на открытие файла).
     * Значения из пользовательских полей сейфа (name/site/login) с такими
     * ведущими символами получают префикс {@code '}. BOM-опция этого файла
     * целится именно в Excel — гвард обязателен. Числовые колонки не
     * трогаются.
     */
    static String guardFormula(String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }
        char first = value.charAt(0);
        if (first == '=' || first == '+' || first == '-' || first == '@'
                || first == '\t') {
            return "'" + value;
        }
        return value;
    }

    /** Одна строка CSV-отчёта (данные из VaultScanService.WeakEntry). */
    public record VaultScanWeakRow(String name, String site, String username,
                                   List<String> reasons, Integer score,
                                   int passwordLength, int reuseCount,
                                   UUID entryId) {
    }
}
