package com.example.safeaccounts.service.csv;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Парсер CSV по RFC 4180 без внешних зависимостей:
 * <ul>
 *   <li>UTF-8 (BOM {@code EF BB BF} снимается автоматически);</li>
 *   <li>разделитель — запятая {@code ,};</li>
 *   <li>поддержка CRLF / LF / CR как разделителей строк;</li>
 *   <li>поддержка кавычек {@code "..."} и удвоения внутренней кавычки {@code ""};</li>
 *   <li>пустые значения корректно ({@code a,,b});</li>
 *   <li>лишние колонки (после 5-й) тихо игнорируются при разборе
 *       в {@link CsvExportRow} (см. {@link #parseDataRows}).</li>
 * </ul>
* <p>
 * Класс stateless — {@code @Component}-бин, может также создаваться через {@code new}
 * в unit-тестах без поднятия Spring-контекста.
 */
@Component
public class CsvParser {

    /**
     * Полный разбор CSV в {@code List<List<String>>}. Первая строка — заголовок.
     */
    public List<List<String>> parse(byte[] csvBytes) {
        if (csvBytes == null) {
            throw new InvalidCsvException("CSV payload is null");
        }
        byte[] body = stripBom(csvBytes);
        String text = new String(body, StandardCharsets.UTF_8);
        return parseText(text);
    }

    /**
     * Проверяет заголовок: ровно первые 5 колонок должны быть
     * {@code name,url,username,password,note} в этом порядке.
     * Лишние колонки после 5-й допускаются и игнорируются.
     *
     * @return список имён первых 5 колонок (для повторного использования)
     * @throws InvalidCsvException если заголовок отсутствует или нарушен порядок
     */
    public List<String> parseFirstRowAsHeader(byte[] csvBytes) {
        List<List<String>> rows = parse(csvBytes);
        if (rows.isEmpty()) {
            throw new InvalidCsvException("CSV is empty");
        }
        List<String> header = rows.get(0);
        if (header.size() < 5) {
            throw new InvalidCsvException(
                    "CSV header must contain at least 5 columns (name,url,username,password,note); got "
                            + header.size());
        }
        String[] expected = {"name", "url", "username", "password", "note"};
        for (int i = 0; i < expected.length; i++) {
            if (!expected[i].equals(header.get(i))) {
                // TP A1: содержимое ячейки НЕ подставляем в сообщение —
                // данные файла не должны попадать в ответы об ошибках.
                throw new InvalidCsvException(
                        "CSV header column " + (i + 1) + " must be '" + expected[i] + "'");
            }
        }
        return Arrays.asList(expected);
    }

    /**
     * Парсит CSV и возвращает только строки данных (без заголовка) в виде
     * {@link CsvExportRow}. Колонки после 5-й тихо отбрасываются.
     *
     * @throws InvalidCsvException при ошибке парсинга/заголовка
     */
    public List<CsvExportRow> parseDataRows(byte[] csvBytes) {
        parseFirstRowAsHeader(csvBytes); // проверить заголовок
        List<List<String>> rows = parse(csvBytes);
        List<CsvExportRow> result = new ArrayList<>(Math.max(0, rows.size() - 1));
        for (int idx = 1; idx < rows.size(); idx++) {
            List<String> r = rows.get(idx);
            // Полностью пустая строка (одно поле "") — игнорируем.
            if (r.size() == 1 && r.get(0).isEmpty()) {
                continue;
            }
            if (r.size() < 5) {
                throw new InvalidCsvException(
                        "CSV row " + (idx + 1) + " has " + r.size()
                                + " columns; expected at least 5");
            }
            // Лишние колонки после 5-й молча отбрасываются.
            result.add(new CsvExportRow(
                    r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)));
        }
        return result;
    }

    // -- internals -----------------------------------------------------------

    /**
     * Состояние конечного автомата парсера.
     * Парсим строку {@code text} как последовательность char'ов UTF-16 —
     * это правильно работает для любых Unicode-символов (Cyrillic, CJK и т.п.).
     */
    private List<List<String>> parseText(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> current = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        int len = text.length();
        int i = 0;
        boolean started = false; // была ли уже непустая запись в текущей строке
        while (i < len) {
            char c = text.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < len && text.charAt(i + 1) == '"') {
                        field.append('"');
                        i += 2;
                        continue;
                    }
                    inQuotes = false;
                    i++;
                    continue;
                }
                // Внутри кавычек перевод строки — часть значения.
                if (c == '\n' || c == '\r') {
                    if (c == '\r' && i + 1 < len && text.charAt(i + 1) == '\n') {
                        field.append('\r').append('\n');
                        i += 2;
                    } else {
                        field.append(c);
                        i++;
                    }
                    continue;
                }
                field.append(c);
                i++;
                continue;
            }
            // Вне кавычек.
            if (c == '"') {
                inQuotes = true;
                started = true;
                i++;
                continue;
            }
            if (c == ',') {
                current.add(field.toString());
                field.setLength(0);
                started = true;
                i++;
                continue;
            }
            if (c == '\n' || c == '\r') {
                current.add(field.toString());
                field.setLength(0);
                if (started || !current.isEmpty()) {
                    rows.add(current);
                }
                current = new ArrayList<>();
                started = false;
                if (c == '\r' && i + 1 < len && text.charAt(i + 1) == '\n') {
                    i += 2;
                } else {
                    i++;
                }
                continue;
            }
            field.append(c);
            started = true;
            i++;
        }
        if (started || field.length() > 0 || !current.isEmpty()) {
            current.add(field.toString());
            if (!current.isEmpty()) {
                rows.add(current);
            }
        }
        return rows;
    }

    /** Снимает UTF-8 BOM, если он есть. */
    static byte[] stripBom(byte[] input) {
        if (input.length >= 3
                && (input[0] & 0xFF) == 0xEF
                && (input[1] & 0xFF) == 0xBB
                && (input[2] & 0xFF) == 0xBF) {
            return Arrays.copyOfRange(input, 3, input.length);
        }
        return input;
    }
}