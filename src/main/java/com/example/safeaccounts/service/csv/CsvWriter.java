package com.example.safeaccounts.service.csv;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

/**
 * Сервис-утилита записи CSV в формате Google Chrome Password Manager
 * (5 колонок строго в порядке {@code name,url,username,password,note}).
 * <p>
 * Реализация по RFC 4180:
 * <ul>
 *   <li>разделитель — запятая {@code ,};</li>
 *   <li>строка заканчивается CRLF;</li>
 *   <li>значение оборачивается в {@code "..."}, если содержит запятую,
 *       кавычку или перевод строки;</li>
 *   <li>внутренние кавычки удваиваются ({@code ""} → {@code "});</li>
 *   <li>кодировка — UTF-8;</li>
 *   <li>BOM UTF-8 ({@code EF BB BF}) добавляется по запросу.</li>
 * </ul>
 * <p>
 * Никаких внешних библиотек (нет opencsv/commons-csv/univocity).
 */
@Component
public class CsvWriter {

    /** Заголовок — строго в этом порядке. */
    static final String HEADER = "name,url,username,password,note";

    /** BOM UTF-8. */
    static final byte[] BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    /**
     * Сериализует строки в байты CSV.
     *
     * @param rows       строки данных (без заголовка); пустой список допустим
     * @param includeBom {@code true} — начать вывод с UTF-8 BOM
     * @return UTF-8 байты готового CSV
     */
    public byte[] write(java.util.List<CsvExportRow> rows, boolean includeBom) {
        StringBuilder sb = new StringBuilder();
        sb.append(HEADER).append("\r\n");
        for (CsvExportRow row : rows) {
            sb.append(escape(row.name())).append(',');
            sb.append(escape(row.url())).append(',');
            sb.append(escape(row.username())).append(',');
            sb.append(escape(row.password())).append(',');
            sb.append(escape(row.note())).append("\r\n");
        }
        byte[] body = sb.toString().getBytes(StandardCharsets.UTF_8);
        if (includeBom) {
            byte[] out = new byte[BOM.length + body.length];
            System.arraycopy(BOM, 0, out, 0, BOM.length);
            System.arraycopy(body, 0, out, BOM.length, body.length);
            return out;
        }
        return body;
    }

    /**
     * Экранирует значение по RFC 4180: если значение содержит запятую, кавычку
     * или перевод строки — оборачивается в {@code "..."} с удвоением внутренних кавычек.
     */
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
}