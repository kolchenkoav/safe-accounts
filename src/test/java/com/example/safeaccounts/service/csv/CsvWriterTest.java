package com.example.safeaccounts.service.csv;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты райтера {@link CsvWriter}: round-trip с парсером, экранирование,
 * BOM, строго 5 колонок.
 */
class CsvWriterTest {

    private final CsvWriter writer = new CsvWriter();
    private final CsvParser parser = new CsvParser();

    @Test
    void writesHeaderOnlyWhenNoRows() {
        byte[] out = writer.write(List.of(), false);
        String s = new String(out, StandardCharsets.UTF_8);
        assertThat(s).isEqualTo("name,url,username,password,note\r\n");
    }

    @Test
    void writesSimpleRowWithoutBom() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("Gmail", "https://gmail.com", "alice", "p", "n")
        ), false);
        String s = new String(out, StandardCharsets.UTF_8);
        assertThat(s).isEqualTo("name,url,username,password,note\r\n"
                + "Gmail,https://gmail.com,alice,p,n\r\n");
        assertThat(out[0]).isNotEqualTo((byte) 0xEF);
    }

@Test
    void writesUtf8BomWhenRequested() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("n", "u", "l", "p", "no")
        ), true);
        assertThat(out[0] & 0xFF).isEqualTo(0xEF);
        assertThat(out[1] & 0xFF).isEqualTo(0xBB);
        assertThat(out[2] & 0xFF).isEqualTo(0xBF);
        // Пропускаем BOM при сравнении содержимого.
        String s = new String(out, 3, out.length - 3, StandardCharsets.UTF_8);
        assertThat(s).isEqualTo("name,url,username,password,note\r\nn,u,l,p,no\r\n");
    }

    @Test
    void escapesCommaInValue() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("Hello, world", "u", "l", "p", "n")
        ), false);
        String s = new String(out, StandardCharsets.UTF_8);
        assertThat(s).contains("\"Hello, world\",u,l,p,n");
    }

    @Test
    void escapesDoubleQuoteInValue() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("He said \"hi\"", "u", "l", "p", "n")
        ), false);
        String s = new String(out, StandardCharsets.UTF_8);
        assertThat(s).contains("\"He said \"\"hi\"\"\",u,l,p,n");
    }

    @Test
    void escapesNewlineInValue() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("line1\nline2", "u", "l", "p", "n")
        ), false);
        String s = new String(out, StandardCharsets.UTF_8);
        assertThat(s).contains("\"line1\nline2\",u,l,p,n");
    }

    @Test
    void emptyStringIsNotQuoted() {
        // Пустая строка не должна оборачиваться в кавычки — иначе парсинг
        // не отличит её от "", которая обязана квотиться.
        String esc = CsvWriter.escape("");
        assertThat(esc).isEqualTo("");
    }

    @Test
    void strictFiveColumnsOrder() {
        byte[] out = writer.write(List.of(
                new CsvExportRow("n", "u", "l", "p", "note")
        ), false);
        String s = new String(out, StandardCharsets.UTF_8);
        String header = s.substring(0, s.indexOf("\r\n"));
        assertThat(header).isEqualTo("name,url,username,password,note");
    }

    @Test
    void roundTripPreservesValues() {
        List<CsvExportRow> rows = List.of(
                new CsvExportRow("Simple", "https://x.com", "user1", "p1", "n1"),
                new CsvExportRow("With, comma", "https://y.com", "user2", "p2", "n2"),
                new CsvExportRow("With \"quote\"", "https://z.com", "user3", "p3", "n3"),
                new CsvExportRow("Multi\nline", "https://a.com", "user4", "p4", "n4"),
                new CsvExportRow("Empty note", "", "user5", "p5", "")
        );
        byte[] csv = writer.write(rows, false);
        List<CsvExportRow> parsed = parser.parseDataRows(csv);
        assertThat(parsed).containsExactlyElementsOf(rows);
    }

    @Test
    void roundTripWithBom() {
        List<CsvExportRow> rows = List.of(
                new CsvExportRow("Hello", "https://x.com", "u", "p", "n")
        );
        byte[] csv = writer.write(rows, true);
        assertThat(csv[0] & 0xFF).isEqualTo(0xEF);
        List<CsvExportRow> parsed = parser.parseDataRows(csv);
        assertThat(parsed).containsExactlyElementsOf(rows);
    }

    @Test
    void roundTripPreservesUtf8() {
        List<CsvExportRow> rows = List.of(
                new CsvExportRow("Привет", "https://пример.рф", "юзер", "пароль", "заметка")
        );
        byte[] csv = writer.write(rows, false);
        List<CsvExportRow> parsed = parser.parseDataRows(csv);
        assertThat(parsed.get(0).name()).isEqualTo("Привет");
        assertThat(parsed.get(0).username()).isEqualTo("юзер");
    }
}