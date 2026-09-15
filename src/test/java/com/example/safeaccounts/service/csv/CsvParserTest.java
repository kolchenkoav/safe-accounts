package com.example.safeaccounts.service.csv;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit-тесты RFC 4180 парсера {@link CsvParser}.
 * Тесты покрывают: BOM, CRLF/LF/CR, кавычки, удвоенные кавычки,
 * запятые и переводы строк внутри значений, лишние колонки,
 * пустые значения, отсутствие заголовка.
 */
class CsvParserTest {

    private final CsvParser parser = new CsvParser();

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void parsesHeaderOnly() {
        List<List<String>> rows = parser.parse(bytes("name,url,username,password,note\r\n"));
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0)).containsExactly("name", "url", "username", "password", "note");
    }

    @Test
    void parsesSimpleRow() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "Gmail,https://gmail.com,alice@gmail.com,S3cret,my email\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).containsExactly(new CsvExportRow(
                "Gmail", "https://gmail.com", "alice@gmail.com", "S3cret", "my email"));
    }

    @Test
    void supportsLfLineEnding() {
        byte[] csv = bytes("name,url,username,password,note\n"
                + "Site,u,u,p,n\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).name()).isEqualTo("Site");
    }

    @Test
    void supportsCrLineEnding() {
        byte[] csv = bytes("name,url,username,password,note\r"
                + "Site,u,u,p,n\r");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).name()).isEqualTo("Site");
    }

    @Test
    void stripsUtf8Bom() {
        byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        byte[] tail = bytes("name,url,username,password,note\nSite,u,u,p,n\n");
        byte[] withBom = new byte[bom.length + tail.length];
        System.arraycopy(bom, 0, withBom, 0, bom.length);
        System.arraycopy(tail, 0, withBom, bom.length, tail.length);
        List<CsvExportRow> rows = parser.parseDataRows(withBom);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).name()).isEqualTo("Site");
    }

    @Test
    void supportsQuotedFieldWithComma() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "\"Hello, world\",https://x.com,u,p,n\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows.get(0).name()).isEqualTo("Hello, world");
    }

    @Test
    void supportsQuotedFieldWithDoubleQuotes() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "\"He said \"\"hi\"\"\",u,u,p,n\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows.get(0).name()).isEqualTo("He said \"hi\"");
    }

    @Test
    void supportsQuotedFieldWithNewline() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "\"line1\r\nline2\",u,u,p,n\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows.get(0).name()).isEqualTo("line1\r\nline2");
    }

    @Test
    void supportsQuotedFieldWithLfInside() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "\"line1\nline2\",u,u,p,n\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows.get(0).name()).isEqualTo("line1\nline2");
    }

    @Test
    void parsesEmptyValues() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "name1,,u,p,\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows.get(0).url()).isEqualTo("");
        assertThat(rows.get(0).note()).isEqualTo("");
    }

    @Test
    void ignoresExtraColumns() {
        // 6-я колонка "tags" тихо игнорируется (требование плана).
        byte[] csv = bytes("name,url,username,password,note,tags\r\n"
                + "Gmail,u,u,p,n,\"work,personal\"\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).name()).isEqualTo("Gmail");
        assertThat(rows.get(0).password()).isEqualTo("p");
    }

    @Test
    void emptyCsvThrows() {
        assertThatThrownBy(() -> parser.parseFirstRowAsHeader(bytes("")))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void missingRequiredColumnThrows() {
        byte[] csv = bytes("name,url,username,password,extra\r\n");
        assertThatThrownBy(() -> parser.parseFirstRowAsHeader(csv))
                .isInstanceOf(InvalidCsvException.class)
                .hasMessageContaining("note");
    }

@Test
    void wrongColumnOrderThrows() {
        // Column 1 must be 'name'; here it's 'url' → parser complains about column 1.
        byte[] csv = bytes("url,name,username,password,note\r\n");
        assertThatThrownBy(() -> parser.parseFirstRowAsHeader(csv))
                .isInstanceOf(InvalidCsvException.class)
                .hasMessageContaining("column 1");
    }

    @Test
    void wrongColumnAtPosition2Throws() {
        byte[] csv = bytes("name,user,username,password,note\r\n");
        assertThatThrownBy(() -> parser.parseFirstRowAsHeader(csv))
                .isInstanceOf(InvalidCsvException.class)
                .hasMessageContaining("column 2");
    }

    @Test
    void tooFewHeaderColumnsThrows() {
        byte[] csv = bytes("name,url,username,password\r\n");
        assertThatThrownBy(() -> parser.parseFirstRowAsHeader(csv))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void dataRowWithTooFewColumnsThrows() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "n,u,u,p\r\n");
        assertThatThrownBy(() -> parser.parseDataRows(csv))
                .isInstanceOf(InvalidCsvException.class);
    }

    @Test
    void parsesMultipleRows() {
        byte[] csv = bytes("name,url,username,password,note\r\n"
                + "A,u1,u,p1,n1\r\n"
                + "B,u2,u,p2,n2\r\n"
                + "C,u3,u,p3,n3\r\n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).hasSize(3);
        assertThat(rows.get(0).name()).isEqualTo("A");
        assertThat(rows.get(2).note()).isEqualTo("n3");
    }

    @Test
    void parsesRowWithoutTrailingNewline() {
        byte[] csv = bytes("name,url,username,password,note\r\nSite,u,u,p,n");
        List<CsvExportRow> rows = parser.parseDataRows(csv);
        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).name()).isEqualTo("Site");
    }
}