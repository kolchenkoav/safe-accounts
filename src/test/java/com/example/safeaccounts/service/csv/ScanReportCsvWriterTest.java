package com.example.safeaccounts.service.csv;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты CSV-экспорта отчёта скана (G2): преамбула, formula-injection
 * гвард, score=null, 0 weak, escaped-значения. BOM-тест — IT (byte-level).
 */
class ScanReportCsvWriterTest {

    private final ScanReportCsvWriter writer = new ScanReportCsvWriter();

    private static final Instant SCANNED_AT = Instant.parse("2025-06-01T10:00:00Z");

    @Test
    void preambleContainsAggregatesAndSnapshotNote() {
        byte[] csv = writer.write("alice", SCANNED_AT, 3, 2, 1, 1, 1, true,
                Collections.singletonList(weak("W1", null, 0)), false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text)
                .contains("# Weak password scan report")
                .contains("# target,alice")
                .contains("# scanned,3")
                .contains("# weak,2")
                .contains("# tagged,1")
                .contains("# untagged,1")
                .contains("# failed,1")
                .contains("# truncated,true")
                .contains("# Снимок отчёта: 2025-06-01 10:00:00Z;"
                        + " записи, изменённые после скана, в файле не отражены");
    }

    @Test
    void headerAndWeakRowsArePresent() {
        byte[] csv = writer.write("alice", SCANNED_AT, 1, 1, 0, 0, 0, false,
                Collections.singletonList(weak("Weak entry", 2, 1)), false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text)
                .contains("name,url,username,reasons,score,password_length,reuse_count,entry_id")
                .contains("Weak entry")
                .contains("2");
    }

    @Test
    void zeroWeakEntriesProducesPreambleOnly() {
        byte[] csv = writer.write("alice", SCANNED_AT, 5, 0, 0, 2, 0, false,
                Collections.emptyList(), false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text).contains("# weak,0").doesNotContain("Weak entry");
    }

    /** Formula-injection гвард: опасные ведущие символы получают префикс '. */
    @Test
    void formulaInjectionIsGuardedWithApostrophePrefix() {
        byte[] csv = writer.write("alice", SCANNED_AT, 4, 4, 0, 0, 0, false, java.util.Arrays.asList(
                        weak("=WEBSERVICE(https://evil)", null, 1),
                        weak("+CMD|'/C calc'!A0", null, 1),
                        weak("@SUM(1)", null, 1),
                        weak("-2+3", null, 1),
                        weak("\tTAB()(", null, 1)),
                false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text).contains("'=WEBSERVICE")
                .contains("'+CMD|")
                .contains("'@SUM(1)")
                .contains("'-2+3")
                .contains("'\tTAB()(");
        // «голого» =WEBSERVICE нет: каждое вхождение прикрыто апострофом
        // (само '=WEBSERVICE содержит =WEBSERVICE как подстроку — вырезаем)
        assertThat(text.replace("'=WEBSERVICE", "")).doesNotContain("=WEBSERVICE");
    }

    /** score=null (гвард zxcvbn) → пустая колонка score. */
    @Test
    void nullScoreRendersAsEmptyColumn() {
        byte[] csv = writer.write("alice", SCANNED_AT, 1, 1, 0, 0, 0, false,
                Collections.singletonList(weak("Long", null, 0)), false);
        String text = new String(csv, StandardCharsets.UTF_8);
        // строка вида name,url,username,reasons,,<len>,<reuse>,<id>:
        // пустая колонка score между reasons и password_length
        assertThat(text).contains(
                "alice,Слишком короткий (меньше 12 символов); Вырожденный набор символов,,12,0,");
        assertThat(text).contains("Long,https://example.com");
    }

    @Test
    void rfc4180EscapingQuotesValuesWithCommas() {
        byte[] csv = writer.write("alice", SCANNED_AT, 1, 1, 0, 0, 0, false,
                Collections.singletonList(weak("Name, with comma", null, 0)), false);
        String text = new String(csv, StandardCharsets.UTF_8);
        assertThat(text).contains("\"Name, with comma\"");
    }

    @Test
    void bomIsPrependedWhenRequested() {
        byte[] csv = writer.write("alice", SCANNED_AT, 0, 0, 0, 0, 0, false,
                Collections.emptyList(), true);
        assertThat(csv[0]).isEqualTo((byte) 0xEF);
        assertThat(csv[1]).isEqualTo((byte) 0xBB);
        assertThat(csv[2]).isEqualTo((byte) 0xBF);
    }

    private static ScanReportCsvWriter.VaultScanWeakRow weak(String name, Integer score, int reuse) {
        return new ScanReportCsvWriter.VaultScanWeakRow(name,
                "https://example.com", "alice",
                List.of("Слишком короткий (меньше 12 символов)", "Вырожденный набор символов"),
                score, 12, reuse, UUID.randomUUID());
    }
}
