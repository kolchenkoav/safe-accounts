package com.example.safeaccounts.service.csv;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-тесты нейтрального хелпера имён CSV-файлов (Фаза 5): санитизация
 * username и компактный ISO-timestamp.
 */
class CsvFilenamesTest {

    @Test
    void sanitizesNonAsciiAndPathSeparators() {
        // Кириллица → «_»; допустимые [A-Za-z0-9._-] сохраняются
        assertThat(CsvFilenames.safeFilenamePart("алёна.volkova"))
                .isEqualTo("_____.volkova");
        // «/» заменяется, «..» без слэшей безопасен в filename
        assertThat(CsvFilenames.safeFilenamePart("../etc/passwd"))
                .isEqualTo(".._etc_passwd");
        assertThat(CsvFilenames.safeFilenamePart("user-01_x.y"))
                .isEqualTo("user-01_x.y");
        assertThat(CsvFilenames.safeFilenamePart(null)).isEqualTo("user");
        assertThat(CsvFilenames.safeFilenamePart("")).isEqualTo("user");
    }

    @Test
    void filenamesUseCompactIsoUtcTimestamp() {
        Instant fixed = Instant.parse("2025-06-12T10:00:00Z");
        assertThat(CsvFilenames.forUser("alice", fixed))
                .isEqualTo("vault-alice-20250612T100000Z.csv");
        assertThat(CsvFilenames.forTargetUser("Bob", fixed))
                .isEqualTo("vault-user-Bob-20250612T100000Z.csv");
    }

    @Test
    void warningConstantsAreSingleSourceOfTruth() {
        assertThat(CsvFilenames.EXPORT_WARNING_HEADER)
                .isEqualTo("X-Vault-Export-Warning");
        assertThat(CsvFilenames.EXPORT_WARNING_VALUE)
                .isEqualTo("csv-contains-plaintext-passwords");
    }
}
