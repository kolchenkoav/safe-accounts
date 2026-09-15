package com.example.safeaccounts.web;

import com.example.safeaccounts.service.csv.ConflictStrategy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit-тесты пакетного парсера conflictStrategy web-форм импорта (Фаза 5):
 * заглавные буквы/пробелы, дефолты, отказ на неизвестном значении.
 */
class WebVaultControllerTest {

    @Test
    void parseConflictStrategyAcceptsUppercaseAndTrims() {
        assertThat(WebVaultController.parseConflictStrategy("SKIP"))
                .isEqualTo(ConflictStrategy.SKIP);
        assertThat(WebVaultController.parseConflictStrategy(" Upsert "))
                .isEqualTo(ConflictStrategy.UPSERT);
    }

    @Test
    void parseConflictStrategyDefaultsAndRejectsUnknown() {
        assertThat(WebVaultController.parseConflictStrategy(null))
                .isEqualTo(ConflictStrategy.SKIP);
        assertThat(WebVaultController.parseConflictStrategy("   "))
                .isEqualTo(ConflictStrategy.SKIP);
        assertThatThrownBy(() -> WebVaultController.parseConflictStrategy("merge"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
