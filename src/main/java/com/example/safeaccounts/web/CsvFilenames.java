package com.example.safeaccounts.web;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Имена CSV-файлов для скачивания в web-интерфейсе (Фаза 3/4).
 * Один общий хелпер для пользовательского и административного экспорта
 * (вместо копий в контроллерах). REST-контроллер (api) имеет собственную
 * копию — дедупликация api↔web отложена на фазу 5.
 */
final class CsvFilenames {

    private CsvFilenames() {
    }

    /** Собственный сейф пользователя: {@code vault-<username>-<timestamp>.csv}. */
    static String forUser(String username, Instant now) {
        return "vault-" + safeFilenamePart(username) + "-" + compactTimestamp(now) + ".csv";
    }

    /** Админский экспорт чужого сейфа: {@code vault-user-<username>-<timestamp>.csv}. */
    static String forTargetUser(String username, Instant now) {
        return "vault-user-" + safeFilenamePart(username) + "-" + compactTimestamp(now)
                + ".csv";
    }

    /**
     * Нейтральная часть имени файла из username: только [A-Za-z0-9._-]
     * (тот же паттерн, что в api/VaultController). Остальное → {@code _}.
     */
    static String safeFilenamePart(String value) {
        if (value == null || value.isEmpty()) {
            return "user";
        }
        return value.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    /** ISO-8601 compact без «:» и «.»: {@code 20250612T100000Z}. */
    static String compactTimestamp(Instant instant) {
        return DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
                .withZone(ZoneOffset.UTC)
                .format(instant);
    }
}
