package com.example.safeaccounts.service.csv;

import java.time.Instant;
import java.util.List;

/**
 * Отчёт о результате импорта CSV. Используется как JSON-ответ в Фазе 5
 * и как возвращаемое значение {@link com.example.safeaccounts.service.VaultExportImportService#importFromCsv}.
 *
 * @param totalRows всего строк данных в файле (без заголовка)
 * @param created   сколько новых записей было создано (или было бы создано при dry-run)
 * @param updated   сколько существующих записей было обновлено (или было бы при dry-run)
 * @param skipped   сколько конфликтов было пропущено (стратегия SKIP)
 * @param failed    сколько строк завершились ошибкой валидации/парсинга
 * @param errors    список ошибок (только нечувствительные причины)
 * @param importedAt момент времени формирования отчёта (UTC)
 * @param dryRun    {@code true}, если изменения не были применены к БД
 */
public record ImportReport(int totalRows,
                           int created,
                           int updated,
                           int skipped,
                           int failed,
                           List<ImportError> errors,
                           Instant importedAt,
                           boolean dryRun) {
}