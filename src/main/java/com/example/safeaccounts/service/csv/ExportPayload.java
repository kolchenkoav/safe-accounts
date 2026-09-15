package com.example.safeaccounts.service.csv;

/**
 * Внутренний DTO — результат экспорта сейфа в CSV.
 * Контроллер API (Фаза 5) использует это для формирования HTTP-ответа.
 *
 * @param csv    байтовое представление CSV (RFC 4180, UTF-8, CRLF, опционально BOM)
 * @param sha256 hex-строка sha256 канонизированного CSV (CRLF → LF); используется
 *               для идентификации экспорта в аудите
 * @param rows   количество строк данных (без заголовка)
 * @param bom    {@code true}, если в {@code csv} присутствует UTF-8 BOM
 */
public record ExportPayload(byte[] csv, String sha256, int rows, boolean bom) {
}