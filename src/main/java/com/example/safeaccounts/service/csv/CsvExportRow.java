package com.example.safeaccounts.service.csv;

/**
 * Строка CSV экспорта/импорта в формате Google Chrome Password Manager:
 * {@code name,url,username,password,note} (строго 5 колонок в указанном порядке).
 * Теги НЕ включены (Chrome их не поддерживает).
 *
 * @param name     метка записи (зашифровывается в {@code name_enc})
 * @param url      сайт (зашифровывается в {@code site_enc}); допускается пустая строка
 * @param username логин (зашифровывается в {@code login_enc}); NotBlank
 * @param password пароль (зашифровывается в {@code password_enc}); NotBlank, никогда не логируется
 * @param note     примечание (зашифровывается в {@code notes_enc}); допускается пустая строка
 */
public record CsvExportRow(String name,
                           String url,
                           String username,
                           String password,
                           String note) {
}