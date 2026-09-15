-- Task-feat-name-tags: добавление зашифрованного поля name в vault_entries.
-- Колонка шифруется по общему паттерну существующих полей VaultEntry:
-- base64(iv || ciphertext || tag) хранится в одном TEXT (как site_enc/login_enc/...).
-- В V1 для vault_entries нет отдельной колонки site_iv, поэтому в V2 вводится
-- только name_enc (без name_iv); бэкфилл копирует site_enc как name_enc.
-- После бэкфилла name_enc переводится в NOT NULL.

ALTER TABLE vault_entries ADD COLUMN name_enc text;

UPDATE vault_entries
   SET name_enc = site_enc
 WHERE name_enc IS NULL;

ALTER TABLE vault_entries ALTER COLUMN name_enc SET NOT NULL;