package com.example.safeaccounts.crypto;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

/**
 * Конфигурация криптомодуля (Task-03).
 * <p>
 * Материал ключей читается ТОЛЬКО из переменных окружения или файлов секретов
 * (см. AGENTS.md): значения по умолчанию в application.yaml отсутствуют намеренно.
 * <p>
 * Поддерживаются два режима:
 * <ul>
 *   <li>упрощенный — одиночный мастер-ключ {@code app.crypto.master-key-base64}
 *       или {@code app.crypto.master-key-file};</li>
 *   <li>расширенный — список KEK {@code app.crypto.keys[n].id / secret-base64 / active}
 *       для ротации: активный ключ один, старые остаются для дешифровки.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "app.crypto")
public class CryptoProperties {

    /** Список KEK: ровно один активный (для wrapping) + старые (для unwrapping). */
    private List<Kek> keys = new ArrayList<>();

    /** Упрощенный режим: материал мастер-ключа в base64 (из окружения). */
    private String masterKeyBase64;

    /** Упрощенный режим: путь к файлу секрета с материалом ключа в base64. */
    private String masterKeyFile;

    public List<Kek> getKeys() {
        return keys;
    }

    public void setKeys(List<Kek> keys) {
        this.keys = keys;
    }

    public String getMasterKeyBase64() {
        return masterKeyBase64;
    }

    public void setMasterKeyBase64(String masterKeyBase64) {
        this.masterKeyBase64 = masterKeyBase64;
    }

    public String getMasterKeyFile() {
        return masterKeyFile;
    }

    public void setMasterKeyFile(String masterKeyFile) {
        this.masterKeyFile = masterKeyFile;
    }

    /** Описание одного KEK. {@code id} не является секретом и хранится в БД. */
    public static class Kek {

        /** Нечувствительный идентификатор ключа (попадает в users.dek_kek_id). */
        private String id;

        /** Материал ключа в base64; секрет, задается только из окружения/файла. */
        private String secretBase64;

        /** Активный ключ должен быть ровно один. */
        private boolean active;

        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        public String getSecretBase64() {
            return secretBase64;
        }

        public void setSecretBase64(String secretBase64) {
            this.secretBase64 = secretBase64;
        }

        public boolean isActive() {
            return active;
        }

        public void setActive(boolean active) {
            this.active = active;
        }
    }
}
