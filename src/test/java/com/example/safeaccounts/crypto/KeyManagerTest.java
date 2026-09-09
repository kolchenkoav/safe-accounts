package com.example.safeaccounts.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit-тесты KeyManager (Task-03): fail-fast при отсутствии мастер-ключа,
 * ошибка при неверной длине ключа, ротация (активный ровно один),
 * поддержка нескольких KEK, чтение ключа из файла секрета.
 */
class KeyManagerTest {

    private static final String KEY_32B = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";
    private static final String KEY_16B = "MDEyMzQ1Njc4OWFiY2RlZg=="; // 16 байт

    @Test
    @DisplayName("Нет ключей в нетестовом профиле -> fail-fast на старте")
    void noKeysFailsFastInNonTestProfile() {
        KeyManager manager = manager(new CryptoProperties(), new String[0]);

        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No master key (KEK) configured");
    }

    @Test
    @DisplayName("Нет ключей в тестовом профиле -> приложение стартует")
    void noKeysAllowedInTestProfile() {
        KeyManager manager = manager(new CryptoProperties(), new String[]{"test"});

        assertThatCode(manager::afterPropertiesSet).doesNotThrowAnyException();
        // Без активного ключа доступ к нему также обязан падать
        assertThatThrownBy(manager::getActiveKekId)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No active KEK");
    }

    @Test
    @DisplayName("Нет активного ключа в нетестовом профиле -> fail-fast")
    void noActiveKeyFailsFast() {
        CryptoProperties props = new CryptoProperties();
        CryptoProperties.Kek kek = kek("kek-1", KEY_32B, false);
        props.getKeys().add(kek);

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("No active KEK");
    }

    @Test
    @DisplayName("Ключ неверной длины (128 бит) -> ошибка старта")
    void wrongKeyLengthFails() {
        CryptoProperties props = new CryptoProperties();
        props.getKeys().add(kek("kek-1", KEY_16B, true));

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256 bit");
    }

    @Test
    @DisplayName("Невалидный base64 -> ошибка старта")
    void invalidBase64Fails() {
        CryptoProperties props = new CryptoProperties();
        props.getKeys().add(kek("kek-1", "!!!not-base64!!!", true));

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not valid base64");
    }

    @Test
    @DisplayName("Несколько активных ключей -> ошибка старта")
    void multipleActiveKeysFail() {
        CryptoProperties props = new CryptoProperties();
        props.getKeys().add(kek("kek-1", KEY_32B, true));
        props.getKeys().add(kek("kek-2", KEY_32B, true));

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Multiple active KEKs");
    }

    @Test
    @DisplayName("Активный ключ ровно один + старый неактивный: оба доступны для дешифровки")
    void rotationActiveAndLegacyKeys() {
        CryptoProperties props = new CryptoProperties();
        props.getKeys().add(kek("kek-old", KEY_32B, false));
        props.getKeys().add(kek("kek-new", KEY_32B, true));

        KeyManager manager = manager(props, new String[0]);
        manager.afterPropertiesSet();

        assertThat(manager.getActiveKekId()).isEqualTo("kek-new");
        assertThat(manager.getKnownKeyIds()).containsExactlyInAnyOrder("kek-old", "kek-new");
        assertThat(manager.getKek("kek-old")).isPresent();
        assertThat(manager.getKek("unknown")).isEmpty();
    }

    @Test
    @DisplayName("Упрощенный режим: master-key-base64 становится активным ключом 'primary'")
    void simpleModeBase64() {
        CryptoProperties props = new CryptoProperties();
        props.setMasterKeyBase64(KEY_32B);

        KeyManager manager = manager(props, new String[0]);
        manager.afterPropertiesSet();

        assertThat(manager.getActiveKekId()).isEqualTo("primary");
        assertThat(manager.getActiveKek()).isNotNull();
        assertThat(manager.getKnownKeyIds()).containsExactly("primary");
    }

    @Test
    @DisplayName("Упрощенный режим: master-key-file читает ключ из файла секрета")
    void simpleModeFile() throws Exception {
        java.nio.file.Path file = java.nio.file.Files.createTempFile("kek", ".txt");
        java.nio.file.Files.writeString(file, KEY_32B + "\n");

        try {
            CryptoProperties props = new CryptoProperties();
            props.setMasterKeyFile(file.toString());

            KeyManager manager = manager(props, new String[0]);
            manager.afterPropertiesSet();

            assertThat(manager.getActiveKekId()).isEqualTo("primary");
        } finally {
            java.nio.file.Files.deleteIfExists(file);
        }
    }

    @Test
    @DisplayName("Несуществующий файл секрета -> ошибка старта")
    void missingKeyFileFails() {
        CryptoProperties props = new CryptoProperties();
        props.setMasterKeyFile("Z:/no/such/dir/kek.txt");

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Failed to read master key file");
    }

    @Test
    @DisplayName("Одновременное задание обоих режимов -> ошибка конфигурации")
    void bothModesFails() {
        CryptoProperties props = new CryptoProperties();
        props.setMasterKeyBase64(KEY_32B);
        props.getKeys().add(kek("kek-1", KEY_32B, true));

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not both");
    }

    @Test
    @DisplayName("Дубликат key id -> ошибка старта")
    void duplicateIdFails() {
        CryptoProperties props = new CryptoProperties();
        props.getKeys().add(kek("kek-1", KEY_32B, true));
        props.getKeys().add(kek("kek-1", KEY_32B, false));

        KeyManager manager = manager(props, new String[0]);
        assertThatThrownBy(manager::afterPropertiesSet)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Duplicate KEK id");
    }

    @Test
    @DisplayName("В логи попадают только key id и fingerprint, материал ключа не логируется")
    void keyMaterialNeverLogged() {
        ch.qos.logback.classic.Logger logbackLogger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(KeyManager.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logbackLogger.addAppender(appender);
        try {
            CryptoProperties props = new CryptoProperties();
            props.setMasterKeyBase64(KEY_32B);
            manager(props, new String[0]).afterPropertiesSet();

            assertThat(appender.list).isNotEmpty();
            for (ch.qos.logback.classic.spi.ILoggingEvent event : appender.list) {
                String message = event.getFormattedMessage();
                assertThat(message).doesNotContain(KEY_32B);
                // Проверяем, что ни один фрагмент base64 ключа не попал в лог
                for (int i = 0; i + 8 <= KEY_32B.length(); i += 8) {
                    assertThat(message).doesNotContain(KEY_32B.substring(i, i + 8));
                }
                // Событие регистрации содержит fingerprint, но не материал ключа
                if (message.contains("Registered KEK")) {
                    assertThat(message).contains("fingerprint-prefix=");
                }
            }
        } finally {
            logbackLogger.detachAppender(appender);
        }
    }

    // -- helpers -----------------------------------------------------------

    private static KeyManager manager(CryptoProperties props, String[] activeProfiles) {
        return new KeyManager(props, () -> activeProfiles);
    }

    private static CryptoProperties.Kek kek(String id, String secretBase64, boolean active) {
        CryptoProperties.Kek kek = new CryptoProperties.Kek();
        kek.setId(id);
        kek.setSecretBase64(secretBase64);
        kek.setActive(active);
        return kek;
    }
}
