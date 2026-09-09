package com.example.safeaccounts.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Загружает мастер-ключи (KEK) из окружения / файлов секретов и предоставляет
 * их остальному криптомодулю (Task-03).
 * <p>
 * Правила безопасности (AGENTS.md, Task-03):
 * <ul>
 *   <li>материал ключей читается только из {@code app.crypto.master-key-base64},
 *       {@code app.crypto.master-key-file} или {@code app.crypto.keys[n].secret-base64};
 *       все значения задаются через переменные окружения (см. application.yaml);</li>
 *   <li>fail-fast: если в нетестовом профиле не задано ни одного ключа или
 *       активный KEK не определен, приложение обязано упасть на старте
 *       ({@link #afterPropertiesSet()});</li>
 *   <li>в логах разрешены только нечувствительный key id и усеченный SHA-256
 *       fingerprint (восстановить ключ по нему нельзя); сам материал ключа
 *       никогда не логируется;</li>
 *   <li>поддерживается несколько KEK для ротации: активный — ровно один,
 *       старые используются только для дешифровки.</li>
 * </ul>
 */
@Component
public class KeyManager implements InitializingBean {

    static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    /** Требуемая длина AES-256 ключа в байтах. */
    static final int REQUIRED_KEY_BYTES = 32;

    /** Профили, в которых отсутствие мастер-ключа допустимо (тестовые). */
    static final Set<String> TEST_PROFILES = Set.of("test", "it");

    private final CryptoProperties properties;

    /** Поставщик активных профилей (вынос для тестируемости без Spring). */
    private final Supplier<String[]> activeProfilesSupplier;

    /** key id -> SecretKey; порядок сохранен для детерминированных сообщений об ошибках. */
    private final Map<String, SecretKey> keysById = new LinkedHashMap<>();

    /** Идентификатор активного ключа; {@code null}, если не задан (тестовый профиль). */
    private volatile String activeKeyId;

    @org.springframework.beans.factory.annotation.Autowired
    public KeyManager(CryptoProperties properties, Environment environment) {
        this(properties, environment::getActiveProfiles);
    }

    /** Для unit-тестов: без Spring-окружения. */
    KeyManager(CryptoProperties properties, Supplier<String[]> activeProfilesSupplier) {
        this.properties = properties;
        this.activeProfilesSupplier = activeProfilesSupplier;
    }

    @Override
    public void afterPropertiesSet() {
        load();
        validate();
        log.info("KeyManager initialized: {} KEK(s) registered, active key id='{}'",
                keysById.size(), activeKeyId);
    }

    /** Загружает ключи из обоих режимов конфигурации. Package-private для тестов. */
    void load() {
        keysById.clear();
        activeKeyId = null;

        boolean hasListMode = properties.getKeys() != null && !properties.getKeys().isEmpty();
        boolean hasSimpleMode = hasText(properties.getMasterKeyBase64())
                || hasText(properties.getMasterKeyFile());

        if (hasListMode && hasSimpleMode) {
            throw new IllegalStateException(
                    "Configure either app.crypto.keys[...] or app.crypto.master-key-base64/-file, not both");
        }

        if (hasListMode) {
            for (CryptoProperties.Kek kek : properties.getKeys()) {
                registerKey(kek.getId(), kek.getSecretBase64(), kek.isActive());
            }
        } else if (hasSimpleMode) {
            if (hasText(properties.getMasterKeyBase64())) {
                registerKey("primary", properties.getMasterKeyBase64(), true);
            } else {
                registerKey("primary", readSecretFile(properties.getMasterKeyFile()), true);
            }
        }
    }

    /** Валидация после загрузки: fail-fast при отсутствии ключей/активного KEK. */
    void validate() {
        if (keysById.isEmpty()) {
            if (isTestProfile()) {
                log.info("No KEK configured: test profile, skipping fail-fast check");
                return;
            }
            throw new IllegalStateException(
                    "No master key (KEK) configured. Set VAULT_MASTER_KEY_BASE64 (or "
                            + "APP_CRYPTO_MASTER_KEY_BASE64), VAULT_MASTER_KEY_FILE or APP_CRYPTO_KEYS_* "
                            + "environment variables. "
                            + "Refusing to start without encryption keys.");
        }
        if (activeKeyId == null) {
            if (isTestProfile()) {
                log.info("No active KEK defined: test profile, skipping fail-fast check");
                return;
            }
            throw new IllegalStateException(
                    "No active KEK: exactly one key must have active=true "
                            + "(or provide app.crypto.master-key-base64 / -file)");
        }
    }

    private void registerKey(String id, String secretBase64, boolean active) {
        if (!hasText(id)) {
            throw new IllegalStateException("KEK id must not be blank");
        }
        if (keysById.containsKey(id)) {
            throw new IllegalStateException("Duplicate KEK id '" + id + "'");
        }
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(secretBase64 == null ? "" : secretBase64.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("KEK '" + id + "': secret is not valid base64", e);
        }
        if (keyBytes.length != REQUIRED_KEY_BYTES) {
            throw new IllegalStateException("KEK '" + id + "' must be exactly 256 bit (32 bytes), got "
                    + keyBytes.length * 8 + " bit");
        }
        keysById.put(id, new SecretKeySpec(keyBytes, "AES"));
        if (active) {
            if (activeKeyId != null) {
                throw new IllegalStateException(
                        "Multiple active KEKs: '" + activeKeyId + "' and '" + id + "'");
            }
            activeKeyId = id;
        }
        // Логируем только нечувствительные идентификаторы: key id и усеченный
        // SHA-256 fingerprint. Материал ключа никогда не попадает в логи.
        log.info("Registered KEK id='{}', fingerprint-prefix='{}'", id, fingerprint(keyBytes));
    }

    private String readSecretFile(String path) {
        try {
            String content = Files.readString(Path.of(path.trim()), StandardCharsets.UTF_8).trim();
            if (content.isBlank()) {
                throw new IllegalStateException("Master key file is empty");
            }
            return content;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read master key file", e);
        }
    }

    /**
     * Fingerprint для логов: усеченный SHA-256 от материала ключа.
     * Восстановить ключ по 16 hex-символам невозможно.
     */
    private static String fingerprint(byte[] keyBytes) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(keyBytes);
            return HexFormat.of().formatHex(digest, 0, 8);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 digest unavailable", e);
        }
    }

    /** Активный KEK (для wrapping нового DEK / шифрования новых данных). */
    public SecretKey getActiveKek() {
        requireActive();
        return keysById.get(activeKeyId);
    }

    /** Идентификатор активного KEK (нечувствительный, безопасен для логов и БД). */
    public String getActiveKekId() {
        requireActive();
        return activeKeyId;
    }

    /** KEK по идентификатору (для unwrapping DEK, зашифрованных старым ключом). */
    public Optional<SecretKey> getKek(String keyId) {
        return Optional.ofNullable(keysById.get(keyId));
    }

    /** Все зарегистрированные key id (нечувствительные идентификаторы). */
    public Set<String> getKnownKeyIds() {
        return Set.copyOf(keysById.keySet());
    }

    private void requireActive() {
        if (activeKeyId == null) {
            throw new IllegalStateException("No active KEK configured");
        }
    }

    private boolean isTestProfile() {
        for (String profile : activeProfilesSupplier.get()) {
            if (TEST_PROFILES.contains(profile)) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
