package com.example.safeaccounts.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit-тесты AES-256-GCM (Task-03): round-trip, уникальность IV,
 * негативные кейсы (поврежденный ciphertext/IV, неверный ключ),
 * wrapping/unwrapping DEK. Тестовые ключи — только синтетические.
 */
class AesGcmCryptoServiceTest {

    private static final String KEY_A_B64 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"; // 32 байта
    private static final String KEY_B_B64 = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA"; // 32 байта

    private AesGcmCryptoService service;
    private KeyManager keyManager;
    private SecretKey dek;

    @BeforeEach
    void setUp() {
        keyManager = keyManagerWithActive(KEY_A_B64);
        service = new AesGcmCryptoService(keyManager);
        dek = service.generateDek();
    }

    @Test
    @DisplayName("Round-trip: encrypt -> decrypt возвращает исходный текст")
    void encryptDecryptRoundTrip() {
        String plaintext = "p@ssw0rd-пример-секрет";
        String encrypted = service.encrypt(plaintext, dek);

        assertThat(encrypted).isNotBlank().isNotEqualTo(plaintext);
        assertThat(service.decrypt(encrypted, dek)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("Повторное шифрование того же текста дает разные результаты (уникальный IV)")
    void encryptTwiceProducesDifferentCiphertexts() {
        String plaintext = "same-secret";
        String first = service.encrypt(plaintext, dek);
        String second = service.encrypt(plaintext, dek);

        assertThat(first).isNotEqualTo(second);
        // Но оба расшифровываются в исходный текст
        assertThat(service.decrypt(first, dek)).isEqualTo(plaintext);
        assertThat(service.decrypt(second, dek)).isEqualTo(plaintext);
    }

    @Test
    @DisplayName("IV уникален на каждую операцию: первые 12 байт контейнера различаются")
    void ivIsUniquePerOperation() {
        byte[] iv1 = extractIv(service.encrypt("x", dek));
        byte[] iv2 = extractIv(service.encrypt("x", dek));
        byte[] iv3 = extractIv(service.encrypt("x", dek));

        assertThat(iv1).hasSize(12).isNotEqualTo(iv2);
        assertThat(iv2).isNotEqualTo(iv3);
        assertThat(iv1).isNotEqualTo(iv3);
    }

    @Test
    @DisplayName("Расшифровка неверным ключом падает с нейтральным исключением")
    void decryptWithWrongKeyFails() {
        String encrypted = service.encrypt("secret", dek);
        SecretKey otherDek = service.generateDek();

        assertThatThrownBy(() -> service.decrypt(encrypted, otherDek))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class)
                .hasMessage("Decryption failed");
    }

    @Test
    @DisplayName("Поврежденный ciphertext не расшифровывается")
    void corruptedCiphertextFails() {
        String encrypted = service.encrypt("secret", dek);
        byte[] container = Base64.getDecoder().decode(encrypted);
        container[container.length - 1] ^= 0x01; // ломаем последний байт tag
        String corrupted = Base64.getEncoder().encodeToString(container);

        assertThatThrownBy(() -> service.decrypt(corrupted, dek))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class);
    }

    @Test
    @DisplayName("Поврежденный IV не расшифровывается")
    void corruptedIvFails() {
        String encrypted = service.encrypt("secret", dek);
        byte[] container = Base64.getDecoder().decode(encrypted);
        container[0] ^= 0x01; // ломаем первый байт IV
        String corrupted = Base64.getEncoder().encodeToString(container);

        assertThatThrownBy(() -> service.decrypt(corrupted, dek))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class);
    }

    @Test
    @DisplayName("Некорректный base64 дает нейтральную ошибку")
    void malformedBase64Fails() {
        assertThatThrownBy(() -> service.decrypt("!!!not-base64!!!", dek))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class)
                .hasMessageContaining("malformed");
    }

    @Test
    @DisplayName("Слишком короткий контейнер отклоняется")
    void tooShortContainerFails() {
        String tiny = Base64.getEncoder().encodeToString(new byte[8]);
        assertThatThrownBy(() -> service.decrypt(tiny, dek))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class);
    }

    @Test
    @DisplayName("wrapDek -> unwrapDek round-trip: DEK восстанавливается KEK-ом")
    void wrapUnwrapDekRoundTrip() {
        WrappedDek wrapped = service.wrapDek(dek);

        assertThat(wrapped.kekId()).isEqualTo("primary");
        assertThat(wrapped.wrappedDekBase64()).isNotBlank();
        assertThat(wrapped.ivBase64()).isNotBlank();

        SecretKey unwrapped = service.unwrapDek(wrapped);
        assertThat(unwrapped.getEncoded()).isEqualTo(dek.getEncoded());

        // Расшифровка данных развернутым DEK работает
        String encrypted = service.encrypt("check", dek);
        assertThat(service.decrypt(encrypted, unwrapped)).isEqualTo("check");
    }

    @Test
    @DisplayName("unwrapDek чужим KEK-ом падает")
    void unwrapWithWrongKekFails() {
        WrappedDek wrapped = service.wrapDek(dek);

        KeyManager otherManager = keyManagerWithActive(KEY_B_B64);
        AesGcmCryptoService otherService = new AesGcmCryptoService(otherManager);

        assertThatThrownBy(() -> otherService.unwrapDek(wrapped))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class)
                .hasMessageContaining("unwrapping failed");
    }

    @Test
    @DisplayName("unwrapDek неизвестным KEK id падает")
    void unwrapWithUnknownKekIdFails() {
        WrappedDek wrapped = new WrappedDek(
                Base64.getEncoder().encodeToString(new byte[32]),
                Base64.getEncoder().encodeToString(new byte[12]),
                "no-such-kek");

        assertThatThrownBy(() -> service.unwrapDek(wrapped))
                .isInstanceOf(AesGcmCryptoService.CryptoException.class)
                .hasMessageContaining("Unknown KEK id");
    }

    @Test
    @DisplayName("generateDek возвращает 256-битный ключ, ключи разные")
    void generateDekReturns256BitKeys() {
        SecretKey a = service.generateDek();
        SecretKey b = service.generateDek();

        assertThat(a.getEncoded()).hasSize(32);
        assertThat(a.getAlgorithm()).isEqualTo("AES");
        assertThat(a.getEncoded()).isNotEqualTo(b.getEncoded());
    }

    @Test
    @DisplayName("Шифрование старым KEK-ом (после ротации) можно расшифровать тем же ключом")
    void legacyKeyStillDecryptsAfterRotation() {
        // Шифруем DEK старым KEK-ом
        WrappedDek legacyWrapped = service.wrapDek(dek);

        // "Ротация": у KeyManager теперь активен другой KEK, но старый задан
        CryptoProperties props = new CryptoProperties();
        CryptoProperties.Kek oldKek = new CryptoProperties.Kek();
        oldKek.setId("primary");
        oldKek.setSecretBase64(KEY_A_B64);
        oldKek.setActive(false);
        CryptoProperties.Kek newKek = new CryptoProperties.Kek();
        newKek.setId("secondary");
        newKek.setSecretBase64(KEY_B_B64);
        newKek.setActive(true);
        props.getKeys().add(oldKek);
        props.getKeys().add(newKek);
        KeyManager rotated = new KeyManager(props, () -> new String[0]);
        rotated.afterPropertiesSet();

        AesGcmCryptoService rotatedService = new AesGcmCryptoService(rotated);
        SecretKey restored = rotatedService.unwrapDek(legacyWrapped);
        assertThat(restored.getEncoded()).isEqualTo(dek.getEncoded());

        // Новый wrapping идет уже новым KEK-ом
        WrappedDek rewrapped = rotatedService.wrapDek(restored);
        assertThat(rewrapped.kekId()).isEqualTo("secondary");
        assertThat(rotatedService.unwrapDek(rewrapped).getEncoded()).isEqualTo(dek.getEncoded());
    }

    @Test
    @DisplayName("Кириллица и спецсимволы проходят round-trip")
    void unicodeRoundTrip() {
        String plaintext = "логин@example.com\nпароль:\"p@$$w0rd\"線";
        String encrypted = service.encrypt(plaintext, dek);
        assertThat(service.decrypt(encrypted, dek)).isEqualTo(plaintext);
    }

    // -- helpers -----------------------------------------------------------

    private static byte[] extractIv(String encryptedBase64) {
        byte[] container = Base64.getDecoder().decode(encryptedBase64);
        byte[] iv = new byte[12];
        System.arraycopy(container, 0, iv, 0, 12);
        return iv;
    }

    private static KeyManager keyManagerWithActive(String secretBase64) {
        CryptoProperties props = new CryptoProperties();
        props.setMasterKeyBase64(secretBase64);
        KeyManager manager = new KeyManager(props, () -> new String[0]);
        manager.afterPropertiesSet();
        return manager;
    }
}
