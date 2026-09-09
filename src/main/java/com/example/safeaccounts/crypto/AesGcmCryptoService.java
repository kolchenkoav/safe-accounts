package com.example.safeaccounts.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM шифрование для сейфа (Task-03).
 * <p>
 * Формат хранения: {@code base64(iv || ciphertext || tag)}:
 * <ul>
 *   <li>IV — 12 байт, генерируется через {@link SecureRandom} на КАЖДУЮ операцию
 *       шифрования и никогда не переиспользуется (NIST SP 800-38D);</li>
 *   <li>ключ — 256 бит (AES-256);</li>
 *   <li>tag — 128 бит, проверяется автоматически при расшифровке.</li>
 * </ul>
 * Реализация на стандартном JCE ({@code AES/GCM/NoPadding}) — самописные
 * криптосхемы запрещены (AGENTS.md).
 * <p>
 * Безопасность: материал ключей и расшифрованные секреты никогда не логируются;
 * при ошибке расшифровки наружу отдается нейтральное {@link CryptoException}
 * без чувствительных деталей.
 */
@Service
public class AesGcmCryptoService {

    static final Logger log = LoggerFactory.getLogger(AesGcmCryptoService.class);

    /** Длина IV для GCM в байтах (NIST SP 800-38D рекомендует 96 бит). */
    static final int IV_BYTES = 12;

    /** Длина тега аутентификации GCM в битах. */
    static final int TAG_BITS = 128;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecureRandom secureRandom = new SecureRandom();
    private final KeyManager keyManager;

    public AesGcmCryptoService(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    /** Генерирует новый пользовательский DEK (AES-256). */
    public SecretKey generateDek() {
        byte[] keyBytes = new byte[32];
        secureRandom.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Шифрует строку DEK-ом пользователя.
     *
     * @return base64(iv || ciphertext || tag)
     */
    public String encrypt(String plaintext, SecretKey dek) {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] iv = newIv();
        try {
            byte[] ciphertextAndTag = cipher(Cipher.ENCRYPT_MODE, dek, iv).doFinal(plaintextBytes);
            return toContainerBase64(iv, ciphertextAndTag);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("Encryption failed");
        }
    }

    /**
     * Расшифровывает base64(iv || ciphertext || tag).
     * При любой ошибке (неверный ключ, поврежденный IV/шифротекст/тег,
     * некорректный base64) бросает нейтральное {@link CryptoException}.
     */
    public String decrypt(String encryptedBase64, SecretKey dek) {
        byte[] container;
        try {
            container = Base64.getDecoder().decode(encryptedBase64);
        } catch (IllegalArgumentException e) {
            throw new CryptoException("Decryption failed: malformed input");
        }
        if (container.length <= IV_BYTES) {
            throw new CryptoException("Decryption failed: malformed input");
        }
        byte[] iv = Arrays.copyOfRange(container, 0, IV_BYTES);
        byte[] ciphertextAndTag = Arrays.copyOfRange(container, IV_BYTES, container.length);
        try {
            byte[] plaintext = cipher(Cipher.DECRYPT_MODE, dek, iv).doFinal(ciphertextAndTag);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            // AEADBadTagException и др.: неверный ключ или поврежденные данные.
            // Детали не раскрываем и не логируем.
            throw new CryptoException("Decryption failed");
        }
    }

    /**
     * Оборачивает (шифрует) DEK активным KEK для хранения в БД
     * (users.dek_wrapped / dek_iv / dek_kek_id).
     */
    public WrappedDek wrapDek(SecretKey dek) {
        String kekId = keyManager.getActiveKekId();
        SecretKey kek = keyManager.getActiveKek();
        byte[] dekBytes = dek.getEncoded();
        byte[] iv = newIv();
        try {
            byte[] wrapped = cipher(Cipher.ENCRYPT_MODE, kek, iv).doFinal(dekBytes);
            return new WrappedDek(
                    toContainerBase64(iv, wrapped),
                    Base64.getEncoder().encodeToString(iv),
                    kekId);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("DEK wrapping failed");
        }
    }

    /**
     * Разворачивает DEK тем KEK, который указан в {@link WrappedDek#kekId()}.
     * Старые (неактивные) KEK поддерживаются, пока заданы в конфигурации.
     */
    public SecretKey unwrapDek(WrappedDek wrappedDek) {
        SecretKey kek = keyManager.getKek(wrappedDek.kekId())
                .orElseThrow(() -> new CryptoException(
                        "Unknown KEK id '" + wrappedDek.kekId() + "'"));
        byte[] container;
        try {
            container = Base64.getDecoder().decode(wrappedDek.wrappedDekBase64());
        } catch (IllegalArgumentException e) {
            throw new CryptoException("DEK unwrapping failed: malformed input");
        }
        if (container.length <= IV_BYTES) {
            throw new CryptoException("DEK unwrapping failed: malformed input");
        }
        byte[] iv = Arrays.copyOfRange(container, 0, IV_BYTES);
        byte[] wrapped = Arrays.copyOfRange(container, IV_BYTES, container.length);
        try {
            byte[] dekBytes = cipher(Cipher.DECRYPT_MODE, kek, iv).doFinal(wrapped);
            return new SecretKeySpec(dekBytes, "AES");
        } catch (GeneralSecurityException e) {
            throw new CryptoException("DEK unwrapping failed");
        }
    }

    // -- internals ---------------------------------------------------------

    private Cipher cipher(int mode, SecretKey key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(mode, key, new GCMParameterSpec(TAG_BITS, iv));
            return cipher;
        } catch (GeneralSecurityException e) {
            // Не должно происходить: AES/GCM/NoPadding есть в каждом стандартном JDK
            throw new CryptoException("Crypto operation failed");
        }
    }

    /** Уникальный случайный IV на каждую операцию; переиспользование исключено. */
    private byte[] newIv() {
        byte[] iv = new byte[IV_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    /** Собирает контейнер base64(iv || data). */
    private static String toContainerBase64(byte[] iv, byte[] data) {
        return Base64.getEncoder().encodeToString(toContainer(iv, data));
    }

    /** Собирает контейнер iv || data. */
    private static byte[] toContainer(byte[] iv, byte[] data) {
        return ByteBuffer.allocate(iv.length + data.length)
                .put(iv)
                .put(data)
                .array();
    }

    /** Нейтральное исключение: не раскрывает чувствительных деталей ошибки. */
    public static class CryptoException extends RuntimeException {
        public CryptoException(String message) {
            super(message);
        }
    }
}
