package com.example.safeaccounts.it;

import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.KeyManager;
import com.example.safeaccounts.crypto.WrappedDek;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Интеграционный тест Task-03: криптомодуль работает поверх реальной БД —
 * DEK генерируется, wraps KEK-ом и сохраняется в users
 * (dek_wrapped / dek_iv / dek_kek_id), затем читается и unwraps;
 * пароль пользователя шифруется DEK-ом и расшифровывается обратно.
 * Тестовый мастер-ключ задается только в тестовом профиле (application-it.yaml).
 */
@SpringBootTest
@ActiveProfiles("it")
@Testcontainers
class CryptoIntegrationIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("safe_accounts")
                    .withUsername("safe_app")
                    .withPassword("it_db_password");

    @Autowired
    KeyManager keyManager;
    @Autowired
    AesGcmCryptoService cryptoService;
    @Autowired
    UserRepository userRepository;
    @Autowired
    TransactionTemplate transactionTemplate;

    @Test
    void dekRoundTripThroughDatabase() {
        SecretKey dek = cryptoService.generateDek();
        WrappedDek wrapped = cryptoService.wrapDek(dek);

        UUID userId = transactionTemplate.execute(status -> {
            User user = new User(
                    UUID.randomUUID(), "crypto-user", "argon2id$synthetic",
                    "ROLE_USER", true, 0, null,
                    wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                    Instant.now(), null, null);
            return userRepository.saveAndFlush(user).getId();
        });

        transactionTemplate.executeWithoutResult(status -> {
            User loaded = userRepository.findById(userId).orElseThrow();
            assertThat(loaded.getDekKekId()).isEqualTo("primary");

            SecretKey restored = cryptoService.unwrapDek(
                    new WrappedDek(loaded.getDekWrapped(), loaded.getDekIv(), loaded.getDekKekId()));
            assertThat(restored.getEncoded()).isEqualTo(dek.getEncoded());

            // Полный цикл: шифруем секрет DEK-ом, расшифровываем восстановленным
            String secret = "p@ssw0rd-из-БД";
            String encrypted = cryptoService.encrypt(secret, restored);
            assertThat(cryptoService.decrypt(encrypted, restored)).isEqualTo(secret);
        });
    }
}
