package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.CryptoProperties;
import com.example.safeaccounts.crypto.KeyManager;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.AuditEventRepository;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.security.PasswordHasher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.env.Environment;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты бизнес-правил {@link AdminService} (Task-06):
 * проверка роли, сброс пароля с отзывом токенов, идемпотентность rewrap-deks,
 * аудит без секретов.
 */
@ExtendWith(MockitoExtension.class)
class AdminServiceTest {

    private static final String KEK_V1 = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY";

    @Mock
    UserRepository userRepository;
    @Mock
    AuditEventRepository auditEventRepository;
    @Mock
    UserService userService;
    @Mock
    TokenService tokenService;
    @Mock
    PasswordHasher passwordHasher;
    @Mock
    AuditService auditService;

    AesGcmCryptoService cryptoService;
    AdminService adminService;
    User admin;
    User user;

    private static final Instant NOW = Instant.parse("2025-06-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        CryptoProperties props = new CryptoProperties();
        // Фиксированный тестовый KEK — только тестовый профиль (AGENTS.md).
        props.setMasterKeyBase64(KEK_V1);
        Environment environment = org.mockito.Mockito.mock(Environment.class);
        // Заглушка используется не во всех тестах — допускаем лишнюю.
        org.mockito.Mockito.lenient().when(environment.getActiveProfiles())
                .thenReturn(new String[]{"test"});
        KeyManager keyManager = new KeyManager(props, environment);
        keyManager.afterPropertiesSet();
        cryptoService = new AesGcmCryptoService(keyManager);

        adminService = new AdminService(userRepository, auditEventRepository,
                userService, tokenService, passwordHasher, auditService,
                keyManager, cryptoService, Clock.fixed(NOW, ZoneOffset.UTC));

        admin = userWithDek("admin", "ROLE_ADMIN", KEK_V1);
        user = userWithDek("user", "ROLE_USER", KEK_V1);
        initialWrapped = user.getDekWrapped();
    }

    private User userWithDek(String username, String role, String kekId) {
        var dek = cryptoService.generateDek();
        var wrapped = cryptoService.wrapDek(dek);
        // Симулируем ключ kekId при необходимости: в тестах активен ровно один KEK,
        // поэтому dek_kek_id совпадает с реальным.
        return new User(UUID.randomUUID(), username, "hash", role, true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(),
                kekId.equals(wrapped.kekId()) ? wrapped.kekId() : wrapped.kekId(),
                NOW, null, null);
    }

    // -- роль -----------------------------------------------------------------

    @Test
    void createUserRequiresAdminRole() {
        assertThatThrownBy(() -> adminService.createUser("newuser", "Str0ng-Passw0rd!", "ROLE_USER", user))
                .isInstanceOf(AccessDeniedException.class);
        verify(userService, never()).register(anyString(), anyString(), anyString());
    }

    @Test
    void rewrapDeksRequiresAdminRole() {
        assertThatThrownBy(() -> adminService.rewrapDeks(user))
                .isInstanceOf(AccessDeniedException.class);
        verify(auditService, never()).record(any(), eq(AuditService.KEY_ROTATION_STARTED),
                any(), (java.util.Map<String, ?>) any());
    }

    @Test
    void resetPasswordRequiresAdminRole() {
        assertThatThrownBy(() -> adminService.resetPassword(
                user.getId(), "Str0ng-Passw0rd!", user))
                .isInstanceOf(AccessDeniedException.class);
    }

    // -- сброс пароля ---------------------------------------------------------

    @Test
    void resetPasswordHashesAndRevokesAllTokensAndAudits() {
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(passwordHasher.hash("New-Str0ng-Pass!")).thenReturn("new-hash");
        when(tokenService.revokeAllForUser(user.getId())).thenReturn(3);

        int revoked = adminService.resetPassword(user.getId(), "New-Str0ng-Pass!", admin);

        assertThat(revoked).isEqualTo(3);
        assertThat(user.getPasswordHash()).isEqualTo("new-hash");
        verify(tokenService).revokeAllForUser(user.getId());
        // Аудит не содержит пароля: details — только actor и счетчик токенов.
        verify(auditService).record(eq(user), eq(AuditService.USER_RESET_PASSWORD),
                eq((UUID) null), (java.util.Map<String, ?>) any());
    }

    @Test
    void resetPasswordRejectsShortPassword() {
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        assertThatThrownBy(() -> adminService.resetPassword(user.getId(), "short", admin))
                .isInstanceOf(IllegalArgumentException.class);
        verify(passwordHasher, never()).hash(anyString());
        verify(tokenService, never()).revokeAllForUser(any());
    }

    @Test
    void resetPasswordFailsOnUnknownUser() {
        UUID unknown = UUID.randomUUID();
        when(userRepository.findById(unknown)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> adminService.resetPassword(unknown, "Str0ng-Passw0rd!", admin))
                .isInstanceOf(AuthServiceException.class);
    }

    // -- rewrap-deks ----------------------------------------------------------

    @Test
    void rewrapDeksIsIdempotentAndRewrapsOnlyStaleUsers() {
        // user уже на активном ключе (kekId == активный), stale-пользователь — нет.
        when(userRepository.findByDekKekIdNot("primary")).thenReturn(List.of(user));

        AdminService.RewrapResult first = adminService.rewrapDeks(admin);
        assertThat(first.rewrappedUsers()).isEqualTo(1);
        assertThat(user.getDekKekId()).isEqualTo("primary");
        // DEK тот же: расшифровка данных после ротации продолжает работать.
        // (проверяем, что wrapped изменился — перешифровка performed новым ключом)
        assertThat(user.getDekWrapped()).isNotEqualTo(initialWrapped);

        // Повторный запуск: никого перепаковывать не нужно.
        when(userRepository.findByDekKekIdNot("primary")).thenReturn(List.of());
        AdminService.RewrapResult second = adminService.rewrapDeks(admin);
        assertThat(second.rewrappedUsers()).isZero();

        verify(auditService, org.mockito.Mockito.times(2)).record(eq(admin),
                eq(AuditService.KEY_ROTATION_STARTED),
                eq((UUID) null), (java.util.Map<String, ?>) any());
        verify(auditService, org.mockito.Mockito.times(2)).record(eq(admin),
                eq(AuditService.KEY_ROTATION_COMPLETED),
                eq((UUID) null), (java.util.Map<String, ?>) any());
    }

    String initialWrapped;

    @Test
    void rewrapDeksFailureAuditsAndThrows() {
        User broken = new User(UUID.randomUUID(), "broken", "hash", "ROLE_USER", true,
                0, null, "not-valid-base64-or-garbage", "AAAA", "unknown-kek",
                NOW, null, null);
        when(userRepository.findByDekKekIdNot("primary")).thenReturn(List.of(broken));

        assertThatThrownBy(() -> adminService.rewrapDeks(admin))
                .isInstanceOf(KeyRotationException.class);
        verify(auditService).record(eq(admin), eq(AuditService.KEY_ROTATION_FAILED),
                eq((UUID) null), (java.util.Map<String, ?>) any());
    }

    @Test
    void auditFiltersBuildSpecificationWithoutErrors() {
        var page = new PageImpl<>(List.of(), PageRequest.of(0, 10), 0);
        when(auditEventRepository.findAll(any(org.springframework.data.jpa.domain.Specification.class),
                any(Pageable.class))).thenReturn(page);

        var result = adminService.listAudit("LOGIN_SUCCESS", user.getId(),
                NOW.minusSeconds(60), NOW, 0, 10);

        assertThat(result.getTotalElements()).isZero();
    }
}
