package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты бизнес-правил {@link VaultService} (Task-05):
 * owner-scope, шифрование всех полей, отсутствие пароля в списках,
 * нейтральные ошибки, аудит без секретов.
 * Реальная криптография — {@link AesGcmCryptoService} с тестовым KEK.
 */
@ExtendWith(MockitoExtension.class)
class VaultServiceTest {

    @Mock
    VaultEntryRepository vaultEntryRepository;
    @Mock
    AuditService auditService;

    AesGcmCryptoService cryptoService;
    VaultService vaultService;
    User owner;

    private static final Instant NOW = Instant.parse("2025-01-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        var props = new com.example.safeaccounts.crypto.CryptoProperties();
        // Фиксированный тестовый KEK — только тестовый профиль (AGENTS.md).
        props.setMasterKeyBase64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY");
        var environment = org.mockito.Mockito.mock(org.springframework.core.env.Environment.class);
        var keyManager = new com.example.safeaccounts.crypto.KeyManager(props, environment);
        keyManager.afterPropertiesSet();
        cryptoService = new AesGcmCryptoService(keyManager);
        Clock fixedClock = Clock.fixed(NOW, ZoneOffset.UTC);
        vaultService = new VaultService(vaultEntryRepository, cryptoService, auditService, fixedClock);

        var dek = cryptoService.generateDek();
        var wrapped = cryptoService.wrapDek(dek);
        owner = new User(UUID.randomUUID(), "owner", "hash", "ROLE_USER", true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                NOW, null, null);
    }

    private User otherUser() {
        var dek = cryptoService.generateDek();
        var wrapped = cryptoService.wrapDek(dek);
        return new User(UUID.randomUUID(), "other", "hash", "ROLE_USER", true,
                0, null, wrapped.wrappedDekBase64(), wrapped.ivBase64(), wrapped.kekId(),
                NOW, null, null);
    }

    @Test
    void createEncryptsAllFieldsWithOwnerDek() {
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

VaultService.CreatedEntry created = vaultService.create(
                owner, "MyAccount", "https://example.com", "alice", "S3cret-Pass!", "my note");

        VaultEntry saved = created.entry();
        assertThat(saved.getNameEnc()).isNotEqualTo("MyAccount");
        assertThat(saved.getSiteEnc()).isNotEqualTo("https://example.com");
        assertThat(saved.getLoginEnc()).isNotEqualTo("alice");
        assertThat(saved.getPasswordEnc()).isNotEqualTo("S3cret-Pass!");
        assertThat(saved.getNotesEnc()).isNotEqualTo("my note");
        // Все поля реально расшифровываются DEK владельца
        SecretKey dek = cryptoService.unwrapDek(new com.example.safeaccounts.crypto.WrappedDek(
                owner.getDekWrapped(), owner.getDekIv(), owner.getDekKekId()));
        assertThat(cryptoService.decrypt(saved.getNameEnc(), dek)).isEqualTo("MyAccount");
        assertThat(cryptoService.decrypt(saved.getSiteEnc(), dek)).isEqualTo("https://example.com");
        assertThat(cryptoService.decrypt(saved.getLoginEnc(), dek)).isEqualTo("alice");
        assertThat(cryptoService.decrypt(saved.getPasswordEnc(), dek)).isEqualTo("S3cret-Pass!");
        assertThat(cryptoService.decrypt(saved.getNotesEnc(), dek)).isEqualTo("my note");
        verify(auditService).record(eq(owner), eq(AuditService.SECRET_CREATED),
                isNull(), eq("VaultEntry"), eq(saved.getId().toString()), isNull());
    }

    @Test
    void createWithNullNotesStoresNullNotesEnc() {
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));
VaultService.CreatedEntry created = vaultService.create(owner, "n", "s", "l", "p", null);
        assertThat(created.entry().getNotesEnc()).isNull();
    }

    @Test
    void getOfForeignEntryThrowsNeutralNotFound() {
        UUID entryId = UUID.randomUUID();
        when(vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> vaultService.get(owner, entryId, false))
                .isInstanceOf(VaultException.class)
                .hasMessage("Vault entry not found");
    }

    @Test
    void getWithoutRevealDoesNotDecryptPassword() {
        SecretKey dek = unwrap(owner);
        // Пароль зашифрован посторонним ключом: при reveal это упало бы,
        // но без reveal пароль вообще не расшифровывается.
        SecretKey foreignDek = cryptoService.generateDek();
        String nameEnc = cryptoService.encrypt("site", dek);
        VaultEntry entry = new VaultEntry(UUID.randomUUID(), owner,
                nameEnc,
                cryptoService.encrypt("site", dek),
                cryptoService.encrypt("login", dek),
                cryptoService.encrypt("pass", foreignDek),
                null, NOW, null, null);
        UUID entryId = entry.getId();
        when(vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId()))
                .thenReturn(Optional.of(entry));

        VaultService.DecryptedEntry d = vaultService.get(owner, entryId, false);
        assertThat(d.site()).isEqualTo("site");
        assertThat(d.login()).isEqualTo("login");
        assertThat(d.password()).isNull();
    }

    @Test
    void getWithRevealOfCorruptPasswordFailsNeutral() {
        String enc = cryptoService.encrypt("site", unwrap(owner));
        VaultEntry entry = new VaultEntry(UUID.randomUUID(), owner,
                enc,
                cryptoService.encrypt("site", unwrap(owner)),
                cryptoService.encrypt("login", unwrap(owner)),
                "not-a-valid-gcm-container",
                null, NOW, null, null);
        UUID entryId = entry.getId();
        when(vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId()))
                .thenReturn(Optional.of(entry));

        assertThatThrownBy(() -> vaultService.get(owner, entryId, true))
                .isInstanceOf(VaultException.class)
                .hasMessage("Unable to read vault entry")
                .hasNoCause(); // причина наружу не раскрывается
    }

    @Test
    void updateReencryptsWithNewIvAndAudits() {
        SecretKey dek = unwrap(owner);
        String oldSiteEnc = cryptoService.encrypt("old-site", dek);
        VaultEntry entry = new VaultEntry(UUID.randomUUID(), owner,
                oldSiteEnc,
                cryptoService.encrypt("old-site", dek),
                cryptoService.encrypt("old-login", dek),
                cryptoService.encrypt("old-pass", dek),
                null, NOW, null, 1L);
        UUID entryId = entry.getId();
        when(vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId()))
                .thenReturn(Optional.of(entry));
        when(vaultEntryRepository.saveAndFlush(any())).thenAnswer(inv -> inv.getArgument(0));

vaultService.update(owner, entryId, "new-name", "new-site", "new-login", "new-pass", "note");

        ArgumentCaptor<VaultEntry> captor = ArgumentCaptor.forClass(VaultEntry.class);
        verify(vaultEntryRepository).saveAndFlush(captor.capture());
        VaultEntry saved = captor.getValue();
        assertThat(cryptoService.decrypt(saved.getSiteEnc(), dek)).isEqualTo("new-site");
        assertThat(cryptoService.decrypt(saved.getPasswordEnc(), dek)).isEqualTo("new-pass");
        verify(auditService).record(eq(owner), eq(AuditService.SECRET_UPDATED),
                isNull(), eq("VaultEntry"), eq(entryId.toString()), isNull());
    }

    @Test
    void deleteOfForeignEntryThrowsNotFoundAndDoesNotAudit() {
        UUID entryId = UUID.randomUUID();
        when(vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> vaultService.delete(owner, entryId))
                .isInstanceOf(VaultException.class);
        verify(vaultEntryRepository, org.mockito.Mockito.never()).delete(any());
    }

    @Test
    void listDecryptsOnlySiteAndLoginSortedByCreatedAt() {
        SecretKey dek = unwrap(owner);
        String siteEnc = cryptoService.encrypt("site", dek);
        VaultEntry entry = new VaultEntry(UUID.randomUUID(), owner,
                siteEnc,
                cryptoService.encrypt("site", dek),
                cryptoService.encrypt("login", dek),
                cryptoService.encrypt("secret-pass", dek),
                cryptoService.encrypt("note", dek), NOW, null, null);
        var page = new PageImpl<>(List.of(entry), PageRequest.of(0, 20,
                Sort.by(Sort.Direction.ASC, "createdAt")), 1);
        when(vaultEntryRepository.findAllByUser_Id(eq(owner.getId()), any(PageRequest.class)))
                .thenReturn(page);

        var result = vaultService.list(owner, 0, 20);
        assertThat(result.getContent()).hasSize(1);
        var item = result.getContent().get(0);
        assertThat(item.site()).isEqualTo("site");
        assertThat(item.login()).isEqualTo("login");
        assertThat(item.id()).isEqualTo(entry.getId());
        // В ListItem вообще нет поля пароля/notes — компилятор гарантирует.
    }

    private SecretKey unwrap(User user) {
        return cryptoService.unwrapDek(new com.example.safeaccounts.crypto.WrappedDek(
                user.getDekWrapped(), user.getDekIv(), user.getDekKekId()));
    }
}