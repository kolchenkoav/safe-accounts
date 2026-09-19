package com.example.safeaccounts.service;

import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.WrappedDek;
import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.security.RateLimiter;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты diff-логики тегов и отчёта {@link VaultScanService} (G2, план §4):
 * add слабым / remove у исправившихся / идемпотентность / truncated / отчёт
 * и аудит без паролей. Реальный {@link WeakPasswordEvaluator} (детерминированные
 * пароли: «123456» — слабый, случайная 20-символьная — сильный).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VaultScanServiceTest {

    @Mock
    VaultEntryRepository vaultEntryRepository;
    @Mock
    TagService tagService;
    @Mock
    AesGcmCryptoService cryptoService;
    @Mock
    AuditService auditService;
    @Mock
    RateLimiter rateLimiter;

    private static final Instant NOW = Instant.parse("2025-06-01T00:00:00Z");
    private static final String WEAK_PASSWORD = "123456";
    private static final String STRONG_PASSWORD = "Zk9#mQ2$vL8!wR4&xJ6%";

    private ScanProperties scanProperties;
    private VaultScanService service;
    private User target;
    private Tag weakTag;
    private UUID weakTagId;
    private VaultEntry weakUntagged;
    private VaultEntry strongTagged;
    private VaultEntry weakTagged;

    @BeforeEach
    void setUp() {
        scanProperties = new ScanProperties();
        target = new User(UUID.randomUUID(), "target", "hash", "ROLE_USER", true,
                0, null, "dek-wrapped", "dek-iv", "kek-id", NOW, null, null);
        // ВАЖНО: стабgetId должен быть ПЕРВЫМ — вызов getId() на моке внутри
        // другого when() (eq(weakTag.getId())) ловится Mockito как misuse.
        weakTagId = UUID.randomUUID();
        weakTag = mock(Tag.class);
        when(weakTag.getId()).thenReturn(weakTagId);

        weakUntagged = entry("e1", WEAK_PASSWORD);
        strongTagged = entry("e2", STRONG_PASSWORD);
        strongTagged.getTags().add(weakTag);
        weakTagged = entry("e3", "password");
        weakTagged.getTags().add(weakTag);

        org.springframework.transaction.PlatformTransactionManager txManager =
                mock(org.springframework.transaction.PlatformTransactionManager.class);
        service = new VaultScanService(vaultEntryRepository, tagService, cryptoService,
                new WeakPasswordEvaluator(), scanProperties, auditService, rateLimiter,
                new org.springframework.transaction.support.TransactionTemplate(txManager));

        when(tagService.findOrCreateByName(target, VaultScanService.WEAK_PASSWORD_TAG_NAME))
                .thenReturn(weakTag);
        when(rateLimiter.tryAcquireWithRetryAfter(anyString(), any()))
                .thenReturn(RateLimiter.Decision.ALLOWED);
        when(cryptoService.unwrapDek(any(WrappedDek.class))).thenReturn(mock(SecretKey.class));
        when(vaultEntryRepository.findAllById(any())).thenAnswer(inv -> {
            java.util.List<UUID> ids = new java.util.ArrayList<>();
            for (Object id : (Iterable<?>) inv.getArgument(0)) {
                ids.add((UUID) id);
            }
            return java.util.List.of(weakUntagged, strongTagged, weakTagged).stream()
                    .filter(e -> ids.contains(e.getId()))
                    .toList();
        });
        when(cryptoService.decrypt(anyString(), any())).thenAnswer(inv -> {
            String cipher = inv.getArgument(0);
            if (cipher.startsWith("enc-pass-e1")) return WEAK_PASSWORD;
            if (cipher.startsWith("enc-pass-e2")) return STRONG_PASSWORD;
            if (cipher.startsWith("enc-pass-e3")) return "password";
            if (cipher.startsWith("enc-name")) return "Name-" + cipher.substring(9);
            /* При добавлении новых when(...)-заглушек Mockito «реплеит» уже
               зарегистрированный answer с дефолтными аргументами — возвращаем
               сильный дефолт вместо исключения (иначе упадёт вся последующая
               заглушка). Скан на bulk-записях ниже перекрыт contains-stub'ами. */
            return "Default-Strong-Passw0rd!";
        });
        when(vaultEntryRepository.findAllByUser_Id(eq(target.getId()), any(Pageable.class)))
                .thenAnswer(inv -> {
                    Pageable pageable = inv.getArgument(1);
                    return pageable.getPageNumber() == 0
                            ? new PageImpl<>(List.of(weakUntagged, strongTagged, weakTagged))
                            : new PageImpl<>(List.of());
                });
        // Динамический ответ: множество помеченных вычисляется из живых сущностей.
        when(vaultEntryRepository.findAllByUser_IdAndTags_Id(
                eq(target.getId()), eq(weakTagId), any(Pageable.class)))
                .thenAnswer(inv -> new PageImpl<>(List.of(
                        weakUntagged, strongTagged, weakTagged).stream()
                        .filter(e -> e.getTags().contains(weakTag))
                        .toList()));
    }

    private VaultEntry entry(String index, String password) {
        return new VaultEntry(UUID.randomUUID(), target,
                "enc-name-" + index, "enc-site-" + index, "enc-login-" + index,
                "enc-pass-" + index, null, NOW, null, null);
    }

    @Test
    void scanAppliesExactTagDiff() {
        VaultScanService.ScanReport report = service.scan(target, target);

        assertThat(report.scanned()).isEqualTo(3);
        assertThat(report.weakCount()).isEqualTo(2);
        assertThat(report.tagged()).isEqualTo(1);
        assertThat(report.untagged()).isEqualTo(1);
        assertThat(report.failed()).isZero();
        assertThat(report.truncated()).isFalse();

        assertThat(weakUntagged.getTags()).containsExactly(weakTag);
        assertThat(strongTagged.getTags()).isEmpty();
        assertThat(weakTagged.getTags()).containsExactly(weakTag);

        assertThat(report.weakEntries())
                .extracting(VaultScanService.WeakEntry::name)
                .containsExactlyInAnyOrder("Name-e1", "Name-e3");
        assertThat(report.weakEntries().get(0).reasons()).isNotEmpty();
    }

    @Test
    void repeatedScanIsIdempotent() {
        service.scan(target, target);
        VaultScanService.ScanReport second = service.scan(target, target);

        assertThat(second.tagged()).isZero();
        assertThat(second.untagged()).isZero();
        assertThat(second.weakCount()).isEqualTo(2);
    }

    @Test
    void truncatedWhenMoreThanLimitEntries() {
        // >10 000 записей: PAGE_SIZE=500, страниц 21+ — скан останавливается на лимите.
        List<VaultEntry> many = new java.util.ArrayList<>();
        for (int i = 0; i < 21 * 500; i++) {
            many.add(entry("bulk-" + i, WEAK_PASSWORD));
        }
        when(vaultEntryRepository.findAllByUser_Id(eq(target.getId()), any(Pageable.class)))
                .thenAnswer(inv -> {
                    Pageable pageable = inv.getArgument(1);
                    int from = pageable.getPageNumber() * 500;
                    List<VaultEntry> content = from >= many.size()
                            ? List.<VaultEntry>of()
                            : many.subList(from, Math.min(from + 500, many.size()));
                    // total = many.size(): hasNext() должен быть true до последней страницы,
                    // иначе скан закончит после первой страницы (500 < лимита).
                    return new PageImpl<>(content, pageable, many.size());
                });
        // bulk-записи: пароль — слабый "123456" (короткий/только цифры/score 0),
        // имя — Name-bulk-N. Скановый decrypt читает только passwordEnc и nameEnc;
        // site/login/notes не читаются (не расшифровываются).
        when(cryptoService.decrypt(org.mockito.ArgumentMatchers
                .contains("enc-pass-bulk"), any())).thenReturn(WEAK_PASSWORD);
        when(cryptoService.decrypt(org.mockito.ArgumentMatchers
                .contains("enc-name-bulk"), any())).thenAnswer(inv ->
                "Name-" + ((String) inv.getArgument(0)).substring("enc-name-".length()));

        VaultScanService.ScanReport report = service.scan(target, target);

        assertThat(report.truncated()).as("truncated").isTrue();
        assertThat(report.scanned()).as("scanned").isEqualTo(VaultScanService.MAX_SCAN_ENTRIES);
        assertThat(report.weakCount()).as("weakCount").isEqualTo(VaultScanService.MAX_SCAN_ENTRIES);
        assertThat(report.tagged()).as("tagged").isEqualTo(VaultScanService.MAX_SCAN_ENTRIES);
        // В отчёте и аудите нет самих паролей.
        assertThat(report.toString()).doesNotContain(WEAK_PASSWORD);
        var detailsCaptor = ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).record(eq(target), eq(AuditService.VAULT_SCANNED), isNull(),
                eq("User"), eq(target.getId().toString()), detailsCaptor.capture());
        assertThat(String.valueOf(detailsCaptor.getValue())).doesNotContain(WEAK_PASSWORD);
    }

    @Test
    void scanSecondTimeInWindowIsRateLimited() {
        when(rateLimiter.tryAcquireWithRetryAfter(anyString(), any()))
                .thenReturn(new RateLimiter.Decision(false, 60L));

        assertThatThrownBy(() -> service.scan(target, target))
                .isInstanceOf(ScanRateLimitedException.class)
                .hasMessageContaining("try again later");
    }

    @Test
    void auditContainsOnlyAggregates() {
        service.scan(target, target);
        var detailsCaptor = ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).record(
                eq(target), eq(AuditService.VAULT_SCANNED), isNull(),
                eq("User"), eq(target.getId().toString()), detailsCaptor.capture());
        String details = String.valueOf(detailsCaptor.getValue());
        assertThat(details).contains("scanned").contains("weak")
                .contains("tagged").contains("untagged").contains("durationMs");
        assertThat(details).doesNotContain(WEAK_PASSWORD).doesNotContain(STRONG_PASSWORD);
    }

    /** Ошибка расшифровки конкретной записи: failed=1, запись пропущена, скан идёт. */
    @Test
    void scanCountsFailedDecryptAndSkipsEntry() {
        when(cryptoService.decrypt(eq("enc-pass-e2"), any()))
                .thenThrow(new RuntimeException("decrypt boom"));

        VaultScanService.ScanReport report = service.scan(target, target);

        assertThat(report.failed()).as("failed").isEqualTo(1);
        assertThat(report.scanned()).as("scanned").isEqualTo(2);
        assertThat(report.weakCount()).as("weakCount").isEqualTo(2);
        // Пропущенная запись не переклассифицируется: её тег не снимается.
        assertThat(strongTagged.getTags()).containsExactly(weakTag);
        var detailsCaptor = ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).record(eq(target), eq(AuditService.VAULT_SCANNED), isNull(),
                eq("User"), eq(target.getId().toString()), detailsCaptor.capture());
        assertThat(String.valueOf(detailsCaptor.getValue())).contains("failed=1");
    }

    /** Пагинация с детерминированным Sort: createdAt asc + id asc (tie-breaker). */
    @Test
    void scanPagesUseDeterministicSort() {
        service.scan(target, target);

        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(vaultEntryRepository, org.mockito.Mockito.atLeastOnce())
                .findAllByUser_Id(eq(target.getId()), pageableCaptor.capture());
        org.springframework.data.domain.Sort sort =
                pageableCaptor.getAllValues().get(0).getSort();
        org.springframework.data.domain.Sort.Order createdAt = sort.getOrderFor("createdAt");
        org.springframework.data.domain.Sort.Order id = sort.getOrderFor("id");
        assertThat(createdAt).as("createdAt sort order").isNotNull();
        assertThat(createdAt.getDirection())
                .isEqualTo(org.springframework.data.domain.Sort.Direction.ASC);
        assertThat(id).as("id tie-breaker sort order").isNotNull();
        assertThat(id.getDirection())
                .isEqualTo(org.springframework.data.domain.Sort.Direction.ASC);
    }
}
