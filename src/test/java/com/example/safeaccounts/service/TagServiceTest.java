package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты контракта гонки параллельного создания тега (fix cycle 2):
 * INSERT выполняется в отдельной транзакции ({@link TagInsertHelper},
 * REQUIRES_NEW), DataIntegrityViolationException ловится ВНЕ вставки,
 * повторный findByUser_IdAndNameLower — в здоровой внешней транзакции.
 * На моках фиксируется сигнатура контракта; корректность на живом PG
 * проверяет {@code WebTagRaceIT} (Testcontainers, regression).
 */
@ExtendWith(MockitoExtension.class)
class TagServiceTest {

    @Mock
    TagRepository tagRepository;
    @Mock
    VaultEntryRepository vaultEntryRepository;
    @Mock
    TagInsertHelper insertHelper;
    @Mock
    AuditService auditService;

    TagService tagService;
    User actor;
    VaultEntry entry;
    Tag parallelWinner;

    private static final Instant NOW = Instant.parse("2025-01-01T00:00:00Z");

    @BeforeEach
    void setUp() {
        tagService = new TagService(tagRepository, vaultEntryRepository, insertHelper,
                auditService, Clock.fixed(NOW, ZoneOffset.UTC));
        actor = new User(UUID.randomUUID(), "actor", "hash", "ROLE_USER", true,
                0, null, "dek-wrapped", "dek-iv", "kek-id", NOW, null, null);
        entry = new VaultEntry(UUID.randomUUID(), actor,
                "name-enc", "site-enc", "login-enc", "password-enc",
                null, NOW, null, null);
        // Тег, «выигравший» гонку: вставлен параллельным запросом
        parallelWinner = Tag.create(UUID.randomUUID(), actor, "Work", NOW);
    }

    @Test
    void attachOrCreateResolvesUniqueRaceByReusingParallelWinner() {
        when(vaultEntryRepository.findByIdAndUser_Id(entry.getId(), actor.getId()))
                .thenReturn(Optional.of(entry));
        // Первый find — тега нет; после неудачного INSERT — есть (параллельный winner)
        when(tagRepository.findByUser_IdAndNameLower(actor.getId(), "work"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(parallelWinner));
        // INSERT в REQUIRES_NEW-транзакции нарушает UNIQUE(user_id, name_lower);
        // DIVe пробрасывается наружу, внутренняя tx откатывается
        when(insertHelper.insert(any(Tag.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        Tag result = tagService.attachOrCreate(actor, entry.getId(), "work");

        // Гонка разрешена переиспользованием: без исключений, тег привязан
        assertThat(result.getId()).isEqualTo(parallelWinner.getId());
        assertThat(entry.getTags()).containsExactly(parallelWinner);
        verify(vaultEntryRepository).saveAndFlush(entry);
    }

    @Test
    void createTagResolvesUniqueRaceWithTagAlreadyExistsException() {
        when(tagRepository.findByUser_IdAndNameLower(actor.getId(), "work"))
                .thenReturn(Optional.empty())
                .thenReturn(Optional.of(parallelWinner));
        when(insertHelper.insert(any(Tag.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> tagService.createTag(actor, "work"))
                .isInstanceOf(TagAlreadyExistsException.class);
    }
}
