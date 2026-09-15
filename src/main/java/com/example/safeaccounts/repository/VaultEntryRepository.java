package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.VaultEntry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Репозиторий записей сейфа. Чувствительные поля всегда в шифротексте;
 * пароль по умолчанию нигде не расшифровывается и не возвращается.
 */
@Repository
public interface VaultEntryRepository extends JpaRepository<VaultEntry, UUID> {

    List<VaultEntry> findAllByUser_IdOrderByCreatedAtAsc(UUID userId);

    Optional<VaultEntry> findByIdAndUser_Id(UUID id, UUID userId);

    long deleteByIdAndUser_Id(UUID id, UUID userId);

    /** Пагинированный owner-scoped список (Task-05). */
    org.springframework.data.domain.Page<VaultEntry> findAllByUser_Id(UUID userId,
            org.springframework.data.domain.Pageable pageable);

    /**
     * Пагинированный owner-scoped список записей, помеченных указанным тегом
     * (фильтр «?tag=<id>» web-UI, Фаза 2).
     */
    org.springframework.data.domain.Page<VaultEntry> findAllByUser_IdAndTags_Id(
            UUID userId, UUID tagId, org.springframework.data.domain.Pageable pageable);

    /** Количество записей, ссылающихся на тег (для сообщения об ошибке удаления). */
    long countByTags_Id(UUID tagId);

    /** Количество записей пользователя (cumulative-cap импорта, Фаза 5). */
    long countByUser_Id(UUID userId);

    /**
     * True, если хотя бы одна запись ссылается на указанный тег.
     * Используется сервисом тегов для запрета удаления «занятого» тега.
     */
    boolean existsByTags_Id(UUID tagId);
}
