package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.Tag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Репозиторий тегов. Теги хранятся в открытом виде, уникальны в пределах
 * пользователя (по {@code name_lower}).
 */
@Repository
public interface TagRepository extends JpaRepository<Tag, UUID> {

    Optional<Tag> findByUser_IdAndNameLower(UUID userId, String nameLower);

    List<Tag> findAllByUser_Id(UUID userId);

    /**
     * Теги записей одним запросом для страницы списка (без N+1):
     * пары (entryId, Tag), отсортированные по name_lower тега.
     */
    @Query("select v.id, t from VaultEntry v join v.tags t "
            + "where v.id in :entryIds order by t.nameLower")
    List<Object[]> findTagsByEntryIds(@Param("entryIds") Collection<UUID> entryIds);

    /** Количество записей по каждому тегу пользователя (для страницы /web/tags). */
    @Query("select t.id, count(v.id) from VaultEntry v join v.tags t "
            + "where t.user.id = :userId group by t.id")
    List<Object[]> countEntriesPerTagByUserId(@Param("userId") UUID userId);
}
