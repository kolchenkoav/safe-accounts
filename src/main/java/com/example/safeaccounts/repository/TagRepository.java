package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.Tag;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

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
}