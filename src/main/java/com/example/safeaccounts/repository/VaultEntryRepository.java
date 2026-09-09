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
}
