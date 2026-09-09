package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.AuthToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Репозиторий Bearer-токенов. Хранит только хэши токенов;
 * ревокация выполняется по token_hash / id пользователя.
 */
@Repository
public interface AuthTokenRepository extends JpaRepository<AuthToken, UUID> {

    Optional<AuthToken> findByTokenHash(String tokenHash);

    List<AuthToken> findAllByUser_Id(UUID userId);

    @Modifying
    @Query("""
            UPDATE AuthToken t
               SET t.revokedAt = :now
             WHERE t.user.id = :userId
               AND t.revokedAt IS NULL
            """)
    int revokeAllForUser(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("""
            UPDATE AuthToken t
               SET t.revokedAt = :now
             WHERE t.tokenHash = :tokenHash
               AND t.revokedAt IS NULL
            """)
    int revokeByTokenHash(@Param("tokenHash") String tokenHash, @Param("now") Instant now);
}
