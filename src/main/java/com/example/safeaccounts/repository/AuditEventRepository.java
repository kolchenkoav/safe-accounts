package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Репозиторий аудита. details_json должен содержать только
 * нечувствительные метаданные (без секретов и расшифровок).
 */
@Repository
public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID>,
        JpaSpecificationExecutor<AuditEvent> {

    List<AuditEvent> findAllByUser_IdOrderByCreatedAtDesc(UUID userId);

    Page<AuditEvent> findAllByOrderByCreatedAtDesc(Pageable pageable);

    List<AuditEvent> findAllByCreatedAtAfterOrderByCreatedAtDesc(Instant after);
}
