package com.example.safeaccounts.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * Событие аудита. Запрещено записывать сюда расшифрованные секреты:
 * details_json предназначен только для нечувствительных метаданных.
 */
@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", foreignKey = @ForeignKey(name = "fk_audit_events_user"))
    private User user;

    /** UUID отозванного/выпущенного токена; FK в схеме не объявлен намеренно. */
    @Column(name = "token_id")
    private UUID tokenId;

    @Column(nullable = false, length = 64)
    private String type;

    @Column(name = "object_type")
    private String objectType;

    @Column(name = "object_id")
    private String objectId;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "details_json", columnDefinition = "jsonb")
    private String detailsJson;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    protected AuditEvent() {
        // для JPA
    }

    public AuditEvent(UUID id,
                      User user,
                      UUID tokenId,
                      String type,
                      String objectType,
                      String objectId,
                      String ipAddress,
                      String userAgent,
                      String detailsJson,
                      Instant createdAt) {
        this.id = id;
        this.user = user;
        this.tokenId = tokenId;
        this.type = type;
        this.objectType = objectType;
        this.objectId = objectId;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.detailsJson = detailsJson;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public UUID getTokenId() {
        return tokenId;
    }

    public String getType() {
        return type;
    }

    public String getObjectType() {
        return objectType;
    }

    public String getObjectId() {
        return objectId;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getDetailsJson() {
        return detailsJson;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
