package com.example.safeaccounts.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Токен доступа (Bearer). В БД хранится только SHA-256 хэш токена (token_hash);
 * сам токен показывается клиенту один раз при выпуске.
 */
@Entity
@Table(name = "auth_tokens")
public class AuthToken {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_auth_tokens_user"))
    private User user;

    /** Хэш токена; сам токен никогда не хранится и не логируется. */
    @Column(name = "token_hash", nullable = false, unique = true, length = 128)
    private String tokenHash;

    /** Не-секретная подсказка для UI (например, последние 4 символа). */
    @Column(name = "token_hint", nullable = false, length = 32)
    private String tokenHint;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Version
    private Long version;

    protected AuthToken() {
        // для JPA
    }

    public AuthToken(UUID id,
                     User user,
                     String tokenHash,
                     String tokenHint,
                     String userAgent,
                     String ipAddress,
                     Instant createdAt,
                     Instant expiresAt,
                     Instant lastUsedAt,
                     Instant revokedAt,
                     Long version) {
        this.id = id;
        this.user = user;
        this.tokenHash = tokenHash;
        this.tokenHint = tokenHint;
        this.userAgent = userAgent;
        this.ipAddress = ipAddress;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.lastUsedAt = lastUsedAt;
        this.revokedAt = revokedAt;
        this.version = version;
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getTokenHint() {
        return tokenHint;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getLastUsedAt() {
        return lastUsedAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public Long getVersion() {
        return version;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired(Instant now) {
        return expiresAt != null && expiresAt.isBefore(now);
    }
}
