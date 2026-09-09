package com.example.safeaccounts.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

/**
 * Пользователь приложения. Хранит только Argon2id-хэш пароля
 * и DEK в wrapped-виде (открытый DEK и мастер-ключ в БД не хранятся).
 */
@Entity
@Table(name = "users")
public class User {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @Column(nullable = false, unique = true, length = 255)
    private String username;

    /** Argon2id-хэш, секрет в открытом виде не хранится и не логируется. */
    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(nullable = false, length = 32)
    private String role;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    /** DEK, зашифрованный (wrapped) мастер-ключом KEK. */
    @Column(name = "dek_wrapped", nullable = false)
    private String dekWrapped;

    /** IV последней операции wrapping DEK (base64). */
    @Column(name = "dek_iv", nullable = false)
    private String dekIv;

    /** Идентификатор KEK, которым wrapped DEK (материал ключа не хранится). */
    @Column(name = "dek_kek_id", nullable = false, length = 64)
    private String dekKekId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Version
    private Long version;

    protected User() {
        // для JPA
    }

    public User(UUID id,
                String username,
                String passwordHash,
                String role,
                boolean enabled,
                int failedAttempts,
                Instant lockedUntil,
                String dekWrapped,
                String dekIv,
                String dekKekId,
                Instant createdAt,
                Instant updatedAt,
                Long version) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.role = role;
        this.enabled = enabled;
        this.failedAttempts = failedAttempts;
        this.lockedUntil = lockedUntil;
        this.dekWrapped = dekWrapped;
        this.dekIv = dekIv;
        this.dekKekId = dekKekId;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.version = version;
    }

    public UUID getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getRole() {
        return role;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public String getDekWrapped() {
        return dekWrapped;
    }

    public String getDekIv() {
        return dekIv;
    }

    public String getDekKekId() {
        return dekKekId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Long getVersion() {
        return version;
    }

    // -- доменные операции (вызываются только сервисным слоем, Task-04) ------

    /** Заменяет хэш пароля (смена пароля). Аргумент — уже готовый Argon2id-хэш. */
    public void changePasswordHash(String newPasswordHash, Instant at) {
        this.passwordHash = newPasswordHash;
        this.updatedAt = at;
    }

    /** Фиксирует состояние защиты от перебора после неудачной попытки входа. */
    public void applyAuthState(int newFailedAttempts, java.time.Instant newLockedUntil, Instant at) {
        this.failedAttempts = newFailedAttempts;
        this.lockedUntil = newLockedUntil;
        this.updatedAt = at;
    }

    /** Сбрасывает счетчик неудачных попыток и блокировку (успешный вход). */
    public void clearAuthFailures(Instant at) {
        this.failedAttempts = 0;
        this.lockedUntil = null;
        this.updatedAt = at;
    }

    /** Включает/отключает учетную запись (административная операция). */
    public void setEnabled(boolean enabled, Instant at) {
        this.enabled = enabled;
        this.updatedAt = at;
    }

    /**
     * Заменяет wrapped-форму DEK при ротации KEK (Task-06): переупаковка тем же
     * DEK новым активным ключом. Сам DEK не меняется — данные остаются читаемыми.
     */
    public void rewrapDek(String newDekWrapped, String newDekIv, String newKekId) {
        this.dekWrapped = newDekWrapped;
        this.dekIv = newDekIv;
        this.dekKekId = newKekId;
        this.updatedAt = Instant.now();
    }
}
