package com.example.safeaccounts.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Locale;
import java.util.UUID;

/**
 * Тег записи сейфа. Хранится в открытом виде (per-user), уникальность
 * имени — по {@code name_lower} (case-insensitive). Шифрование не применяется.
 * Удаление пользователя каскадно удаляет его теги; удаление записи сейфа
 * каскадно чистит связи в {@code vault_entry_tags} (теги при этом остаются).
 */
@Entity
@Table(name = "tags")
public class Tag {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_tags_user"))
    private User user;

    /** Оригинальное имя тега (1..64 символа, regex на валидации сервиса). */
    @Column(name = "name", nullable = false, length = 64)
    private String name;

    /** Имя в нижнем регистре; используется для UNIQUE и поиска. */
    @Column(name = "name_lower", nullable = false, length = 64)
    private String nameLower;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    protected Tag() {
        // для JPA
    }

    public Tag(UUID id,
               User user,
               String name,
               String nameLower,
               Instant createdAt) {
        this.id = id;
        this.user = user;
        this.name = name;
        this.nameLower = nameLower;
        this.createdAt = createdAt;
    }

    /** Удобный конструктор: вычисляет {@code nameLower} из {@code name}. */
    public static Tag create(UUID id, User user, String name, Instant createdAt) {
        return new Tag(id, user, name, name.toLowerCase(Locale.ROOT), createdAt);
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getName() {
        return name;
    }

    public String getNameLower() {
        return nameLower;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    /**
     * Переименовывает тег; {@code nameLower} пересчитывается автоматически.
     * Вызывается только сервисным слоем.
     */
    public void rename(String newName) {
        this.name = newName;
        this.nameLower = newName.toLowerCase(Locale.ROOT);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (!(other instanceof Tag tag)) return false;
        return id != null && id.equals(tag.id);
    }

    @Override
    public int hashCode() {
        return getClass().hashCode();
    }
}