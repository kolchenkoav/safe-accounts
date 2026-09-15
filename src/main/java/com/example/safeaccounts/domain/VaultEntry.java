package com.example.safeaccounts.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Запись сейфа (имя, сайт, логин, пароль, примечание).
 * Все чувствительные поля хранятся только в зашифрованном виде
 * (AES-256-GCM, base64(iv || ciphertext || tag)); в списковых запросах
 * пароль не возвращается.
 * Связь с тегами — many-to-many через {@code vault_entry_tags};
 * каскадов и orphan-removal нет (теги живут независимо).
 */
@Entity
@Table(name = "vault_entries")
public class VaultEntry {

    @Id
    @Column(nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false,
            foreignKey = @ForeignKey(name = "fk_vault_entries_user"))
    private User user;

    /**
     * Шифротекст имени (base64(iv || ciphertext || tag));
     * открытое значение в БД отсутствует.
     */
    @Column(name = "name_enc", nullable = false)
    private String nameEnc;

    /** Шифротекст сайта (base64), открытое значение в БД отсутствует. */
    @Column(name = "site_enc", nullable = false)
    private String siteEnc;

    /** Шифротекст логина (base64). */
    @Column(name = "login_enc", nullable = false)
    private String loginEnc;

    /** Шифротекст пароля (base64), никогда не логируется. */
    @Column(name = "password_enc", nullable = false)
    private String passwordEnc;

    /** Шифротекст примечания (base64), nullable. */
    @Column(name = "notes_enc")
    private String notesEnc;

    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    @Version
    private Long version;

    /**
     * Теги записи (plaintext). Загружаются лениво; каскадного удаления тегов
     * нет — удаление записи чистит только связи (ON DELETE CASCADE в БД).
     */
    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "vault_entry_tags",
            joinColumns = @JoinColumn(name = "vault_entry_id",
                    foreignKey = @ForeignKey(name = "fk_vet_entry")),
            inverseJoinColumns = @JoinColumn(name = "tag_id",
                    foreignKey = @ForeignKey(name = "fk_vet_tag")))
    private Set<Tag> tags = new LinkedHashSet<>();

    protected VaultEntry() {
        // для JPA
    }

    public VaultEntry(UUID id,
                      User user,
                      String nameEnc,
                      String siteEnc,
                      String loginEnc,
                      String passwordEnc,
                      String notesEnc,
                      Instant createdAt,
                      Instant updatedAt,
                      Long version) {
        this.id = id;
        this.user = user;
        this.nameEnc = nameEnc;
        this.siteEnc = siteEnc;
        this.loginEnc = loginEnc;
        this.passwordEnc = passwordEnc;
        this.notesEnc = notesEnc;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.version = version;
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public String getNameEnc() {
        return nameEnc;
    }

    public String getSiteEnc() {
        return siteEnc;
    }

    public String getLoginEnc() {
        return loginEnc;
    }

    public String getPasswordEnc() {
        return passwordEnc;
    }

    public String getNotesEnc() {
        return notesEnc;
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

    /** Теги записи; коллекция модифицируется через сервисный слой. */
    public Set<Tag> getTags() {
        return tags;
    }

    // -- доменные операции (вызываются только сервисным слоем, Task-05) ------

    /**
     * Полностью заменяет зашифрованные поля записи (обновление через API).
     * Аргументы — готовые шифротексты; открытые значения сюда не передаются.
     * Оптимистичная блокировка обеспечивается {@code @Version}.
     */
    public void updateEncrypted(String newNameEnc,
                                String newSiteEnc,
                                String newLoginEnc,
                                String newPasswordEnc,
                                String newNotesEnc,
                                Instant at) {
        this.nameEnc = newNameEnc;
        this.siteEnc = newSiteEnc;
        this.loginEnc = newLoginEnc;
        this.passwordEnc = newPasswordEnc;
        this.notesEnc = newNotesEnc;
        this.updatedAt = at;
    }
}