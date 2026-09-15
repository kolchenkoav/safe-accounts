package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.crypto.AesGcmCryptoService;
import com.example.safeaccounts.crypto.AesGcmCryptoService.CryptoException;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

/**
 * Бизнес-правила записей сейфа (Task-05).
 * <p>
 * Правила безопасности (AGENTS.md / Task-05):
 * <ul>
 *   <li>все чувствительные поля (name, site, login, password, notes) перед
 *       сохранением шифруются AES-256-GCM персональным DEK владельца;
 *       в БД нет plaintext;</li>
 *   <li>DEK разворачивается из wrapped-формы через {@link AesGcmCryptoService#unwrapDek}
 *       (KEK берется из окружения, материал ключей в БД/логах отсутствует);</li>
 *   <li>любая операция owner-scoped: чужая запись неотличима от несуществующей
 *       (единый безопасный 404, защита от перечисления записей);</li>
 *   <li>пароль в списках не возвращается; расшифровка пароля — только явный
 *       reveal-запрос владельца, факт которого фиксируется в аудите;</li>
 *   <li>аудит (SECRET_CREATED/UPDATED/DELETED/REVEALED) не содержит расшифрованных
 *       секретов — только идентификаторы;</li>
 *   <li>IV уникален для каждой операции шифрования (SecureRandom внутри
 *       {@link AesGcmCryptoService});</li>
 *   <li>ошибка расшифровки возвращает нейтральное {@link VaultException}
 *       без утечки деталей.</li>
 * </ul>
 */
@Service
public class VaultService {

    static final Logger log = LoggerFactory.getLogger(VaultService.class);

    /** Ограничение размера страницы списка (Task-05: пагинация). */
    static final int MAX_PAGE_SIZE = 100;

    private final VaultEntryRepository vaultEntryRepository;
    private final AesGcmCryptoService cryptoService;
    private final AuditService auditService;
    private final Clock clock;

    public VaultService(VaultEntryRepository vaultEntryRepository,
                        AesGcmCryptoService cryptoService,
                        AuditService auditService,
                        Clock clock) {
        this.vaultEntryRepository = vaultEntryRepository;
        this.cryptoService = cryptoService;
        this.auditService = auditService;
        this.clock = clock;
    }

    /** Результат создания записи: сущность + расшифрованные name/site/login для ответа. */
    public record CreatedEntry(VaultEntry entry, String name, String site, String login) {
    }

    /** Расшифрованные поля записи для детального просмотра. */
    public record DecryptedEntry(String name, String site, String login, String password, String notes,
                                 Instant createdAt, Instant updatedAt) {
    }

    /**
     * Создает запись: шифрует все поля DEK владельца и сохраняет.
     *
     * @throws IllegalArgumentException если поля не проходят сервисную валидацию
     */
    @Transactional
    public CreatedEntry create(User owner, String name, String site, String login,
                               String password, String notes) {
        SecretKey dek = unwrapDek(owner);
        Instant now = clock.instant();

        String nameEnc = cryptoService.encrypt(name, dek);
        String siteEnc = cryptoService.encrypt(site, dek);
        // notes==null значит «примечания нет»: в БД NULL, а не шифротекст пустой строки.
        String notesEnc = notes == null ? null : cryptoService.encrypt(notes, dek);

        VaultEntry entry = new VaultEntry(
                UUID.randomUUID(),
                owner,
                nameEnc,
                siteEnc,
                cryptoService.encrypt(login, dek),
                cryptoService.encrypt(password, dek),
                notesEnc,
                now,
                null,
                null);
        VaultEntry saved = vaultEntryRepository.saveAndFlush(entry);
        auditService.record(owner, AuditService.SECRET_CREATED, null,
                "VaultEntry", saved.getId().toString(), null);
        log.info("Vault entry created: user={}, entryId={}", owner.getId(), saved.getId());
        return new CreatedEntry(saved, name, site, login);
    }

    /**
     * Пагинированный список записей владельца, отсортированный по createdAt (Task-05).
     * Возвращает только шифротексты; расшифровка name/site/login выполняется здесь,
     * пароль и notes намеренно не расшифровываются.
     */
    @Transactional(readOnly = true)
    public Page<ListItem> list(User owner, int page, int size) {
        int safeSize = Math.min(Math.max(size, 1), MAX_PAGE_SIZE);
        Pageable pageable = PageRequest.of(Math.max(page, 0), safeSize,
                Sort.by(Sort.Direction.ASC, "createdAt"));
        Page<VaultEntry> entries = vaultEntryRepository.findAllByUser_Id(owner.getId(), pageable);
        return entries.map(entry -> toListItem(owner, entry));
    }

    /**
     * Детальный просмотр записи владельца. Пароль расшифровывается только при
     * {@code reveal=true}; факт reveal фиксируется в аудите (без самого пароля).
     *
     * @throws VaultException NOT_FOUND, если записи нет или она чужая
     */
    // Не readOnly: внутри пишется событие аудита SECRET_REVEALED.
    @Transactional
    public DecryptedEntry get(User owner, UUID entryId, boolean reveal) {
        VaultEntry entry = findOwnedOrThrow(owner, entryId);
        SecretKey dek = unwrapDek(owner);
        DecryptedEntry decrypted = decryptEntry(entry, dek, reveal);
        if (reveal) {
            auditService.record(owner, AuditService.SECRET_REVEALED, null,
                    "VaultEntry", entryId.toString(), null);
            log.info("Vault entry password revealed: user={}, entryId={}", owner.getId(), entryId);
        }
        return decrypted;
    }

    /**
     * Обновляет запись владельца: все поля перешифровываются заново (новые IV).
     * Оптимистичная блокировка — через {@code @Version} JPA.
     *
     * @throws VaultException NOT_FOUND, если записи нет или она чужая
     */
    @Transactional
    public UpdatedEntry update(User owner, UUID entryId,
                               String name, String site, String login,
                               String password, String notes) {
        VaultEntry entry = findOwnedOrThrow(owner, entryId);
        SecretKey dek = unwrapDek(owner);
        Instant now = clock.instant();

        String notesEnc = notes == null ? null : cryptoService.encrypt(notes, dek);
        entry.updateEncrypted(
                cryptoService.encrypt(name, dek),
                cryptoService.encrypt(site, dek),
                cryptoService.encrypt(login, dek),
                cryptoService.encrypt(password, dek),
                notesEnc,
                now);
        VaultEntry saved = vaultEntryRepository.saveAndFlush(entry);
        auditService.record(owner, AuditService.SECRET_UPDATED, null,
                "VaultEntry", entryId.toString(), null);
        log.info("Vault entry updated: user={}, entryId={}", owner.getId(), entryId);
        return new UpdatedEntry(saved, entry.getVersion(), name, site, login);
    }

    /** Результат обновления: сущность + версия ДО обновления (для ответа API). */
    public record UpdatedEntry(VaultEntry entry, Long previousVersion,
                               String name, String site, String login) {
    }

    /**
     * Удаляет запись владельца. Idempotent-поведение не используется:
     * удаление чужой/несуществующей записи — тот же нейтральный 404.
     *
     * @throws VaultException NOT_FOUND, если записи нет или она чужая
     */
    @Transactional
    public void delete(User owner, UUID entryId) {
        VaultEntry entry = findOwnedOrThrow(owner, entryId);
        vaultEntryRepository.delete(entry);
        vaultEntryRepository.flush();
        auditService.record(owner, AuditService.SECRET_DELETED, null,
                "VaultEntry", entryId.toString(), null);
        log.info("Vault entry deleted: user={}, entryId={}", owner.getId(), entryId);
    }

    // -- internals -----------------------------------------------------------

    /** Owner-scoped поиск: чужая запись неотличима от отсутствующей. */
    private VaultEntry findOwnedOrThrow(User owner, UUID entryId) {
        return vaultEntryRepository.findByIdAndUser_Id(entryId, owner.getId())
                .orElseThrow(() -> new VaultException(VaultException.Reason.NOT_FOUND));
    }

    /** Разворачивает DEK владельца; ошибки не раскрывают деталей. */
    private SecretKey unwrapDek(User owner) {
        return cryptoService.unwrapDek(new com.example.safeaccounts.crypto.WrappedDek(
                owner.getDekWrapped(), owner.getDekIv(), owner.getDekKekId()));
    }

    /** Расшифровывает метаданные записи; пароль — только по reveal. */
    private DecryptedEntry decryptEntry(VaultEntry entry, SecretKey dek, boolean reveal) {
        try {
            String password = reveal ? cryptoService.decrypt(entry.getPasswordEnc(), dek) : null;
            return new DecryptedEntry(
                    cryptoService.decrypt(entry.getNameEnc(), dek),
                    cryptoService.decrypt(entry.getSiteEnc(), dek),
                    cryptoService.decrypt(entry.getLoginEnc(), dek),
                    password,
                    entry.getNotesEnc() == null ? null : cryptoService.decrypt(entry.getNotesEnc(), dek),
                    entry.getCreatedAt(),
                    entry.getUpdatedAt());
        } catch (CryptoException e) {
            // Нейтрально наружу: детали (какое поле, причина) не раскрываются.
            throw new VaultException(VaultException.Reason.DECRYPTION_FAILED);
        }
    }

    /** Расшифровывает только name/site/login для элемента списка; пароль не трогаем. */
    private ListItem toListItem(User owner, VaultEntry entry) {
        SecretKey dek = unwrapDek(owner);
        try {
            return new ListItem(
                    entry.getId(),
                    cryptoService.decrypt(entry.getNameEnc(), dek),
                    cryptoService.decrypt(entry.getSiteEnc(), dek),
                    cryptoService.decrypt(entry.getLoginEnc(), dek),
                    entry.getCreatedAt(),
                    entry.getUpdatedAt(),
                    entry.getVersion());
        } catch (CryptoException e) {
            throw new VaultException(VaultException.Reason.DECRYPTION_FAILED);
        }
    }

    /** Элемент списка: без пароля и notes (Task-05). */
    public record ListItem(UUID id, String name, String site, String login,
                           Instant createdAt, Instant updatedAt, Long version) {
    }
}