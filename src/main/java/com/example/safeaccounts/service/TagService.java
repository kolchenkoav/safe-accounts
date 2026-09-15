package com.example.safeaccounts.service;

import com.example.safeaccounts.audit.AuditService;
import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.domain.VaultEntry;
import com.example.safeaccounts.repository.TagRepository;
import com.example.safeaccounts.repository.VaultEntryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Управление тегами (Task-08, Фаза 5). Все операции owner-scoped:
 * обычный пользователь видит/правит только свои теги; админ
 * маршруты {@code /api/admin/users/{id}/...} не предусмотрены —
 * admin работает с записями пользователя через {@code /api/admin/users/{id}/vault/...}.
 * <p>
 * Правила безопасности (AGENTS.md / план 5):
 * <ul>
 *   <li>имя тега: 1..64 символа, regex {@code ^[a-zA-Z0-9 _\\-.]+$}, trim перед сохранением;</li>
 *   <li>case-insensitive уникальность в пределах пользователя
 *       (поле {@code name_lower} + UNIQUE(user_id, name_lower));</li>
 *   <li>удаление запрещено, если на тег ссылается хотя бы одна запись
 *       (план, раздел 5 п.1) — {@link TagStillReferencedException} → 409;</li>
 *   <li>аудит (TAG_CREATED/RENAMED/DELETED/ENTRY_TAGS_REPLACED) не содержит
 *       секретов: тег-имена не секрет, но идентификаторы пользователей/записей
 *       могут присутствовать как objectId;</li>
 *   <li>все операции — в транзакции, чтение — readOnly.</li>
 * </ul>
 */
@Service
public class TagService {

    static final Logger log = LoggerFactory.getLogger(TagService.class);

    /** Допустимый regex для имени тега. */
    public static final String TAG_NAME_REGEX = "^[a-zA-Z0-9 _\\-.]+$";

    /** Границы длины имени тега (синхронизированы со схемой: CHECK 1..64). */
    static final int TAG_NAME_MAX_LEN = 64;

    private final TagRepository tagRepository;
    private final VaultEntryRepository vaultEntryRepository;
    private final TagInsertHelper insertHelper;
    private final AuditService auditService;
    private final Clock clock;

    public TagService(TagRepository tagRepository,
                      VaultEntryRepository vaultEntryRepository,
                      TagInsertHelper insertHelper,
                      AuditService auditService,
                      Clock clock) {
        this.tagRepository = tagRepository;
        this.vaultEntryRepository = vaultEntryRepository;
        this.insertHelper = insertHelper;
        this.auditService = auditService;
        this.clock = clock;
    }

    // -- list / find ----------------------------------------------------------

    /** Все теги пользователя (отсортированы по name_lower — стабильно для UI). */
    @Transactional(readOnly = true)
    public List<Tag> listUserTags(User actor) {
        return tagRepository.findAllByUser_Id(actor.getId());
    }

    /** Поиск тега пользователя с owner-check (тег принадлежит actor). */
    @Transactional(readOnly = true)
    public Optional<Tag> findTag(User actor, UUID tagId) {
        if (tagId == null) {
            return Optional.empty();
        }
        return tagRepository.findById(tagId)
                .filter(t -> isOwner(t, actor));
    }

    // -- create / rename ------------------------------------------------------

    /**
     * Создаёт тег. Имя валидируется (regex, длина, trim); если у пользователя
     * уже есть тег с таким {@code nameLower} — {@link TagAlreadyExistsException}.
     */
    @Transactional
    public Tag createTag(User actor, String rawName) {
        String name = normalizeAndValidateName(rawName);
        String nameLower = name.toLowerCase(Locale.ROOT);
        tagRepository.findByUser_IdAndNameLower(actor.getId(), nameLower)
                .ifPresent(existing -> {
                    throw new TagAlreadyExistsException("Tag already exists");
                });

        Tag tag = Tag.create(UUID.randomUUID(), actor, name, clock.instant());
        Tag saved;
        try {
            // INSERT в отдельной транзакции (REQUIRES_NEW): гонка UNIQUE(user_id,
            // name_lower) не переводит текущую tx в aborted (PG 25P02) —
            // retry-find ниже выполняется в здоровой транзакции.
            saved = insertHelper.insert(tag);
        } catch (DataIntegrityViolationException e) {
            // Гонка параллельных созданий: параллельный INSERT уже выиграл.
            // Повторный find в ЗДОРОВОЙ внешней tx подтверждает дубль имени.
            if (tagRepository.findByUser_IdAndNameLower(actor.getId(), nameLower).isPresent()) {
                throw new TagAlreadyExistsException("Tag already exists");
            }
            throw e;
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("tagId", saved.getId().toString());
        // Имя тега — не секрет (см. AGENTS.md).
        details.put("name", saved.getName());
        auditService.record(actor, AuditService.TAG_CREATED, null,
                "Tag", saved.getId().toString(), details);
        log.info("Tag created: actor={}, tagId={}", actor.getUsername(), saved.getId());

        return saved;
    }

    /**
     * Переименовывает тег. Если новый {@code nameLower} совпадает с другим
     * тегом пользователя — {@link TagAlreadyExistsException}.
     */
    @Transactional
    public Tag renameTag(User actor, UUID tagId, String rawName) {
        Tag tag = requireOwnedTag(actor, tagId);
        String name = normalizeAndValidateName(rawName);
        String nameLower = name.toLowerCase(Locale.ROOT);

        if (!tag.getNameLower().equals(nameLower)) {
            tagRepository.findByUser_IdAndNameLower(actor.getId(), nameLower)
                    .filter(other -> !other.getId().equals(tag.getId()))
                    .ifPresent(other -> {
                        throw new TagAlreadyExistsException("Tag already exists");
                    });
        }

        String oldName = tag.getName();
        tag.rename(name);
        Tag saved = tagRepository.save(tag);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("tagId", saved.getId().toString());
        details.put("oldName", oldName);
        details.put("newName", saved.getName());
        auditService.record(actor, AuditService.TAG_RENAMED, null,
                "Tag", saved.getId().toString(), details);
        log.info("Tag renamed: actor={}, tagId={}", actor.getUsername(), saved.getId());

        return saved;
    }

    // -- delete ---------------------------------------------------------------

    /**
     * Удаляет тег. Если на тег ссылается хотя бы одна запись —
     * {@link TagStillReferencedException} → 409. Чтобы удалить занятый тег,
     * пользователь сначала снимает его со всех записей через PUT
     * {@code /api/vault/{id}/tags} или DELETE {@code /api/vault/{id}/tags/{tagId}}.
     */
    @Transactional
    public void deleteTag(User actor, UUID tagId) {
        Tag tag = requireOwnedTag(actor, tagId);
        if (vaultEntryRepository.existsByTags_Id(tag.getId())) {
            throw new TagStillReferencedException("Tag is still referenced by vault entries");
        }
        tagRepository.delete(tag);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("tagId", tag.getId().toString());
        details.put("name", tag.getName());
        auditService.record(actor, AuditService.TAG_DELETED, null,
                "Tag", tag.getId().toString(), details);
        log.info("Tag deleted: actor={}, tagId={}", actor.getUsername(), tag.getId());
    }

    // -- entry tags -----------------------------------------------------------

    /** Теги записи (owner-check записи). Возвращаемая коллекция отвязана от lazy-сессии. */
    @Transactional(readOnly = true)
    public Set<Tag> getEntryTags(User actor, UUID entryId) {
        VaultEntry entry = requireOwnedEntry(actor, entryId);
        return new LinkedHashSet<>(entry.getTags());
    }

    /**
     * Replace-all тегов записи. Для каждого имени из {@code tagNames}
     * либо находится существующий тег пользователя, либо создаётся новый.
     * Пустой список — снимает все теги с записи.
     */
    @Transactional
    public Set<Tag> replaceEntryTags(User actor, UUID entryId, List<String> tagNames) {
        VaultEntry entry = requireOwnedEntry(actor, entryId);

        // Дедупликация по nameLower внутри запроса.
        Set<String> normalized = new LinkedHashSet<>();
        List<String> validated = new ArrayList<>();
        if (tagNames != null) {
            for (String raw : tagNames) {
                String name = normalizeAndValidateName(raw);
                String lower = name.toLowerCase(Locale.ROOT);
                if (normalized.add(lower)) {
                    validated.add(name);
                }
            }
        }

        Set<Tag> resolved = new LinkedHashSet<>();
        for (String name : validated) {
            // Тот же race-safe путь создания, что и в attachOrCreate:
            // INSERT через TagInsertHelper (REQUIRES_NEW), гонка UNIQUE
            // разрешается повторным find в здоровой транзакции.
            resolved.add(findOrCreateTag(actor, name, "ENTRY_TAGS_REPLACED"));
        }

        entry.getTags().clear();
        entry.getTags().addAll(resolved);
        vaultEntryRepository.saveAndFlush(entry);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("entryId", entryId.toString());
        // Аудит: только количество и нечувствительные метаданные.
        // AGENTS.md: «в detailsJson запрещено записывать списки тегов целиком».
        details.put("tagCount", resolved.size());
        auditService.record(actor, AuditService.ENTRY_TAGS_REPLACED, null,
                "VaultEntry", entryId.toString(), details);
        log.info("Entry tags replaced: actor={}, entryId={}, tagCount={}",
                actor.getUsername(), entryId, resolved.size());

        return resolved;
    }

    // -- web: покомпонентные операции над тегами записи (Фаза 2) -------------

    /**
     * Привязывает тег к записи по имени: находит существующий тег пользователя
     * по {@code name_lower}, иначе создаёт новый, — и добавляет его к записи.
     * Повторная привязка уже привязанного тега — no-op (без аудита).
     *
     * @throws IllegalArgumentException если имя не проходит валидацию
     * @throws VaultException           NOT_FOUND, если записи нет или она чужая
     */
    @Transactional
    public Tag attachOrCreate(User actor, UUID entryId, String rawName) {
        VaultEntry entry = requireOwnedEntry(actor, entryId);
        Tag tag = findOrCreateTag(actor, rawName, "ENTRY_TAG_ATTACH");

        if (entry.getTags().add(tag)) {
            vaultEntryRepository.saveAndFlush(entry);
            recordEntryTagsChanged(actor, entryId, entry.getTags().size());
        }
        return tag;
    }

    /**
     * Находит тег пользователя по имени либо создаёт новый.
     * <p>
     * Гонка параллельных созданий: INSERT выполняется в ОТДЕЛЬНОЙ транзакции
     * ({@link TagInsertHelper}, REQUIRES_NEW). При нарушении UNIQUE(user_id,
     * name_lower) внутренняя tx откатывается, внешняя остаётся здоровой —
     * повторный find ниже работает в рабочей транзакции. Ранее retry-find
     * выполнялся в aborted-транзакции PG (25P02) → JpaSystemException → 500
     * у проигравшего гонку.
     * <p>
     * Осознанный трейд-офф: тег, созданный в REQUIRES_NEW, закоммитится даже
     * при откате внешней транзакции (возможен «осиротевший» тег без привязки —
     * безвреден, удаляется через /web/tags).
     *
     * @throws IllegalArgumentException если имя не проходит валидацию
     */
    private Tag findOrCreateTag(User actor, String rawName, String via) {
        String name = normalizeAndValidateName(rawName);
        String nameLower = name.toLowerCase(Locale.ROOT);
        Optional<Tag> existing = tagRepository.findByUser_IdAndNameLower(actor.getId(), nameLower);
        if (existing.isPresent()) {
            return existing.get();
        }
        Tag created;
        try {
            created = insertHelper.insert(
                    Tag.create(UUID.randomUUID(), actor, name, clock.instant()));
        } catch (DataIntegrityViolationException e) {
            // Гонка: параллельный INSERT выиграл — переиспользуем его тег.
            Tag winner = tagRepository.findByUser_IdAndNameLower(actor.getId(), nameLower)
                    .orElseThrow(() -> e);
            log.info("Tag race resolved: actor={}, tagId={} (parallel create won)",
                    actor.getUsername(), winner.getId());
            return winner;
        }
        Map<String, Object> createDetails = new LinkedHashMap<>();
        createDetails.put("actor", actor.getUsername());
        createDetails.put("tagId", created.getId().toString());
        // Имя тега — не секрет (см. AGENTS.md).
        createDetails.put("name", created.getName());
        createDetails.put("via", via);
        auditService.record(actor, AuditService.TAG_CREATED, null,
                "Tag", created.getId().toString(), createDetails);
        log.info("Tag created: actor={}, tagId={}", actor.getUsername(), created.getId());
        return created;
    }

    /**
     * Снимает тег с записи. Нетопотентно: тег, не привязанный к записи,
     * ничего не меняет и аудита не пишет.
     *
     * @throws VaultException NOT_FOUND, если записи нет или она чужая
     */
    @Transactional
    public void detach(User actor, UUID entryId, UUID tagId) {
        VaultEntry entry = requireOwnedEntry(actor, entryId);
        if (tagId == null) {
            return;
        }
        boolean removed = entry.getTags().removeIf(t -> t.getId().equals(tagId));
        if (removed) {
            vaultEntryRepository.saveAndFlush(entry);
            recordEntryTagsChanged(actor, entryId, entry.getTags().size());
        }
    }

    /**
     * Теги пользователя с количеством записей (страница /web/tags).
     * Порядок — как в {@link #listUserTags(User)} (name_lower).
     */
    @Transactional(readOnly = true)
    public List<TagWithCount> listWithEntryCounts(User actor) {
        Map<UUID, Long> counts = tagRepository.countEntriesPerTagByUserId(actor.getId())
                .stream()
                .collect(Collectors.toMap(
                        row -> (UUID) row[0],
                        row -> (Long) row[1]));
        return tagRepository.findAllByUser_Id(actor.getId()).stream()
                .map(t -> new TagWithCount(t.getId(), t.getName(),
                        counts.getOrDefault(t.getId(), 0L)))
                .toList();
    }

    /** Количество записей, использующих тег пользователя (для UI-сообщения). */
    @Transactional(readOnly = true)
    public long countEntriesUsingTag(User actor, UUID tagId) {
        return findTag(actor, tagId)
                .map(tag -> vaultEntryRepository.countByTags_Id(tag.getId()))
                .orElse(0L);
    }

    /** Тег пользователя + количество записей (для страницы /web/tags). */
    public record TagWithCount(UUID id, String name, long entryCount) {
    }

    /**
     * Аудит изменения набора тегов записи: только счётчик, без списка имён
     * (AGENTS.md: в detailsJson — без перечисления тегов).
     */
    private void recordEntryTagsChanged(User actor, UUID entryId, int tagCount) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("actor", actor.getUsername());
        details.put("entryId", entryId.toString());
        details.put("tagCount", tagCount);
        auditService.record(actor, AuditService.ENTRY_TAGS_REPLACED, null,
                "VaultEntry", entryId.toString(), details);
        log.info("Entry tags changed: actor={}, entryId={}, tagCount={}",
                actor.getUsername(), entryId, tagCount);
    }

    // -- helpers --------------------------------------------------------------

    /** Нормализация и валидация имени тега. */
    static String normalizeAndValidateName(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("tag name is blank");
        }
        String name = raw.trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("tag name is blank");
        }
        if (name.length() > TAG_NAME_MAX_LEN) {
            throw new IllegalArgumentException("tag name too long");
        }
        if (!name.matches(TAG_NAME_REGEX)) {
            throw new IllegalArgumentException(
                    "tag name must match " + TAG_NAME_REGEX);
        }
        return name;
    }

    private Tag requireOwnedTag(User actor, UUID tagId) {
        if (tagId == null) {
            throw new IllegalArgumentException("tagId is null");
        }
        Tag tag = tagRepository.findById(tagId).orElse(null);
        if (tag == null || !isOwner(tag, actor)) {
            // Чужой/несуществующий тег → единый нейтральный 404.
            throw new VaultException(VaultException.Reason.NOT_FOUND);
        }
        return tag;
    }

    private VaultEntry requireOwnedEntry(User actor, UUID entryId) {
        if (entryId == null) {
            throw new IllegalArgumentException("entryId is null");
        }
        return vaultEntryRepository.findByIdAndUser_Id(entryId, actor.getId())
                .orElseThrow(() -> new VaultException(VaultException.Reason.NOT_FOUND));
    }

    private static boolean isOwner(Tag tag, User actor) {
        return tag.getUser() != null
                && tag.getUser().getId() != null
                && tag.getUser().getId().equals(actor.getId());
    }
}
