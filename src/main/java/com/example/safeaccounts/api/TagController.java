package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.TagService;
import com.example.safeaccounts.service.VaultException;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Управление тегами (Task-08, Фаза 5).
 * <p>
 * Контроллер тонкий: вся бизнес-логика и owner-check — в {@link TagService}.
 * <p>
 * Безопасность:
 * <ul>
 *   <li>все эндпоинты закрыты аутентификацией (Bearer, см. SecurityConfig);</li>
 *   <li>owner-check — в сервисе: пользователь видит/правит только свои теги;</li>
 *   <li>чужие/несуществующие теги/записи возвращают нейтральный 404
 *       (нет утечки существования);</li>
 *   <li>теги хранятся в открытом виде (по решению пользователя, план 2.2),
 *       имена тегов не считаются секретами.</li>
 * </ul>
 */
@RestController
@RequestMapping("/api")
public class TagController {

    private final TagService tagService;

    public TagController(TagService tagService) {
        this.tagService = tagService;
    }

    // -- теги пользователя (/api/tags) ----------------------------------------

    /** Список тегов текущего пользователя. */
    @GetMapping("/tags")
    public List<TagResponse> listTags(@AuthenticationPrincipal AuthUser principal) {
        return tagService.listUserTags(currentUser(principal)).stream()
                .map(TagController::toResponse)
                .toList();
    }

    /** Создание тега (201 Created). */
    @PostMapping("/tags")
    public ResponseEntity<TagResponse> createTag(
            @AuthenticationPrincipal AuthUser principal,
            @Valid @RequestBody TagCreateRequest request) {
        Tag created = tagService.createTag(currentUser(principal), request.name());
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(created));
    }

    /** Переименование тега. */
    @PatchMapping("/tags/{id}")
    public TagResponse renameTag(@AuthenticationPrincipal AuthUser principal,
                                 @PathVariable UUID id,
                                 @Valid @RequestBody TagRenameRequest request) {
        return toResponse(tagService.renameTag(currentUser(principal), id, request.name()));
    }

    /**
     * Удаление тега. Чужие/несуществующие — 404. Если тег ещё привязан
     * к записям — 409 (маппится в {@code ApiExceptionHandler}).
     */
    @DeleteMapping("/tags/{id}")
    public ResponseEntity<Void> deleteTag(@AuthenticationPrincipal AuthUser principal,
                                          @PathVariable UUID id) {
        tagService.deleteTag(currentUser(principal), id);
        return ResponseEntity.noContent().build();
    }

    // -- теги записи (/api/vault/{id}/tags) -----------------------------------

    /** Теги указанной записи владельца. */
    @GetMapping("/vault/{id}/tags")
    public List<TagResponse> getEntryTags(@AuthenticationPrincipal AuthUser principal,
                                          @PathVariable UUID id) {
        Set<Tag> tags = tagService.getEntryTags(currentUser(principal), id);
        return tags.stream().map(TagController::toResponse).toList();
    }

    /** Replace-all тегов записи. Пустой список снимает все теги. */
    @PutMapping("/vault/{id}/tags")
    public List<TagResponse> replaceEntryTags(@AuthenticationPrincipal AuthUser principal,
                                              @PathVariable UUID id,
                                              @Valid @RequestBody TagReplaceRequest request) {
        Set<Tag> tags = tagService.replaceEntryTags(
                currentUser(principal), id, request.tags());
        return tags.stream().map(TagController::toResponse).toList();
    }

    /** Снять один тег с записи. */
    @DeleteMapping("/vault/{id}/tags/{tagId}")
    public ResponseEntity<Void> removeEntryTag(@AuthenticationPrincipal AuthUser principal,
                                               @PathVariable UUID id,
                                               @PathVariable UUID tagId) {
        User actor = currentUser(principal);
        // Убеждаемся, что запись существует и принадлежит пользователю
        // (иначе — 404). Этот вызов бросит VaultException(NOT_FOUND) при чужой записи.
        Set<Tag> current = tagService.getEntryTags(actor, id);
        List<String> remaining = current.stream()
                .filter(t -> !t.getId().equals(tagId))
                .map(Tag::getName)
                .toList();
        tagService.replaceEntryTags(actor, id, remaining);
        return ResponseEntity.noContent().build();
    }

    // -- helpers --------------------------------------------------------------

    private static User currentUser(AuthUser principal) {
        return principal.user();
    }

    private static TagResponse toResponse(Tag tag) {
        return new TagResponse(tag.getId(), tag.getName(), tag.getCreatedAt());
    }
}
