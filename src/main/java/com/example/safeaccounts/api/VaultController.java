package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.VaultService;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * CRUD API записей сейфа (Task-05). Контроллер тонкий:
 * вся бизнес-логика и шифрование — в {@link VaultService}.
 * <p>
 * Безопасность: пароли в списках не возвращаются; расшифрованный пароль
 * отдается только при явном {@code ?reveal=true} и только владельцу.
 * Пароли и шифротексты никогда не логируются.
 */
@RestController
@RequestMapping("/api/vault")
public class VaultController {

    private final VaultService vaultService;

    public VaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

    /** Список записей текущего пользователя (без паролей и notes). */
    @GetMapping
    public PageResponse<VaultEntryListItemResponse> list(
            @AuthenticationPrincipal AuthUser principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<VaultService.ListItem> items = vaultService.list(currentUser(principal), page, size);
        return new PageResponse<>(
                items.getNumber(),
                items.getSize(),
                items.getTotalElements(),
                items.getTotalPages(),
                items.getContent().stream()
                        .map(i -> new VaultEntryListItemResponse(
                                i.id(), i.name(), i.site(), i.login(),
                                i.createdAt(), i.updatedAt(),
                                i.version() == null ? 0L : i.version()))
                        .toList());
    }

    /** Создание записи: все чувствительные поля шифруются DEK владельца. */
    @PostMapping
    public ResponseEntity<VaultEntryDetailResponse> create(
            @AuthenticationPrincipal AuthUser principal,
            @Valid @RequestBody VaultEntryCreateRequest request) {
        VaultService.CreatedEntry created = vaultService.create(
                currentUser(principal),
                request.name(),
                request.site(), request.login(), request.password(), request.notes());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(VaultEntryDetailResponse.withoutPassword(
                        created.entry().getId(),
                        created.name(),
                        created.site(),
                        created.login(),
                        request.notes(),
                        created.entry().getCreatedAt(),
                        created.entry().getUpdatedAt(),
                        0L));
    }

    /**
     * Детальный просмотр записи владельца. Пароль возвращается только при
     * {@code ?reveal=true}; факт reveal фиксируется в аудите.
     */
    @GetMapping("/{id}")
    public VaultEntryDetailResponse get(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @RequestParam(defaultValue = "false") boolean reveal) {
        VaultService.DecryptedEntry entry = vaultService.get(currentUser(principal), id, reveal);
        return new VaultEntryDetailResponse(
                id,
                entry.name(),
                entry.site(),
                entry.login(),
                entry.password(),
                entry.notes(),
                entry.createdAt() != null ? entry.createdAt() : null,
                entry.updatedAt(),
                0L);
    }

    /** Обновление записи владельца: поля перешифровываются новыми IV. */
    @PutMapping("/{id}")
    public VaultEntryDetailResponse update(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @Valid @RequestBody VaultEntryUpdateRequest request) {
        VaultService.UpdatedEntry updated = vaultService.update(
                currentUser(principal),
                id,
                request.name(),
                request.site(), request.login(), request.password(), request.notes());
        return new VaultEntryDetailResponse(
                id,
                updated.name(),
                updated.site(),
                updated.login(),
                null,
                request.notes(),
                updated.entry().getCreatedAt(),
                updated.entry().getUpdatedAt(),
                updated.entry().getVersion() == null ? 0L : updated.entry().getVersion());
    }

    /** Удаление записи владельца. Чужая запись неотличима от несуществующей (404). */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id) {
        vaultService.delete(currentUser(principal), id);
        return ResponseEntity.noContent().build();
    }

    /** Пользователь из Bearer-principal (User — LAZY, данные уже зафиксированы). */
    private static User currentUser(AuthUser principal) {
        return principal.user();
    }

    /** Простой пагинированный ответ без зависимости от Spring Data в контракте API. */
    public record PageResponse<T>(
            int page,
            int size,
            long totalElements,
            int totalPages,
            List<T> content) {
    }
}