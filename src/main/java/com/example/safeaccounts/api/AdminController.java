package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.AdminService;
import com.example.safeaccounts.service.KeyRotationException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Административный API (Task-06): управление пользователями, просмотр аудита,
 * ротация KEK (rewrap пользовательских DEK).
 * <p>
 * Безопасность: все эндпоинты закрыты ролью ADMIN — на уровне SecurityConfig
 * ({@code /api/admin/**} requires ROLE_ADMIN), через {@code @PreAuthorize} и
 * повторной проверкой в {@link AdminService} (defense in depth).
 * В ответах и аудите нет паролей, токенов и материала ключей.
 */
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    // -- пользователи ---------------------------------------------------------

    /** Список пользователей (пагинация, без хэшей паролей и wrapped DEK). */
    @GetMapping("/users")
    public PageResponse<AdminUserResponse> listUsers(
            @AuthenticationPrincipal AuthUser principal,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<User> users = adminService.listUsers(page, size);
        return new PageResponse<>(
                users.getNumber(),
                users.getSize(),
                users.getTotalElements(),
                users.getTotalPages(),
                users.getContent().stream().map(AdminController::toUserResponse).toList());
    }

    /** Создание пользователя администратором (USER_CREATED_BY_ADMIN в аудите). */
    @PostMapping("/users")
    public ResponseEntity<AdminUserResponse> createUser(
            @AuthenticationPrincipal AuthUser principal,
            @Valid @RequestBody AdminCreateUserRequest request) {
        User created = adminService.createUser(
                request.username(), request.password(), request.role(), principal.user());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(toUserResponse(created));
    }

    /** Включение учетной записи. */
    @PostMapping("/users/{id}/enable")
    public AdminUserResponse enableUser(@AuthenticationPrincipal AuthUser principal,
                                        @PathVariable UUID id) {
        return toUserResponse(adminService.enableUser(id, principal.user()));
    }

    /** Отключение учетной записи (блокирует вход, USER_DISABLED в аудите). */
    @PostMapping("/users/{id}/disable")
    public AdminUserResponse disableUser(@AuthenticationPrincipal AuthUser principal,
                                         @PathVariable UUID id) {
        return toUserResponse(adminService.disableUser(id, principal.user()));
    }

    /**
     * Сброс пароля администратором: новое значение пароля + отзыв всех
     * активных токенов пользователя (Task-06).
     */
    @PostMapping("/users/{id}/reset-password")
    public AdminResetPasswordResponse resetPassword(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @Valid @RequestBody AdminResetPasswordRequest request) {
        int revoked = adminService.resetPassword(id, request.newPassword(), principal.user());
        return new AdminResetPasswordResponse(revoked);
    }

    // -- аудит ----------------------------------------------------------------

    /**
     * Просмотр аудита: пагинация + фильтры по типу события, пользователю и периоду.
     * Секреты не раскрываются.
     */
    @GetMapping("/audit")
    public PageResponse<AdminAuditEventResponse> audit(
            @RequestParam(required = false) String type,
            @RequestParam(required = false) UUID userId,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<AdminService.AuditView> events =
                adminService.listAudit(type, userId, from, to, page, size);
        return new PageResponse<>(
                events.getNumber(),
                events.getSize(),
                events.getTotalElements(),
                events.getTotalPages(),
                events.getContent().stream()
                        .map(v -> new AdminAuditEventResponse(
                                v.id(), v.userId(), v.tokenId(), v.type(),
                                v.objectType(), v.objectId(),
                                v.ipAddress(), v.userAgent(), v.detailsJson(),
                                v.createdAt()))
                        .toList());
    }

    // -- ротация ключей -------------------------------------------------------

    /**
     * Перепаковка DEK всех пользователей новым активным KEK. Идемпотентно:
     * пользователи на активном ключе пропускаются.
     */
    @PostMapping("/crypto/rewrap-deks")
    public AdminRewrapResponse rewrapDeks(@AuthenticationPrincipal AuthUser principal) {
        AdminService.RewrapResult result = adminService.rewrapDeks(principal.user());
        return new AdminRewrapResponse(result.rewrappedUsers(), result.activeKekId());
    }

    /** Ошибка ротации: понятный RFC 7807 ответ без деталей материала ключей. */
    @ExceptionHandler(KeyRotationException.class)
    public ResponseEntity<ProblemDetail> handleKeyRotation(KeyRotationException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        "Key rotation failed: some DEKs could not be rewrapped"));
    }

    // -- helpers --------------------------------------------------------------

    private static AdminUserResponse toUserResponse(User user) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                user.isEnabled(),
                user.getCreatedAt(),
                user.getUpdatedAt());
    }

    /** Простой пагинированный ответ (как в VaultController). */
    public record PageResponse<T>(
            int page,
            int size,
            long totalElements,
            int totalPages,
            List<T> content) {
    }

    /** Результат сброса пароля: только количество отозванных токенов. */
    public record AdminResetPasswordResponse(int revokedTokens) {
    }

    /** Результат ротации: количество перепакованных DEK + нечувствительный key id. */
    public record AdminRewrapResponse(int rewrappedUsers, String activeKekId) {
    }
}
