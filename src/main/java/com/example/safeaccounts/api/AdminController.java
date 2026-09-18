package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.AdminService;
import com.example.safeaccounts.service.AuthServiceException;
import com.example.safeaccounts.service.KeyRotationException;
import com.example.safeaccounts.service.VaultExportImportService;
import com.example.safeaccounts.service.VaultScanService;
import com.example.safeaccounts.service.csv.ConflictStrategy;
import com.example.safeaccounts.service.csv.CsvFilenames;
import com.example.safeaccounts.service.csv.ExportPayload;
import com.example.safeaccounts.service.csv.ImportReport;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
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
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
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
    private final VaultExportImportService exportImportService;
    private final VaultScanService scanService;

    public AdminController(AdminService adminService,
                           VaultExportImportService exportImportService,
                           VaultScanService scanService) {
        this.adminService = adminService;
        this.exportImportService = exportImportService;
        this.scanService = scanService;
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

    // -- export / import пользовательского сейфа (Task-07 / Task-08) ---------

    /**
     * Экспорт сейфа указанного пользователя в CSV (ADMIN-only).
     * <p>
     * Безопасность: ROLE_ADMIN (проверка на классе через {@code @PreAuthorize} +
     * URL-правило SecurityConfig). Пользователь с {@code id} обязан существовать,
     * иначе — 404 RFC 7807 (не раскрываем, существует ли он в принципе, но это
     * требование задачи). Заголовок {@code X-Vault-Export-Warning} обязателен.
     */
    @GetMapping("/users/{id}/vault/export")
    public ResponseEntity<byte[]> exportUserVault(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @RequestParam(defaultValue = "false") boolean bom) {
        User actor = currentUser(principal);
        User target = requireUserOrNotFound(id);

        ExportPayload payload = exportImportService.export(actor, target, bom);

        String filename = CsvFilenames.forTargetUser(target.getUsername(), Instant.now());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("text/csv; charset=utf-8"));
        headers.set(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"");
        headers.add(VaultController.EXPORT_WARNING_HEADER, VaultController.EXPORT_WARNING_VALUE);
        headers.setContentLength(payload.csv().length);
        // Plaintext-экспорт не должен кэшироваться (паритет с web, Фаза 5).
        headers.setCacheControl("no-store");
        return new ResponseEntity<>(payload.csv(), headers, HttpStatus.OK);
    }

    /**
     * Импорт CSV в сейф указанного пользователя (ADMIN-only).
     * <p>
     * multipart: {@code file} (CSV), {@code conflictStrategy} ({@code skip|upsert}).
     * Query: {@code ?dryRun=true|false}, {@code ?failFast=true|false}.
     * Если пользователь с {@code id} не найден — 404 RFC 7807.
     */
    @PostMapping(path = "/users/{id}/vault/import",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<ImportReport> importUserVault(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id,
            @RequestPart(VaultController.IMPORT_FILE_PART) MultipartFile file,
            @RequestParam(defaultValue = "skip") String conflictStrategy,
            @RequestParam(defaultValue = "false") boolean dryRun,
            @RequestParam(defaultValue = "false") boolean failFast) throws IOException {
        User actor = currentUser(principal);
        User target = requireUserOrNotFound(id);
        ConflictStrategy strategy = VaultController.parseConflictStrategy(conflictStrategy);
        if (file == null || file.isEmpty()) {
            throw new InvalidCsvException("CSV file is empty");
        }
        byte[] csvBytes = file.getBytes();
        ImportReport report = exportImportService.importFromCsv(
                actor, target, csvBytes, strategy, dryRun, failFast);
        return ResponseEntity.ok(report);
    }

    // -- helpers --------------------------------------------------------------

    /** Пользователь из Bearer-principal (User — LAZY, данные уже зафиксированы). */
    private static User currentUser(AuthUser principal) {
        return principal.user();
    }

    /**
     * Возвращает пользователя по id; если не найден — бросает
     * {@link AuthServiceException}(USER_NOT_FOUND), что маппится в 404.
     * Делегирует в {@link AdminService#requireUserById} (P2: контроллеры
     * не зависят от repository).
     */
    private User requireUserOrNotFound(UUID id) {
        return adminService.requireUserById(id);
    }

    /** Ошибка ротации: понятный RFC 7807 ответ без деталей материала ключей. */
    @ExceptionHandler(KeyRotationException.class)
    public ResponseEntity<ProblemDetail> handleKeyRotation(KeyRotationException e) {
        HttpStatus status = HttpStatus.CONFLICT;
        return ResponseEntity.status(status)
                .body(ProblemDetail.forStatusAndDetail(status,
                        "Key rotation failed: some DEKs could not be rewrapped"));
    }

    /** Сканер слабых паролей в сейфе пользователя (G2). actor — администратор. */
    @PostMapping("/users/{id}/vault/scan")
    public VaultScanService.ScanReport scanUserVault(
            @AuthenticationPrincipal AuthUser principal,
            @PathVariable UUID id) {
        User target = requireUserOrNotFound(id);
        return scanService.scan(currentUser(principal), target);
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

    /** Результат сброса пароля: только количество отозванных токенов. */
    public record AdminResetPasswordResponse(int revokedTokens) {
    }

    /** Результат ротации: количество перепакованных DEK + нечувствительный key id. */
    public record AdminRewrapResponse(int rewrappedUsers, String activeKekId) {
    }
}
