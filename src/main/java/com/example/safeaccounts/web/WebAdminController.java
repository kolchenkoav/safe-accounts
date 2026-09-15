package com.example.safeaccounts.web;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.repository.UserRepository;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.AdminService;
import com.example.safeaccounts.service.AdminServiceException;
import com.example.safeaccounts.service.AuthServiceException;
import com.example.safeaccounts.service.KeyRotationException;
import com.example.safeaccounts.service.VaultExportImportService;
import com.example.safeaccounts.service.csv.ConflictStrategy;
import com.example.safeaccounts.service.csv.ExportPayload;
import com.example.safeaccounts.service.csv.ImportReport;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import com.example.safeaccounts.service.csv.PayloadTooLargeException;
import org.springframework.data.domain.Page;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.UUID;

/**
 * Веб-раздел администратора (Task-12): пользователи, аудит, ротация ключей.
 * <p>
 * Безопасность:
 * <ul>
 *   <li>доступ к {@code /web/admin/**} — только ROLE_ADMIN: URL-правило
 *       в SecurityConfig (веб-цепочка) + повторная проверка requireAdmin
 *       внутри {@link AdminService} (defense in depth);</li>
 *   <li>все мутирующие действия — POST-формы с CSRF-токеном;</li>
 *   <li>контроллер тонкий: бизнес-правила и аудит — в AdminService;</li>
 *   <li>пароли никогда не возвращаются в шаблоны и не логируются
 *       (поля reset-password/create-user всегда пустые при рендере);</li>
 *   <li>ошибки сервиса показываются нейтральными flash-сообщениями,
 *       без стектрейсов и внутренних деталей.</li>
 * </ul>
 */
@Controller
public class WebAdminController {

    /** Размер страницы (список пользователей, аудит) — как в REST API. */
    private static final int PAGE_SIZE = 20;

    /** Нейтральное сообщение при запрете смены собственной роли (Task-12). */
    private static final String SELF_ROLE_CHANGE_ERROR =
            "Операция отклонена: нельзя изменить роль собственной учетной записи";

    private final AdminService adminService;
    private final VaultExportImportService exportImportService;
    private final UserRepository userRepository;

    public WebAdminController(AdminService adminService,
                              VaultExportImportService exportImportService,
                              UserRepository userRepository) {
        this.adminService = adminService;
        this.exportImportService = exportImportService;
        this.userRepository = userRepository;
    }

    // -- пользователи ----------------------------------------------------------

    /** Список пользователей: username, role, enabled, createdAt (без хэшей/DEK). */
    @GetMapping("/web/admin/users")
    public String users(@AuthenticationPrincipal AuthUser principal,
                        @RequestParam(defaultValue = "0") int page,
                        Model model) {
        Page<User> users = adminService.listUsers(page, PAGE_SIZE);
        model.addAttribute("users", users.getContent());
        model.addAttribute("currentPage", users.getNumber());
        model.addAttribute("totalPages", users.getTotalPages());
        model.addAttribute("username", principal.getUsername());
        return "admin-users";
    }

    /** Создание пользователя (USER_CREATED_BY_ADMIN пишется в AdminService). */
    @PostMapping("/web/admin/users")
    public String createUser(@AuthenticationPrincipal AuthUser principal,
                             @RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String role,
                             RedirectAttributes redirectAttributes) {
        try {
            adminService.createUser(username, password, role, principal.user());
            redirectAttributes.addFlashAttribute("flashMessage", "Пользователь создан");
        } catch (AuthServiceException e) {
            // Нейтральное сообщение (например, имя занято) — без внутренних деталей.
            redirectAttributes.addFlashAttribute("flashError",
                    e.getReason() == AuthServiceException.Reason.USERNAME_TAKEN
                            ? "Не удалось создать пользователя: имя уже занято"
                            : "Не удалось создать пользователя");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Не удалось создать пользователя: проверьте формат имени "
                            + "и длину пароля (минимум 12 символов)");
        }
        // Пароль в модель/redirect не попадает.
        return "redirect:/web/admin/users";
    }

    /** Включение учетной записи. */
    @PostMapping("/web/admin/users/{id}/enable")
    public String enableUser(@AuthenticationPrincipal AuthUser principal,
                             @PathVariable UUID id,
                             RedirectAttributes redirectAttributes) {
        try {
            adminService.enableUser(id, principal.user());
            redirectAttributes.addFlashAttribute("flashMessage", "Пользователь включен");
        } catch (AuthServiceException e) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
        }
        return "redirect:/web/admin/users";
    }

    /** Отключение учетной записи (блокирует вход). */
    @PostMapping("/web/admin/users/{id}/disable")
    public String disableUser(@AuthenticationPrincipal AuthUser principal,
                              @PathVariable UUID id,
                              RedirectAttributes redirectAttributes) {
        try {
            adminService.disableUser(id, principal.user());
            redirectAttributes.addFlashAttribute("flashMessage", "Пользователь отключен");
        } catch (AuthServiceException e) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
        }
        return "redirect:/web/admin/users";
    }

    /**
     * Сброс пароля администратором. Новый пароль живет только в теле POST:
     * в шаблон не возвращается, в логи не пишется, в URL не попадает.
     */
    @PostMapping("/web/admin/users/{id}/reset-password")
    public String resetPassword(@AuthenticationPrincipal AuthUser principal,
                                @PathVariable UUID id,
                                @RequestParam String newPassword,
                                RedirectAttributes redirectAttributes) {
        try {
            int revoked = adminService.resetPassword(id, newPassword, principal.user());
            redirectAttributes.addFlashAttribute("flashMessage",
                    "Пароль обновлен. Отозвано активных токенов: " + revoked);
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Пароль должен содержать от 12 до 128 символов");
        } catch (AuthServiceException e) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
        }
        return "redirect:/web/admin/users";
    }

    /**
     * Смена роли. Использует новый AdminService.changeRole (Task-12):
     * смена собственной роли блокируется нейтральной ошибкой.
     */
    @PostMapping("/web/admin/users/{id}/change-role")
    public String changeRole(@AuthenticationPrincipal AuthUser principal,
                             @PathVariable UUID id,
                             @RequestParam String role,
                             RedirectAttributes redirectAttributes) {
        try {
            adminService.changeRole(id, role, principal.user());
            redirectAttributes.addFlashAttribute("flashMessage", "Роль изменена");
        } catch (AdminServiceException e) {
            // Нейтральное сообщение без деталей (защита последнего админа).
            redirectAttributes.addFlashAttribute("flashError", SELF_ROLE_CHANGE_ERROR);
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError", "Некорректная роль");
        } catch (AuthServiceException e) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
        }
        return "redirect:/web/admin/users";
    }

    // -- CSV export/import чужого сейфа (Фаза 4) ---------------------------------

    /**
     * Экспорт сейфа пользователя администратором: те же заголовки, что у
     * пользовательского экспорта, но имя файла vault-user-<username>-...csv.
     * Аудит VAULT_EXPORTED (actor=admin, target) пишет сервис.
     */
    @GetMapping("/web/admin/users/{id}/vault/export")
    public Object exportVault(@AuthenticationPrincipal AuthUser principal,
                              @PathVariable UUID id,
                              @RequestParam(defaultValue = "false") boolean bom,
                              RedirectAttributes redirectAttributes) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
            return "redirect:/web/admin/users";
        }
        ExportPayload payload;
        try {
            payload = exportImportService.export(principal.user(), target, bom);
        } catch (PayloadTooLargeException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Экспорт невозможен: превышен лимит записей");
            return "redirect:/web/admin/users";
        }
        String filename = CsvFilenames.forTargetUser(target.getUsername(), Instant.now());
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(
                org.springframework.http.MediaType.parseMediaType("text/csv; charset=utf-8"));
        headers.set(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"");
        // Заголовки-предупреждения — те же константы, что в user-экспорте (TP A4)
        headers.add(WebVaultController.EXPORT_WARNING_HEADER,
                WebVaultController.EXPORT_WARNING_VALUE);
        headers.setContentLength(payload.csv().length);
        // Plaintext-экспорт (CSV с открытыми паролями) не должен кэшироваться
        // ни браузером, ни промежуточными прокси (TP A7).
        headers.setCacheControl("no-store");
        return new org.springframework.http.ResponseEntity<>(payload.csv(), headers,
                org.springframework.http.HttpStatus.OK);
    }

    /** Страница импорта CSV в чужой сейф (переиспользуется import.html). */
    @GetMapping("/web/admin/users/{id}/vault/import")
    public String importPage(@PathVariable UUID id,
                             Model model,
                             RedirectAttributes redirectAttributes) {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
            return "redirect:/web/admin/users";
        }
        model.addAttribute("targetUsername", target.getUsername());
        model.addAttribute("importAction", "/web/admin/users/" + id + "/vault/import");
        model.addAttribute("againUrl", "/web/admin/users/" + id + "/vault/import");
        model.addAttribute("reportBackUrl", "/web/admin/users");
        return "import";
    }

    /**
     * Импорт CSV в сейф пользователя (PRG, Фаза 4): отчёт — во flash,
     * ответ — 302 на GET .../report. Аудит VAULT_IMPORTED (actor=admin,
     * target) пишет сервис; файл нигде не сохраняется, CSV в логи не пишется.
     */
    @PostMapping("/web/admin/users/{id}/vault/import")
    public String importCsv(@AuthenticationPrincipal AuthUser principal,
                            @PathVariable UUID id,
                            @RequestParam("file") org.springframework.web.multipart.MultipartFile file,
                            @RequestParam(defaultValue = "skip") String conflictStrategy,
                            @RequestParam(defaultValue = "false") boolean dryRun,
                            @RequestParam(defaultValue = "false") boolean failFast,
                            RedirectAttributes redirectAttributes) throws java.io.IOException {
        User target = userRepository.findById(id).orElse(null);
        if (target == null) {
            redirectAttributes.addFlashAttribute("flashError", "Пользователь не найден");
            return "redirect:/web/admin/users";
        }
        String importForm = "redirect:/web/admin/users/" + id + "/vault/import";
        try {
            if (file.isEmpty()) {
                throw new InvalidCsvException("CSV file is empty");
            }
            // Тот же парсер, что в user-импорте (TP A4 — дедуп switch-блока)
            ConflictStrategy strategy = WebVaultController.parseConflictStrategy(conflictStrategy);
            ImportReport report = exportImportService.importFromCsv(
                    principal.user(), target, file.getBytes(), strategy, dryRun, failFast);
            redirectAttributes.addFlashAttribute("importReport", report);
            return "redirect:/web/admin/users/" + id + "/vault/import/report";
        } catch (InvalidCsvException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Не удалось разобрать CSV: " + e.getMessage());
            return importForm;
        } catch (PayloadTooLargeException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    WebErrorController.FILE_TOO_LARGE_MESSAGE);
            return importForm;
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Некорректные параметры импорта");
            return importForm;
        }
    }

    /** Отчёт админского импорта из flash (PRG); без flash — на форму. */
    @GetMapping("/web/admin/users/{id}/vault/import/report")
    public String importReport(@PathVariable UUID id,
                               Model model) {
        ImportReport report = (ImportReport) model.asMap().get("importReport");
        if (report == null) {
            return "redirect:/web/admin/users/" + id + "/vault/import";
        }
        model.addAttribute("report", report);
        model.addAttribute("againUrl", "/web/admin/users/" + id + "/vault/import");
        model.addAttribute("reportBackUrl", "/web/admin/users");
        return "import-report";
    }

    // -- аудит ------------------------------------------------------------------

    /**
     * Журнал аудита с фильтрами (type, userId, from, to) и пагинацией.
     * detailsJson выводится как есть — он по построению не содержит секретов.
     */
    @GetMapping("/web/admin/audit")
    public String audit(@AuthenticationPrincipal AuthUser principal,
                        @RequestParam(required = false) String type,
                        @RequestParam(required = false) String userId,
                        @RequestParam(required = false) String from,
                        @RequestParam(required = false) String to,
                        @RequestParam(defaultValue = "0") int page,
                        Model model,
                        RedirectAttributes redirectAttributes) {
        UUID userIdFilter = null;
        Instant fromFilter = null;
        Instant toFilter = null;
        try {
            if (userId != null && !userId.isBlank()) {
                userIdFilter = UUID.fromString(userId.trim());
            }
            if (from != null && !from.isBlank()) {
                fromFilter = Instant.parse(from.trim());
            }
            if (to != null && !to.isBlank()) {
                toFilter = Instant.parse(to.trim());
            }
        } catch (IllegalArgumentException e) {
            // Некорректный фильтр — нейтральное сообщение, без внутренностей.
            redirectAttributes.addFlashAttribute("flashError",
                    "Некорректный формат фильтра (ожидается UUID и/или ISO-8601)");
            return "redirect:/web/admin/audit";
        }

        Page<AdminService.AuditView> events =
                adminService.listAudit(type, userIdFilter, fromFilter, toFilter, page, PAGE_SIZE);
        model.addAttribute("events", events.getContent());
        // Значения фильтров возвращаются в форму как есть (без секретов).
        model.addAttribute("type", type == null ? "" : type);
        model.addAttribute("userId", userId == null ? "" : userId);
        model.addAttribute("from", from == null ? "" : from);
        model.addAttribute("to", to == null ? "" : to);
        model.addAttribute("currentPage", events.getNumber());
        model.addAttribute("totalPages", events.getTotalPages());
        model.addAttribute("username", principal.getUsername());
        return "admin-audit";
    }

    // -- ротация ключей ----------------------------------------------------------

    /** Карточка ротации: кнопка Rewrap DEKs + результат как flash-сообщение. */
    @GetMapping("/web/admin/crypto")
    public String crypto(@AuthenticationPrincipal AuthUser principal, Model model) {
        model.addAttribute("username", principal.getUsername());
        return "admin-crypto";
    }

    /**
     * Rewrap DEK всех пользователей активным KEK. Результат (количество,
     * activeKekId — нечувствительные данные) выводится flash-сообщением.
     */
    @PostMapping("/web/admin/crypto/rewrap-deks")
    public String rewrapDeks(@AuthenticationPrincipal AuthUser principal,
                             RedirectAttributes redirectAttributes) {
        try {
            AdminService.RewrapResult result = adminService.rewrapDeks(principal.user());
            redirectAttributes.addFlashAttribute("flashMessage",
                    "Перепаковано DEK: " + result.rewrappedUsers()
                            + ". Активный KEK: " + result.activeKekId());
        } catch (KeyRotationException e) {
            // Нейтральное сообщение: материал ключей и внутренние детали не раскрываются.
            redirectAttributes.addFlashAttribute("flashError",
                    "Ротация ключей не завершена: часть DEK не удалось перепаковать. "
                            + "Операцию можно безопасно повторить");
        }
        return "redirect:/web/admin/crypto";
    }
}
