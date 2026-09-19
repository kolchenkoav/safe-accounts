package com.example.safeaccounts.web;

import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.TagService;
import com.example.safeaccounts.service.VaultException;
import com.example.safeaccounts.service.ScanProperties;
import com.example.safeaccounts.service.ScanRateLimitedException;
import com.example.safeaccounts.service.VaultExportImportService;
import com.example.safeaccounts.service.VaultScanService;
import com.example.safeaccounts.service.VaultService;
import com.example.safeaccounts.service.csv.ConflictStrategy;
import com.example.safeaccounts.service.csv.CsvFilenames;
import com.example.safeaccounts.service.csv.ExportPayload;
import com.example.safeaccounts.service.csv.ImportReport;
import com.example.safeaccounts.service.csv.InvalidCsvException;
import com.example.safeaccounts.service.csv.PayloadTooLargeException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.UUID;

/**
 * Веб-интерфейс сейфа (Task-11): список, создание, просмотр, изменение,
 * удаление записей. Контроллер тонкий — все бизнес-правила и шифрование
 * в {@link VaultService}; тот же сервис и те же правила доступа, что у API.
 * <p>
 * Безопасность:
 * <ul>
 *   <li>список никогда не содержит пароль (Task-11 / Task-05);</li>
 *   <li>пароль показывается только по явному нажатию "Показать пароль"
 *       (отдельный POST-запрос, reveal=true, факт фиксируется в аудите);</li>
 *   <li>чужая запись неотличима от несуществующей (VaultException.NOT_FOUND);</li>
 *   <li>пароли форм никогда не логируются; в модель они попадают только
 *       при явном reveal-запросе.</li>
 * </ul>
 */
@Controller
public class WebVaultController {

    private final VaultService vaultService;
    private final TagService tagService;
    private final VaultExportImportService exportImportService;
    private final VaultScanService vaultScanService;

    public WebVaultController(VaultService vaultService, TagService tagService,
                              VaultExportImportService exportImportService,
                              VaultScanService vaultScanService) {
        this.vaultService = vaultService;
        this.tagService = tagService;
        this.exportImportService = exportImportService;
        this.vaultScanService = vaultScanService;
    }

    /** Форма и данные страницы списка (без паролей — Task-11/Task-05). */
    public record EntryForm(
            @NotBlank @Size(max = 256) String name,
            @NotBlank @Size(max = 2048) String site,
            @NotBlank @Size(max = 2048) String login,
            @Size(max = 4096) String password,
            @Size(max = 8192) String notes) {
    }

    /** Список записей текущего пользователя (+ опциональный фильтр по тегу, Фаза 2). */
    @GetMapping("/web/entries")
    public String list(@AuthenticationPrincipal AuthUser principal,
                       @RequestParam(defaultValue = "0") int page,
                       @RequestParam(name = "tag", required = false) String tag,
                       Model model) {
        // ?tag=<мусор> не должен давать 400/500 (конвертация UUID): парсим
        // вручную; невалидный — nil-UUID-сентинел, который ничего не матчит
        // → пустая страница фильтра (Фаза 5, edge-харднинг).
        UUID tagId = null;
        if (tag != null && !tag.isBlank()) {
            try {
                tagId = UUID.fromString(tag.trim());
            } catch (IllegalArgumentException e) {
                tagId = new UUID(0L, 0L);
            }
        }
        Page<VaultService.ListItem> items = vaultService.list(principal.user(), page, 20, tagId);
        model.addAttribute("entries", items.getContent());
        // Показываемая страница синхронна с клампингом VaultService
        // (page=999 → последняя существующая, не «1000 / 2»).
        int currentPage = Math.max(page, 0);
        if (items.getTotalPages() > 0 && currentPage >= items.getTotalPages()) {
            currentPage = items.getTotalPages() - 1;
        }
        model.addAttribute("currentPage", currentPage);
        model.addAttribute("totalPages", items.getTotalPages());
        model.addAttribute("username", principal.getUsername());
        // Активный фильтр: id — для ссылок пагинации, name — для индикатора «Тег: ... ✕».
        // Чужой/несуществующий/удалённый tagId — без индикатора, но с подсказкой
        // «Тег не найден» (F1): список пуст, сценарий единообразен.
        var foundTag = tagService.findTag(principal.user(), tagId);
        foundTag.ifPresent(found -> {
            model.addAttribute("tagFilterId", found.getId());
            model.addAttribute("tagFilterName", found.getName());
        });
        model.addAttribute("tagFilterUnknown", tagId != null && foundTag.isEmpty());
        // Опции select-фильтра (Фаза 6): id/name/entryCount текущего пользователя;
        // пусто — контрол не рендерится (th:if в шаблоне).
        model.addAttribute("tagOptions", tagService.listWithEntryCounts(principal.user()));
        return "entries";
    }

    /** Страница создания записи. */
    @GetMapping("/web/entries/new")
    public String newEntry(Model model) {
model.addAttribute("entryForm", new EntryForm("", "", "", "", ""));
        return "entry-form";
    }

    /** Создание записи: шифрование и аудит — в VaultService. Пароль обязателен
     *  (в отличие от edit — G1: там пусто = «не менять»). */
    @PostMapping("/web/entries")
    public String create(@AuthenticationPrincipal AuthUser principal,
                         @Valid @ModelAttribute("entryForm") EntryForm form,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes) {
        // G1 сделал password опциональным в EntryForm (общая с edit форма):
        // при создании пароль ОБЯЗАТЕЛЕН — проверяем явно.
        if (form.password() == null || form.password().isBlank()) {
            bindingResult.rejectValue("password", "NotBlank", "Пароль обязателен");
        }
        if (bindingResult.hasErrors()) {
            // Повторный рендер формы с ошибками (th:errors), а не 500/400.
            return "entry-form";
        }
        vaultService.create(principal.user(), form.name(), form.site(), form.login(),
                form.password(), emptyToNull(form.notes()));
        redirectAttributes.addFlashAttribute("flashMessage", "Запись создана");
        return "redirect:/web/entries";
    }

    /** Просмотр записи. Пароль НЕ показывается — только по явному reveal. */
    @GetMapping("/web/entries/{id}")
    public String view(@AuthenticationPrincipal AuthUser principal,
                       @PathVariable UUID id,
                       Model model) {
        try {
            VaultService.DecryptedEntry entry = vaultService.get(principal.user(), id, false);
            model.addAttribute("entryId", id);
            model.addAttribute("entry", entry);
            model.addAttribute("revealed", false);
            // Существующие теги пользователя — для datalist формы привязки (Фаза 2).
            model.addAttribute("allTags", tagService.listUserTags(principal.user()));
            // Пароль не передаем в модель, когда не было reveal.
            return "entry-view";
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
    }

    /** Явное раскрытие пароля (отдельный POST — фиксируется в аудите). */
    @PostMapping("/web/entries/{id}/reveal")
    public String reveal(@AuthenticationPrincipal AuthUser principal,
                         @PathVariable UUID id,
                         Model model) {
        try {
            VaultService.DecryptedEntry entry = vaultService.get(principal.user(), id, true);
            model.addAttribute("entryId", id);
            model.addAttribute("entry", entry);
            model.addAttribute("revealed", true);
            model.addAttribute("allTags", tagService.listUserTags(principal.user()));
            return "entry-view";
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
    }

    /** Страница редактирования: пароль требуется ввести заново (не подтягиваем старый). */
    @GetMapping("/web/entries/{id}/edit")
    public String edit(@AuthenticationPrincipal AuthUser principal,
                       @PathVariable UUID id,
                       Model model) {
        VaultService.DecryptedEntry entry;
        try {
            entry = vaultService.get(principal.user(), id, false);
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
        // password в форму НЕ выносим: старый пароль не должен попадать в HTML.
        model.addAttribute("entryId", id);
model.addAttribute("entryForm", new EntryForm(entry.name(), entry.site(), entry.login(), "", entry.notes()));
        return "entry-form-edit";
    }

    /** Обновление записи: поля перешифровываются новыми IV; пустой пароль =
     *  «не менять» (G1 — VaultService сохраняет прежний шифротекст). */
    @PostMapping("/web/entries/{id}/edit")
    public String update(@AuthenticationPrincipal AuthUser principal,
                         @PathVariable UUID id,
                         @Valid @ModelAttribute("entryForm") EntryForm form,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes,
                         Model model) {
        if (bindingResult.hasErrors()) {
            // Повторный рендер формы с ошибками; entryId нужен шаблону.
            model.addAttribute("entryId", id);
            return "entry-form-edit";
        }
        try {
            vaultService.update(principal.user(), id, form.name(), form.site(), form.login(),
                    form.password(), emptyToNull(form.notes()));
            redirectAttributes.addFlashAttribute("flashMessage", "Запись обновлена");
            return "redirect:/web/entries";
        } catch (VaultException e) {
            model.addAttribute("entryId", id);
            model.addAttribute("errorMessage", "Не удалось обновить запись");
            return "entry-form-edit";
        }
    }

    /** Удаление записи (POST + CSRF). Чужая запись — нейтральный 404. */
    @PostMapping("/web/entries/{id}/delete")
    public String delete(@AuthenticationPrincipal AuthUser principal,
                         @PathVariable UUID id,
                         RedirectAttributes redirectAttributes) {
        try {
            vaultService.delete(principal.user(), id);
            redirectAttributes.addFlashAttribute("flashMessage", "Запись удалена");
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей
            // (то же правило, что и в API: единый 404).
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
        return "redirect:/web/entries";
    }

    /** Привязка тега к записи по имени: найти существующий или создать (Фаза 2). */
    @PostMapping("/web/entries/{id}/tags")
    public String attachTag(@AuthenticationPrincipal AuthUser principal,
                            @PathVariable UUID id,
                            @RequestParam("tagName") String tagName,
                            RedirectAttributes redirectAttributes) {
        try {
            TagService.AttachResult result =
                    tagService.attachOrCreate(principal.user(), id, tagName);
            redirectAttributes.addFlashAttribute("flashMessage",
                    result.linked() ? "Тег привязан" : "Тег уже был привязан к записи");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Некорректное имя тега: буквы, цифры, пробел, _ - . (1–64 символа)");
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
        return "redirect:/web/entries/" + id;
    }

    /** Отвязка тега от записи (POST + CSRF); редирект обратно на карточку. */
    @PostMapping("/web/entries/{id}/tags/{tagId}/delete")
    public String detachTag(@AuthenticationPrincipal AuthUser principal,
                            @PathVariable UUID id,
                            @PathVariable UUID tagId,
                            RedirectAttributes redirectAttributes) {
        try {
            boolean removed = tagService.detach(principal.user(), id, tagId);
            redirectAttributes.addFlashAttribute("flashMessage",
                    removed ? "Тег снят" : "Тег не был привязан");
        } catch (VaultException e) {
            // Чужая/несуществующая запись — нейтральный 404 без деталей.
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.NOT_FOUND);
        }
        return "redirect:/web/entries/" + id;
    }

    // -- CSV export/import для пользователя (Фаза 3) ---------------------------

    /** Заголовок-предупреждение — единый источник в service/csv (Фаза 5). */
    static final String EXPORT_WARNING_HEADER = CsvFilenames.EXPORT_WARNING_HEADER;
    static final String EXPORT_WARNING_VALUE = CsvFilenames.EXPORT_WARNING_VALUE;

    /**
     * Экспорт собственного сейфа в CSV: тот же контракт, что REST
     * GET /api/vault/export — text/csv, attachment-имя, предупреждение.
     * Превышение MAX_EXPORT_ROWS — flash + возврат на список (не 413-страница).
     */
    @GetMapping("/web/entries/export")
    public Object exportCsv(@AuthenticationPrincipal AuthUser principal,
                            @RequestParam(defaultValue = "false") boolean bom,
                            RedirectAttributes redirectAttributes) {
        ExportPayload payload;
        try {
            payload = exportImportService.export(principal.user(), principal.user(), bom);
        } catch (PayloadTooLargeException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Экспорт невозможен: превышен лимит записей");
            return "redirect:/web/entries";
        }
        String filename = CsvFilenames.forUser(principal.getUsername(),
                java.time.Instant.now());
        org.springframework.http.HttpHeaders headers = new org.springframework.http.HttpHeaders();
        headers.setContentType(
                org.springframework.http.MediaType.parseMediaType("text/csv; charset=utf-8"));
        headers.set(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + filename + "\"");
        headers.add(EXPORT_WARNING_HEADER, EXPORT_WARNING_VALUE);
        headers.setContentLength(payload.csv().length);
        // Plaintext-экспорт (CSV с открытыми паролями) не должен кэшироваться
        // ни браузером, ни промежуточными прокси (TP A7).
        headers.setCacheControl("no-store");
        return new org.springframework.http.ResponseEntity<>(payload.csv(), headers,
                org.springframework.http.HttpStatus.OK);
    }

    /**
     * Сканер слабых паролей собственного сейфа (G2, план §3.4): PRG — отчёт во
     * flash, ответ — 302 на GET /web/entries/scan/report. Аудит VAULT_SCANNED
     * пишет сервис (только агрегаты); причины слабости в отчёте — без паролей.
     * Квота 1/60 c на пользователя — в сервисе (после аутентификации):
     * ScanRateLimitedException → flash с Retry-After + redirect (не 500).
     */
    @PostMapping("/web/entries/scan")
    public String scan(@AuthenticationPrincipal AuthUser principal,
                       RedirectAttributes redirectAttributes) {
        try {
            redirectAttributes.addFlashAttribute("scanReport",
                    vaultScanService.scan(principal.user(), principal.user()));
            return "redirect:/web/entries/scan/report";
        } catch (ScanRateLimitedException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Скан уже выполнялся недавно — повторите через "
                            + e.getRetryAfterSeconds() + " сек");
            return "redirect:/web/entries";
        }
    }

    /** Отчёт скана из flash (PRG); прямой GET без flash — к списку записей. */
    @GetMapping("/web/entries/scan/report")
    public String scanReport(Model model) {
        VaultScanService.ScanReport report =
                (VaultScanService.ScanReport) model.asMap().get("scanReport");
        if (report == null) {
            return "redirect:/web/entries";
        }
        model.addAttribute("report", report);
        model.addAttribute("own", true);
        return "scan-report";
    }

    /** Страница импорта CSV: предупреждение о plaintext + multipart-форма. */
    @GetMapping("/web/entries/import")
    public String importPage(Model model) {
        model.addAttribute("importAction", "/web/entries/import");
        return "import";
    }

    /**
     * Импорт CSV в собственный сейф (PRG, Фаза 4): отчёт уходит во flash,
     * ответ — 302 на GET /report. F5 повторяет только безопасный GET.
     * PRG/FlashMap-контракт: браузер всегда следует 302 и потребляет flash;
     * два POST без follow-GET возможны только у не-браузерного клиента — тогда
     * первый pending-flash покажется при ближайшем GET отчёта (не ошибка).
     * Tomcat буферизует multipart-части во временные файлы work-директории
     * (авто-очистка после запроса); в БД, логи и модель файл не попадает.
     */
    @PostMapping("/web/entries/import")
    public String importCsv(@AuthenticationPrincipal AuthUser principal,
                            @RequestParam("file") org.springframework.web.multipart.MultipartFile file,
                            @RequestParam(defaultValue = "skip") String conflictStrategy,
                            @RequestParam(defaultValue = "false") boolean dryRun,
                            @RequestParam(defaultValue = "false") boolean failFast,
                            RedirectAttributes redirectAttributes) throws java.io.IOException {
        try {
            // file == null невозможен: резолвер бросает
            // MissingServletRequestPartException раньше (→ WebExceptionAdvice)
            if (file.isEmpty()) {
                throw new InvalidCsvException("CSV file is empty");
            }
            ConflictStrategy strategy = parseConflictStrategy(conflictStrategy);
            ImportReport report = exportImportService.importFromCsv(
                    principal.user(), principal.user(), file.getBytes(),
                    strategy, dryRun, failFast);
            redirectAttributes.addFlashAttribute("importReport", report);
            return "redirect:/web/entries/import/report";
        } catch (InvalidCsvException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Не удалось разобрать CSV: " + e.getMessage());
            return "redirect:/web/entries/import";
        } catch (PayloadTooLargeException e) {
            // Единая константа (fix A3): размер файла или cumulative-cap.
            redirectAttributes.addFlashAttribute("flashError",
                    WebErrorController.IMPORT_LIMIT_EXCEEDED_MESSAGE);
            return "redirect:/web/entries/import";
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError",
                    "Некорректные параметры импорта");
            return "redirect:/web/entries/import";
        }
    }

    /**
     * Отчёт импорта из flash (PRG). Прямой GET без flash (F5/ закладка) —
     * назад на форму: повторного импорта не происходит.
     */
    @GetMapping("/web/entries/import/report")
    public String importReport(Model model) {
        ImportReport report = (ImportReport) model.asMap().get("importReport");
        if (report == null) {
            return "redirect:/web/entries/import";
        }
        model.addAttribute("report", report);
        return "import-report";
    }

    /**
     * Парсинг conflictStrategy из формы (skip|upsert, default skip).
     * Пакетный доступ: переиспользуется WebAdminController (TP A4 — дедуп).
     */
    static ConflictStrategy parseConflictStrategy(String value) {
        if (value == null || value.isBlank()) {
            return ConflictStrategy.SKIP;
        }
        return switch (value.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "skip" -> ConflictStrategy.SKIP;
            case "upsert" -> ConflictStrategy.UPSERT;
            default -> throw new IllegalArgumentException("conflictStrategy must be skip|upsert");
        };
    }

    private static String emptyToNull(String notes) {
        return notes == null || notes.isBlank() ? null : notes;
    }
}
