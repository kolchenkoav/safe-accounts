package com.example.safeaccounts.web;

import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.VaultException;
import com.example.safeaccounts.service.VaultService;
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

    public WebVaultController(VaultService vaultService) {
        this.vaultService = vaultService;
    }

/** Форма и данные страницы списка (без паролей — Task-11/Task-05). */
    public record EntryForm(
            @NotBlank @Size(max = 256) String name,
            @NotBlank @Size(max = 2048) String site,
            @NotBlank @Size(max = 2048) String login,
            @NotBlank @Size(max = 4096) String password,
            @Size(max = 8192) String notes) {
    }

    /** Список записей текущего пользователя. */
    @GetMapping("/web/entries")
    public String list(@AuthenticationPrincipal AuthUser principal,
                       @RequestParam(defaultValue = "0") int page,
                       Model model) {
        Page<VaultService.ListItem> items = vaultService.list(principal.user(), page, 20);
        model.addAttribute("entries", items.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", items.getTotalPages());
        model.addAttribute("username", principal.getUsername());
        return "entries";
    }

    /** Страница создания записи. */
    @GetMapping("/web/entries/new")
    public String newEntry(Model model) {
model.addAttribute("entryForm", new EntryForm("", "", "", "", ""));
        return "entry-form";
    }

    /** Создание записи: шифрование и аудит — в VaultService. */
    @PostMapping("/web/entries")
    public String create(@AuthenticationPrincipal AuthUser principal,
                         @Valid @ModelAttribute("entryForm") EntryForm form,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes) {
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

    /** Обновление записи: все поля перешифровываются новыми IV (VaultService). */
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

    private static String emptyToNull(String notes) {
        return notes == null || notes.isBlank() ? null : notes;
    }
}
