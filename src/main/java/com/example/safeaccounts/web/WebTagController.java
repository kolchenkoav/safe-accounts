package com.example.safeaccounts.web;

import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.TagAlreadyExistsException;
import com.example.safeaccounts.service.TagService;
import com.example.safeaccounts.service.TagStillReferencedException;
import com.example.safeaccounts.service.VaultException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

/**
 * Страница управления тегами web-интерфейса (Фаза 2): список с количеством
 * записей, создание, переименование, удаление. Контроллер тонкий — все
 * бизнес-правила, owner-check и аудит в {@link TagService}.
 * <p>
 * Безопасность:
 * <ul>
 *   <li>все POST-формы — через {@code th:action} (CSRF-токен Thymeleaf);</li>
 *   <li>чужие/несуществующие теги — нейтральный 404 (как в API);</li>
 *   <li>валидация имени — та же, что в REST-DTO (1..64, regex), выполняется
 *       jakarta.validation на {@link TagForm} и повторно в сервисе;</li>
 *   <li>ошибки показываются flash-сообщениями (alert-error), без стектрейсов.</li>
 * </ul>
 */
@Controller
public class WebTagController {

    private final TagService tagService;

    public WebTagController(TagService tagService) {
        this.tagService = tagService;
    }

    /** Форма создания/переименования тега: валидация как в REST-DTO. */
    public record TagForm(
            @NotBlank
            @Size(max = 64)
            @Pattern(regexp = TagService.TAG_NAME_REGEX,
                    message = "Допустимы буквы, цифры, пробел, _ - . (длина 1–64)")
            String name) {
    }

    /** Список тегов пользователя с счётчиками записей + форма создания. */
    @GetMapping("/web/tags")
    public String tags(@AuthenticationPrincipal AuthUser principal, Model model) {
        model.addAttribute("tags", tagService.listWithEntryCounts(principal.user()));
        model.addAttribute("username", principal.getUsername());
        return "tags";
    }

    /** Создание тега; дубль имени (case-insensitive) — flash-ошибка, редирект. */
    @PostMapping("/web/tags")
    public String create(@AuthenticationPrincipal AuthUser principal,
                         @Valid @ModelAttribute("tagForm") TagForm form,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("flashError", "Некорректное имя тега");
            return "redirect:/web/tags";
        }
        try {
            tagService.createTag(principal.user(), form.name());
            redirectAttributes.addFlashAttribute("flashMessage", "Тег создан");
        } catch (TagAlreadyExistsException e) {
            redirectAttributes.addFlashAttribute("flashError", "Тег уже существует");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError", "Некорректное имя тега");
        }
        return "redirect:/web/tags";
    }

    /** Переименование тега (inline-форма в списке тегов). */
    @PostMapping("/web/tags/{id}/rename")
    public String rename(@AuthenticationPrincipal AuthUser principal,
                         @PathVariable UUID id,
                         @Valid @ModelAttribute("tagForm") TagForm form,
                         BindingResult bindingResult,
                         RedirectAttributes redirectAttributes) {
        if (bindingResult.hasErrors()) {
            redirectAttributes.addFlashAttribute("flashError", "Некорректное имя тега");
            return "redirect:/web/tags";
        }
        try {
            tagService.renameTag(principal.user(), id, form.name());
            redirectAttributes.addFlashAttribute("flashMessage", "Тег переименован");
        } catch (TagAlreadyExistsException e) {
            redirectAttributes.addFlashAttribute("flashError", "Тег уже существует");
        } catch (com.example.safeaccounts.service.TagReservedNameException e) {
            // Системный тег сканера переименовывать нельзя (G2)
            redirectAttributes.addFlashAttribute("flashError",
                    "Системный тег \"" + e.getReservedName()
                            + "\" переименовывать нельзя");
        } catch (IllegalArgumentException e) {
            redirectAttributes.addFlashAttribute("flashError", "Некорректное имя тега");
        } catch (VaultException e) {
            // Чужой/несуществующий тег — нейтральный 404 без деталей.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "redirect:/web/tags";
    }

    /**
     * Удаление тега. Занятый тег не удаляется: flash с количеством записей
     * (пользователь сначала снимает тег с записей на карточках).
     */
    @PostMapping("/web/tags/{id}/delete")
    public String delete(@AuthenticationPrincipal AuthUser principal,
                         @PathVariable UUID id,
                         RedirectAttributes redirectAttributes) {
        try {
            tagService.deleteTag(principal.user(), id);
            redirectAttributes.addFlashAttribute("flashMessage", "Тег удалён");
        } catch (TagStillReferencedException e) {
            long count = tagService.countEntriesUsingTag(principal.user(), id);
            // Русская плюрализация: 1 записью, 2-4/5-20... записями,
            // 11-14 — записями (1 записью, 21 записью, но 11 записями).
            String noun = count % 10 == 1 && count % 100 != 11
                    ? "записью" : "записями";
            redirectAttributes.addFlashAttribute("flashError",
                    "Тег используется %d %s — сначала снимите его с записей"
                            .formatted(count, noun));
        } catch (VaultException e) {
            // Чужой/несуществующий тег — нейтральный 404 без деталей.
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return "redirect:/web/tags";
    }
}
