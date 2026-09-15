package com.example.safeaccounts.web;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Ошибки конкурентного изменения данных в web-цепочке (TP MAJOR-2).
 * <p>
 * Вместо 500-й ошибки (стектрейс запрещён, RFC 7807 — только для API)
 * пользователь получает flash-сообщение и возвращается на список записей.
 * <p>
 * ВАЖНО (границы скоупа): advice ограничен пакетом {@code ...web} через
 * {@code basePackageClasses}. Вариант {@code @ControllerAdvice(annotations =
 * Controller.class)} здесь НЕДОПУСТИМ: {@code @RestController} мета-аннотирован
 * {@code @Controller}, поэтому такой advice поймал бы и REST-контроллеры
 * ({@code api/*}), превратив их ошибки в редиректы и сломав контракт API.
 */
@ControllerAdvice(basePackageClasses = WebVaultController.class)
public class WebExceptionAdvice {

    /** Нейтральное сообщение: без деталей гонки и без раскрытия причин. */
    static final String CONCURRENT_CHANGE_ERROR =
            "Параллельное изменение — повторите действие";

    /**
     * Гонка тегов (UNIQUE user_id+name_lower, см. TagService) и оптимистичная
     * блокировка записи ({@code @Version} при одновременном редактировании).
     */
    @ExceptionHandler({DataIntegrityViolationException.class,
            ObjectOptimisticLockingFailureException.class})
    public String handleConcurrentModification(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("flashError", CONCURRENT_CHANGE_ERROR);
        return "redirect:/web/entries";
    }

    /**
     * Файл импорта больше multipart-лимита (10 МБ, Фаза 3) — Spring отклоняет
     * запрос до контроллера. В UI — flash + возврат на форму импорта (не 500).
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String handleMaxUpload(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("flashError",
                "Файл больше 10 МБ — уменьшите файл и повторите");
        return "redirect:/web/entries/import";
    }

    /**
     * multipart-часть «file» отсутствует (форма отправлена без файла) —
     * раньше было whitelabel-400. В UI: flash + возврат на форму импорта.
     */
    @ExceptionHandler(org.springframework.web.multipart.support.MissingServletRequestPartException.class)
    public String handleMissingPart(RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("flashError",
                "Не удалось прочитать файл — выберите CSV-файл и повторите");
        return "redirect:/web/entries/import";
    }
}
