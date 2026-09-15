package com.example.safeaccounts.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.net.URI;

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

    /** Fallback, если Referer отсутствует или не прошёл валидацию. */
    static final String DEFAULT_IMPORT_RETURN = "/web/entries/import";

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
     * запрос до контроллера. В UI — flash + возврат на страницу, откуда пришёл
     * запрос (Referer), либо на форму импорта (не 500).
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String handleMaxUpload(HttpServletRequest request,
                                  RedirectAttributes redirectAttributes) {
        // Единая формулировка с WebErrorController и контроллером импорта (TP A2)
        redirectAttributes.addFlashAttribute("flashError",
                WebErrorController.FILE_TOO_LARGE_MESSAGE);
        return "redirect:" + safeReturnTo(request);
    }

    /**
     * multipart-часть «file» отсутствует (форма отправлена без файла) —
     * раньше было whitelabel-400. В UI: flash + возврат по Referer/на форму.
     */
    @ExceptionHandler(org.springframework.web.multipart.support.MissingServletRequestPartException.class)
    public String handleMissingPart(HttpServletRequest request,
                                    RedirectAttributes redirectAttributes) {
        redirectAttributes.addFlashAttribute("flashError",
                "Не удалось прочитать файл — выберите CSV-файл и повторите");
        return "redirect:" + safeReturnTo(request);
    }

    /**
     * Безопасный путь возврата из Referer (анти-open-redirect):
     * только same-origin (scheme+host+port совпадают с текущим запросом),
     * путь начинается с {@code /web/}, без «//» и «:» после первого символа.
     * Всё остальное (включая отсутствующий/кривой Referer) — fallback.
     */
    static String safeReturnTo(HttpServletRequest request) {
        String referer = request.getHeader("Referer");
        if (referer == null || referer.isBlank()) {
            return DEFAULT_IMPORT_RETURN;
        }
        try {
            URI refererUri = URI.create(referer);
            boolean sameOrigin = refererUri.getScheme() != null
                    && refererUri.getHost() != null
                    && refererUri.getScheme().equals(request.getScheme())
                    && refererUri.getHost().equalsIgnoreCase(request.getServerName())
                    && refererUri.getPort() == request.getServerPort();
            if (!sameOrigin) {
                return DEFAULT_IMPORT_RETURN;
            }
            String path = refererUri.getPath();
            if (path == null || !path.startsWith("/web/") || path.contains("//")
                    || path.substring(1).contains(":")) {
                return DEFAULT_IMPORT_RETURN;
            }
            return path;
        } catch (IllegalArgumentException e) {
            // Нераспарсиваемый Referer — нейтральный fallback.
            return DEFAULT_IMPORT_RETURN;
        }
    }
}
