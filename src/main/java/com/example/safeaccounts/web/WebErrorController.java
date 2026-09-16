package com.example.safeaccounts.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Страница ошибки «файл слишком большой» (Фаза 4, TP B).
 * <p>
 * Регистрируется через {@code ErrorPageRegistrar} (см. web/ErrorPageConfig):
 * Tomcat error-dispatch ловит исключения, брошенные ДО DispatcherServlet —
 * в том числе MaxUploadSizeExceededException из CsrfFilter web-цепочки
 * (Tomcat парсит multipart при {@code getParameter("_csrf")}). Раньше это
 * отдавало whitelabel-500; теперь — тематическая страница.
 * <p>
 * Отдаём 413 (ошибка уровня пользователя, а не сервера) с нейтральным
 * текстом без стектрейса. ERROR-dispatch проходит через security-цепочку
 * (spring.security.filter.dispatcher-types по умолчанию включает ERROR);
 * аутентифицированная сессия пользователя сохраняется.
 */
@Controller
public class WebErrorController {

    /** Единая формулировка про размер (TP A2: контроллер/advice/эта страница). */
    public static final String FILE_TOO_LARGE_MESSAGE =
            "Файл слишком большой (лимит 10 МБ) — уменьшите файл и повторите";

    /**
     * Единый текст превышения лимитов ИМПОРТА (fix-волна A3): размер файла
     * (MAX_CSV_BYTES = 10 МБ) или cumulative-cap (10 000 записей).
     * Чисто-размерная FILE_TOO_LARGE_MESSAGE остаётся для error-page/advice.
     */
    public static final String IMPORT_LIMIT_EXCEEDED_MESSAGE =
            "Файл слишком большой (лимит 10 МБ) или превышен суммарный лимит "
                    + "записей (10 000) — уменьшите файл или очистите записи и повторите";

    @GetMapping("/web/error/file-too-large")
    public String fileTooLarge(HttpServletResponse response, Model model,
                               jakarta.servlet.http.HttpServletRequest request) {
        // Осознанно 413, не 500: пользовательская ошибка загрузки.
        response.setStatus(413);
        model.addAttribute("message", FILE_TOO_LARGE_MESSAGE);
        // Админу — дополнительная ссылка «К списку пользователей» (работает
        // через security-обёртку SecurityContextHolderAwareRequestFilter)
        model.addAttribute("isAdmin", request.isUserInRole("ROLE_ADMIN"));
        return "error-file-too-large";
    }
}
