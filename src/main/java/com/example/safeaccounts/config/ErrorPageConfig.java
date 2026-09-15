package com.example.safeaccounts.config;

import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.server.ErrorPageRegistrar;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Регистрация Tomcat error-page для oversized multipart (Фаза 4, TP B).
 * <p>
 * Страховка для случая, когда Spring-тип MaxUploadSizeExceededException
 * НЕ перехвачен advice ({@code @ControllerAdvice} живёт только внутри
 * DispatcherServlet и не видит исключений из фильтров). Нативные исключения
 * Tomcat из фильтров этим error-page НЕ покрываются — он матчится по
 * Spring-типу исключения. Фактический исход web-oversize — строго 302
 * (advice при падении в резолвере; OversizeUploadIT ассертит именно 302;
 * 413-ветка — страховка этого error-page).
 * <p>
 * Не конфликтует с /error (BasicErrorController): наш путь специфичен
 * по типу исключения и перехватывает его раньше дефолтной страницы.
 */
@Configuration
public class ErrorPageConfig {

    @Bean
    ErrorPageRegistrar fileTooLargeErrorPageRegistrar() {
        return registry -> registry.addErrorPages(new ErrorPage(
                MaxUploadSizeExceededException.class, "/web/error/file-too-large"));
    }
}
