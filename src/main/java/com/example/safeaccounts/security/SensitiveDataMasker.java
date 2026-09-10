package com.example.safeaccounts.security;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Маскирование типовых чувствительных полей в тексте (Task-09):
 * password, token, secret, authorization.
 * <p>
 * Применяется ко всем сообщениям об ошибках и любому тексту, который может
 * попасть в логи или ответы клиенту, — чтобы пароли/токены/секреты
 * не утекали в логи при неожиданных сценариях (например, исключение,
 * содержащее тело запроса).
 * <p>
 * Гарантия AGENTS.md: пароли, токены, мастер-ключ и расшифрованные пароли
 * учетных записей никогда не логируются. Маскировщик — «последний рубеж».
 */
public final class SensitiveDataMasker {

    /** Поля, значение которых всегда маскируется. */
    private static final List<Pattern> SENSITIVE_PATTERNS = List.of(
            // JSON-подобные и query-подобные присваивания:
            // "password": "...", password=..., token: '...', Authorization: Basic ...
            Pattern.compile(
                    "(?i)(\"?(?:password|passwd|pwd|secret|token|authorization|api[-_]?key)\"?\\s*[:=]\\s*)(\"[^\"]*\"|'[^']*'|[^,;&\\s}]+)"),
            // Bearer-токены
            Pattern.compile("(?i)(bearer\\s+)([A-Za-z0-9._\\-]+)"),
            // Токены приложения sat_
            Pattern.compile("(sat_)([A-Za-z0-9._\\-]+)")
    );

    private static final String MASK = "***";

    private SensitiveDataMasker() {
    }

    /** Маскирует чувствительные поля в переданном тексте. */
    public static String mask(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String result = input;
        for (Pattern pattern : SENSITIVE_PATTERNS) {
            Matcher matcher = pattern.matcher(result);
            StringBuilder sb = new StringBuilder();
            while (matcher.find()) {
                // Группа 1 — «ключ» (например, password=), группа 2 — значение, маскируем.
                // Кавычки значения сохраняем: {"password":"***"}.
                String prefix = matcher.group(1);
                String value = matcher.group(2);
                String quote = "";
                if (value != null && value.length() >= 2
                        && (value.startsWith("\"") && value.endsWith("\"")
                        || value.startsWith("'") && value.endsWith("'"))) {
                    quote = value.substring(0, 1);
                }
                String replacement = prefix + quote + MASK + quote;
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
            matcher.appendTail(sb);
            result = sb.toString();
        }
        return result;
    }
}
