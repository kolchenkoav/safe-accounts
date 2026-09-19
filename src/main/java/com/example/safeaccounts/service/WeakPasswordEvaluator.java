package com.example.safeaccounts.service;

import com.nulabinc.zxcvbn.Zxcvbn;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Чистая логика классификации слабого пароля (G2, план feat-weak-password-scan
 * §3.1). Без БД, без секретов, офлайн-оценка через zxcvbn4j.
 *
 * <p>Запись считается <b>слабой</b>, если выполнен хотя бы один критерий:
 * <ol>
 *   <li>zxcvbn score &le; {@code cfg.weakScore()} (default 1);</li>
 *   <li>длина &lt; 12 — «слишком короткий»;</li>
 *   <li>вырожденный набор символов: только цифры или только строчные;</li>
 *   <li>повторное использование: {@code reuseCount >= 2}.</li>
 * </ol>
 *
 * <p>Причины — человекочитаемые строки, <b>сам пароль в них и в логах не
 * появляется</b> (в отчёт попадают только владельцу/админу).
 */
@Component
public class WeakPasswordEvaluator {

    private final Zxcvbn zxcvbn;

    /** Выше этой длины zxcvbn не вызывается (DoS-гвард, см. evaluate). */
    public static final int MAX_ZXCVBN_LENGTH = 200;

    public WeakPasswordEvaluator() {
        this(new Zxcvbn());
    }

    /** Пакетный конструктор для детерминированных unit-тестов (стаб zxcvbn). */
    WeakPasswordEvaluator(Zxcvbn zxcvbn) {
        this.zxcvbn = zxcvbn;
    }

    /**
     * Чистая оценка + score (для CSV-отчёта): null в score = пароль длиннее
     * гварда zxcvbn ({@link #MAX_ZXCVBN_LENGTH}) и стойкость не измерялась.
     *
     * <p>ЕДИНСТВЕННОЕ место вызова zxcvbn (fix CPU ×2): раньше
     * {@code evaluateDetailed} звал {@code evaluate()} (measure №1) и делал
     * ещё один measure №2 — а zxcvbn.measure() — самый дорогой шаг скана.
     *
     * <p>zxcvbn-DoS гвард (fix CRITICAL): сложность measure() ~ O(n²) —
     * 4096 симв ≈ 123 c, что делает скан DoS-able. Пароли длиннее 200
     * символов по score не оцениваются: такой пароль заведомо не слабый
     * по score; оценка по длине/charset/reuse остаётся.
     */
    public EvalResult evaluateDetailed(String password, int reuseCount, WeakScanConfig cfg) {
        List<String> reasons = new ArrayList<>();
        Integer score = null;
        if (password == null || password.isEmpty()) {
            return new EvalResult(reasons, null);
        }
        if (reuseCount >= 2) {
            // Русская плюрализация: 1 запись (кроме 11), иначе — записями.
            reasons.add("Пароль используется в " + reuseCount
                    + (reuseCount % 10 == 1 && reuseCount % 100 != 11
                            ? " записи" : " записях"));
        }
        if (password.length() < 12) {
            // без символа '<' — текст попадает в HTML-отчёт (th:text экранирует,
            // но «< 12» в сообщении затрудняет строковые ассерты)
            reasons.add("Слишком короткий (меньше 12 символов)");
        }
        if (password.matches("\\d+")) {
            reasons.add("Вырожденный набор символов");
        } else if (password.matches("[a-z]+")) {
            reasons.add("Вырожденный набор символов");
        }
        if (password.length() <= MAX_ZXCVBN_LENGTH) {
            score = zxcvbn.measure(password).getScore();
            if (score <= cfg.weakScore()) {
                reasons.add("Простой пароль (оценка стойкости " + score + " из 4)");
            }
        }
        return new EvalResult(reasons, score);
    }

    /** Результат детальной оценки: причины + score (null = не измерялся). */
    public record EvalResult(List<String> reasons, Integer score) {
    }

    /**
     * @param password   расшифрованный пароль записи (null/пустой = не оценивается,
     *                   G1: пустой пароль при обновлении означает «не менять»)
     * @param reuseCount сколько записей пользователя используют этот же пароль
     * @param cfg        снимок конфигурации скана
     * @return список причин слабости; пустой список = сильный пароль
     */
    public List<String> evaluate(String password, int reuseCount, WeakScanConfig cfg) {
        // Делегирование: один вызов measure() на пароль — вся логика (включая
        // DoS-гвард) живёт в evaluateDetailed, дубли больше нет.
        return evaluateDetailed(password, reuseCount, cfg).reasons();
    }
}
