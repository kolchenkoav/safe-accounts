package com.example.safeaccounts.service;

import com.nulabinc.zxcvbn.Strength;
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

    public WeakPasswordEvaluator() {
        this(new Zxcvbn());
    }

    /** Пакетный конструктор для детерминированных unit-тестов (стаб zxcvbn). */
    WeakPasswordEvaluator(Zxcvbn zxcvbn) {
        this.zxcvbn = zxcvbn;
    }

    /**
     * @param password   расшифрованный пароль записи (null/пустой = не оценивается,
     *                   G1: пустой пароль при обновлении означает «не менять»)
     * @param reuseCount сколько записей пользователя используют этот же пароль
     * @param cfg        снимок конфигурации скана
     * @return список причин слабости; пустой список = сильный пароль
     */
    public List<String> evaluate(String password, int reuseCount, WeakScanConfig cfg) {
        List<String> reasons = new ArrayList<>();
        if (password == null || password.isEmpty()) {
            return reasons;
        }
        if (reuseCount >= 2) {
            reasons.add("Пароль используется в " + reuseCount + " записях");
        }
        if (password.length() < 12) {
            reasons.add("Слишком короткий (< 12)");
        }
        if (password.matches("\\d+")) {
            reasons.add("Вырожденный набор символов");
        } else if (password.matches("[a-z]+")) {
            reasons.add("Вырожденный набор символов");
        }
        Strength strength = zxcvbn.measure(password);
        int score = strength.getScore();
        if (score <= cfg.weakScore()) {
            reasons.add("Простой пароль (оценка стойкости " + score + " из 4)");
        }
        return reasons;
    }
}
