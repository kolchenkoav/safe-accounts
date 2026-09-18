package com.example.safeaccounts.service;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import org.springframework.validation.annotation.Validated;

/**
 * Конфигурация сканера слабых паролей (G2; план feat-weak-password-scan §3.1,
 * §7.2). Единый источник порога — {@code app.scan.weak-score}.
 */
@Validated
@ConfigurationProperties(prefix = "app.scan")
public class ScanProperties {

    /**
     * Порог стойкости zxcvbn (шкала 0..4): слабым считается пароль с
     * {@code score <= weakScore}. Default 1 (тривиальные и словарные).
     */
    @Min(0)
    @Max(4)
    private int weakScore = 1;

    public int getWeakScore() {
        return weakScore;
    }

    public void setWeakScore(int weakScore) {
        this.weakScore = weakScore;
    }
}
