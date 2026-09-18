package com.example.safeaccounts.service;

/**
 * Снимок конфигурации сканера на момент запуска (передается в
 * {@link WeakPasswordEvaluator#evaluate}, чтобы решение было детерминированным
 * на весь скан, а не менялось между записями при изменении свойств).
 *
 * @param weakScore порог стойкости zxcvbn (0..4): слабым считается score &le; порога
 */
public record WeakScanConfig(int weakScore) {

    public static final WeakScanConfig DEFAULT = new WeakScanConfig(1);
}
