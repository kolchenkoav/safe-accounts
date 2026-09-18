package com.example.safeaccounts.service;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit-тесты {@link WeakPasswordEvaluator} (G2, план §3.1/§4).
 * Реальные случаи — на настоящем zxcvbn; семантика порога (score &le; weakScore)
 * — на стабе с фиксированным score.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class WeakPasswordEvaluatorTest {

    @Mock
    Zxcvbn zxcvbn;

    private final WeakPasswordEvaluator real = new WeakPasswordEvaluator();

    private static WeakScanConfig cfg(int weakScore) {
        return new WeakScanConfig(weakScore);
    }

    @Test
    void trivialDigitsPasswordIsWeakForManyReasons() {
        List<String> reasons = real.evaluate("123456", 0, cfg(1));
        assertThat(reasons).anyMatch(r -> r.contains("оценка стойкости 0 из 4"))
                .anyMatch(r -> r.contains("Слишком короткий (< 12)"))
                .anyMatch(r -> r.contains("Вырожденный набор символов"));
    }

    @Test
    void dictionaryPasswordIsWeak() {
        List<String> reasons = real.evaluate("password", 0, cfg(1));
        assertThat(reasons).anyMatch(r -> r.contains("Простой пароль"));
    }

    @Test
    void longMixedRandomPasswordIsStrong() {
        List<String> reasons = real.evaluate("Zk9#mQ2$vL8!wR4&xJ6%", 0, cfg(1));
        assertThat(reasons).isEmpty();
    }

    @Test
    void elevenCharactersIsTooShort() {
        List<String> reasons = real.evaluate("Abcdefghi12", 0, cfg(4));
        assertThat(reasons).anyMatch(r -> r.contains("Слишком короткий (< 12)"));
    }

    @Test
    void digitsOnlyIsDegenerateEvenWhenLong() {
        List<String> reasons = real.evaluate("123456789012", 0, cfg(4));
        assertThat(reasons).anyMatch(r -> r.contains("Вырожденный набор символов"));
    }

    @Test
    void lowercaseOnlyIsDegenerate() {
        List<String> reasons = real.evaluate("abcdefghijklmnop", 0, cfg(4));
        assertThat(reasons).anyMatch(r -> r.contains("Вырожденный набор символов"));
    }

    @Test
    void reuseCountTwoMakesPasswordWeak() {
        List<String> reasons = real.evaluate("Zk9#mQ2$vL8!wR4&xJ6%", 2, cfg(4));
        assertThat(reasons).anyMatch(r -> r.contains("Пароль используется в 2 записях"));
    }

    @Test
    void reuseCountOneIsNotAReason() {
        // cfg(0): score 4 выше порога — остаётся проверить, что reuse-причины нет
        assertThat(real.evaluate("Zk9#mQ2$vL8!wR4&xJ6%", 1, cfg(0))).isEmpty();
    }

    /** Семантика порога — именно <=: score 2 слаб при weakScore=2, силён при 1. */
    @Test
    void scoreEqualsThresholdIsWeakOnlyWhenScoreBelowOrEqual() {
        WeakPasswordEvaluator mocked = new WeakPasswordEvaluator(zxcvbn);
        Strength score2 = new Strength();
        score2.setScore(2);
        when(zxcvbn.measure(anyString())).thenReturn(score2);

        assertThat(mocked.evaluate("Some-Passw0rd-Here!", 0, cfg(2)))
                .contains("Простой пароль (оценка стойкости 2 из 4)");
        assertThat(mocked.evaluate("Some-Passw0rd-Here!", 0, cfg(1)))
                .doesNotContain("Простой пароль (оценка стойкости 2 из 4)");
    }

    @Test
    void emptyOrNullPasswordIsNotEvaluated() {
        assertThat(real.evaluate(null, 5, cfg(4))).isEmpty();
        assertThat(real.evaluate("", 5, cfg(4))).isEmpty();
    }
}
