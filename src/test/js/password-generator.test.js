/*
 * Модульные тесты чистой логики генератора паролей (отложенный пункт плана
 * feat-password-generator-copy; plan §2.3 — «node-тесты без фреймворков»).
 *
 * Запуск: node src/test/js/password-generator.test.js
 * (или через Maven: mvnw test — exec-maven-plugin на фазе test).
 *
 * ЧТО ПРОВЕРЯЕТСЯ:
 *  - длина результата всегда равна options.length (в границах 12..64);
 *  - алфавит: только символы разрешённых классов (symbols on/off);
 *  - avoidAmbiguous: ни одного 0/O/1/l/I в выдаче;
 *  - гарантия «>=1 символа из каждого активного класса»;
 *  - randomBelow: все значения < max; равномерность (chi-подобная грубая
 *    проверка: мин/макс частоты корзин в пределах ±30% от средней);
 *  - rejection sampling не зацикливается (100k вызовов — по времени это
 *    миллисекунды; детерминированно быстрые прогоны).
 *
 * crypto.getRandomValues доступен в Node >= 19 как globalThis.crypto.
 */
'use strict';

const pw = require('../../main/resources/static/web/main.js');

let checks = 0;
let failures = 0;

function ok(condition, message) {
    checks++;
    if (!condition) {
        failures++;
        console.error('FAIL: ' + message);
    }
}

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*-_=+?';
const AMBIGUOUS = ['0', 'O', '1', 'l', 'I'];

// -- 1. длина всегда = options.length --------------------------------------
for (const len of [12, 20, 64]) {
    for (let i = 0; i < 50; i++) {
        const value = pw.generatePassword({ length: len });
        ok(value.length === len,
            'length=' + len + ' -> got ' + value.length + ' (' + value + ')');
    }
}

// -- 2. алфавит: только символы разрешённых классов -------------------------
const fullAlphabet = LOWER + UPPER + DIGITS + SYMBOLS;
for (let i = 0; i < 1000; i++) {
    const value = pw.generatePassword({ length: 64 });
    for (const ch of value) {
        ok(fullAlphabet.includes(ch), 'char outside full alphabet: ' + ch);
    }
}

// symbols=off -> ни одного спецсимвола
for (let i = 0; i < 200; i++) {
    const value = pw.generatePassword({ length: 64, includeSymbols: false });
    for (const ch of value) {
        ok(!SYMBOLS.includes(ch), 'symbol leaked with includeSymbols=false: ' + ch);
    }
}

// -- 3. avoidAmbiguous: ни одного 0/O/1/l/I ---------------------------------
for (let i = 0; i < 500; i++) {
    const value = pw.generatePassword({ length: 64 });
    for (const ch of AMBIGUOUS) {
        ok(!value.includes(ch), 'ambiguous char leaked: ' + ch);
    }
}

// -- 4. гарантия ">=1 символа из каждого активного класса" ------------------
const combos = [
    { length: 12 },
    { length: 20, includeSymbols: false },
    { length: 12, avoidAmbiguous: false },
    { length: 64, avoidAmbiguous: true }
];
for (const opts of combos) {
    for (let i = 0; i < 500; i++) {
        const value = pw.generatePassword(opts);
        ok(/[a-z]/.test(value), 'no lowercase: ' + value);
        ok(/[A-Z]/.test(value), 'no uppercase: ' + value);
        ok(/[0-9]/.test(value), 'no digit: ' + value);
        if (opts.includeSymbols !== false) {
            ok(new RegExp('[' + SYMBOLS.replace(/[\\\^\$\*\+\?\.\(\)\|\[\]\{\}]/g, '\\$&') + ']').test(value),
                'no symbol: ' + value);
        }
    }
}

// -- 5. randomBelow: диапазон + равномерность -------------------------------
const buckets = new Array(94).fill(0);
const CALLS = 100000;
for (let i = 0; i < CALLS; i++) {
    const v = pw.randomBelow(94);
    ok(v >= 0 && v < 94, 'randomBelow out of range: ' + v);
    buckets[v]++;
}
const mean = CALLS / 94;
const minFreq = Math.min.apply(null, buckets);
const maxFreq = Math.max.apply(null, buckets);
ok(minFreq >= mean * 0.7, 'bucket min too low: ' + minFreq + ' (mean ' + mean + ')');
ok(maxFreq <= mean * 1.3, 'bucket max too high: ' + maxFreq + ' (mean ' + mean + ')');

// rejection sampling не зацикливается: предыдущий цикл уже прогнал 100k
// вызовов без таймаута — фиксируем дополнительно «выжившие» счётчики.
ok(buckets.reduce(function (a, b) { return a + b; }, 0) === CALLS,
    'rejected call counter mismatch');

console.log('checks=' + checks + ' failures=' + failures);
if (failures > 0) {
    process.exitCode = 1;
}
