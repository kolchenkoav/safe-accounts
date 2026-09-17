/*
 * Общая клиентская логика веб-интерфейса (Фаза 2; bfcache-фикс — Фаза 6;
 * генератор пароля — Фаза 1 плана feat-password-generator-copy).
 *
 * Inline-JS в HTML не используется (требование безопасности, CSP-friendly):
 * подтверждения опасных действий задаются атрибутом data-confirm на <form>,
 * генератор и глаз — data-атрибутами на контролах; обработчики — здесь.
 * Подключается через fragments :: pageHead с defer (в отличие от theme.js,
 * которому нужен анти-FOUC порядок).
 */
(function () {
    'use strict';

    function initConfirmations() {
        document.querySelectorAll('form[data-confirm]').forEach(function (form) {
            form.addEventListener('submit', function (event) {
                if (!window.confirm(form.getAttribute('data-confirm'))) {
                    event.preventDefault();
                }
            });
        });
    }

    /* bfcache (fix F3): Safari игнорирует no-store в back/forward cache —
       при возврате на страницу фильтра select может остаться disabled
       (после сабмита). Явно снимаем disabled; политику пустого value
       не пере-применяем — страница из bfcache уже отражает состояние
       на момент ухода. */
    function initBfcacheRecovery() {
        window.addEventListener('pageshow', function (event) {
            if (event.persisted) {
                document.querySelectorAll('select:disabled').forEach(function (select) {
                    select.disabled = false;
                });
            }
        });
    }

    /* ------------------------------------------------------------------
     * Генератор пароля (Фаза 1, план feat-password-generator-copy §2).
     *
     * generatePassword(options) — ЧИСТАЯ функция (детерминированно
     * тестируема; JS-раннера тестов в проекте нет — покрыто разметочными
     * IT + ручным smoke). Опции:
     *   length          12–64, default 20;
     *   includeSymbols  default true — класс `!@#$%^&*-_=+?`;
     *   avoidAmbiguous  default true — исключить `0 O 1 l I |` из ВСЕХ
     *                   классов (без заглушек: классы просто без них).
     *
     * Равномерность: crypto.getRandomValues(Uint32Array) + rejection
     * sampling (отбрасываем значения >= floor(2^32/len)*len) — без
     * modulo-bias. Гарантия: >=1 символ из каждого активного класса
     * (замена случайных позиций), затем Fisher-Yates shuffle тем же RNG.
     * Ничего не логируется: console.log паролей запрещён.
     * ------------------------------------------------------------------ */
    var PW_SYMBOLS = '!@#$%^&*-_=+?';
    var PW_DEFAULT_LENGTH = 20;
    var PW_MIN_LENGTH = 12;
    var PW_MAX_LENGTH = 64;

    function removeChars(alphabet, chars) {
        var out = '';
        for (var i = 0; i < alphabet.length; i++) {
            if (chars.indexOf(alphabet.charAt(i)) === -1) {
                out += alphabet.charAt(i);
            }
        }
        return out;
    }

    /* Равномерное целое [0, maxExclusive): rejection sampling. */
    function randomBelow(maxExclusive) {
        var limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
        var buf = new Uint32Array(1);
        do {
            crypto.getRandomValues(buf);
        } while (buf[0] >= limit);
        return buf[0] % maxExclusive;
    }

    function pickRandom(alphabet) {
        return alphabet.charAt(randomBelow(alphabet.length));
    }

    function fisherYatesShuffle(arr) {
        for (var i = arr.length - 1; i > 0; i--) {
            var j = randomBelow(i + 1);
            var tmp = arr[i];
            arr[i] = arr[j];
            arr[j] = tmp;
        }
    }

    function generatePassword(options) {
        var opts = options || {};
        var length = Math.floor(Number(opts.length));
        if (!isFinite(length)) {
            length = PW_DEFAULT_LENGTH;
        }
        length = Math.min(PW_MAX_LENGTH, Math.max(PW_MIN_LENGTH, length));
        var includeSymbols = opts.includeSymbols !== false;
        var avoidAmbiguous = opts.avoidAmbiguous !== false;

        var lower = 'abcdefghijklmnopqrstuvwxyz';
        var upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        var digits = '0123456789';
        if (avoidAmbiguous) {
            lower = removeChars(lower, '01l');
            upper = removeChars(upper, 'OI');
            digits = removeChars(digits, '01');
        }

        var classes = [lower, upper, digits];
        if (includeSymbols) {
            classes.push(PW_SYMBOLS);
        }
        // Страховка от пустого класса (не должен случиться: 0/1/l уходят из
        // digits/lower, O/I — из upper, но фильтр дешёвый и защищает будущее).
        classes = classes.filter(function (chars) { return chars.length > 0; });

        var alphabet = classes.join('');
        var result = [];
        for (var i = 0; i < classes.length; i++) {
            result.push(pickRandom(classes[i]));
        }
        while (result.length < length) {
            result.push(pickRandom(alphabet));
        }
        fisherYatesShuffle(result);
        return result.join('');
    }

    function readGeneratorOptions(form) {
        var lengthInput = form.querySelector('[data-pw-length]');
        var symbolsInput = form.querySelector('[data-pw-symbols]');
        var avoidInput = form.querySelector('[data-pw-avoid-ambiguous]');
        return {
            length: lengthInput ? Number(lengthInput.value) : PW_DEFAULT_LENGTH,
            includeSymbols: symbolsInput ? symbolsInput.checked : true,
            avoidAmbiguous: avoidInput ? avoidInput.checked : true
        };
    }

    function syncVisibilityLabel(input) {
        var form = input.closest('form');
        var toggle = form ? form.querySelector('[data-toggle-password]') : null;
        if (toggle) {
            toggle.textContent = input.type === 'password' ? 'Показать' : 'Скрыть';
        }
    }

    /* Глаз: toggle type password/text у связанного input[data-password-field]
       в той же форме. «Сгенерировать»: пароль в поле + принудительно
       type=text — пользователь должен видеть, что сгенерировано. */
    function initPasswordTools() {
        document.querySelectorAll('[data-toggle-password]').forEach(function (button) {
            button.addEventListener('click', function () {
                var form = button.closest('form');
                var input = form ? form.querySelector('input[data-password-field]') : null;
                if (!input) {
                    return;
                }
                input.type = input.type === 'password' ? 'text' : 'password';
                syncVisibilityLabel(input);
            });
        });

        document.querySelectorAll('[data-generate-password]').forEach(function (button) {
            button.addEventListener('click', function () {
                var form = button.closest('form');
                var input = form ? form.querySelector('input[data-password-field]') : null;
                if (!input) {
                    return;
                }
                input.value = generatePassword(readGeneratorOptions(form));
                input.type = 'text';
                syncVisibilityLabel(input);
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            initConfirmations();
            initPasswordTools();
        });
    } else {
        initConfirmations();
        initPasswordTools();
    }
    initBfcacheRecovery();
})();
