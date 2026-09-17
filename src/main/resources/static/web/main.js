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

    /* ------------------------------------------------------------------
     * Копирование в буфер (Фаза 2, план feat-password-generator-copy §3).
     *
     * copyToClipboard(text) → Promise<boolean>: сначала navigator.clipboard
     * (доступен только в secure context), при исключении/отсутствии —
     * fallback: временный textarea вне вьюпорта + execCommand('copy')
     * (deprecated, но работает на HTTP-деплое NAS). Двойной отказ → false.
     * showToast(message, kind): контейнер .toast-container в body
     * (создаётся лениво), .toast .toast-ok/.toast-error, авто-скрытие 2.5 с.
     * Никаких alert(); console.log значений нет.
     * ------------------------------------------------------------------ */
    var TOAST_HIDE_DELAY_MS = 2500;
    var TOAST_FADE_MS = 300;

    async function copyToClipboard(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (e) {
            /* secure context отсутствует или доступ запрещен — fallback ниже */
        }
        return copyViaExecCommand(text);
    }

    function copyViaExecCommand(text) {
        var textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        var ok = false;
        try {
            ok = document.execCommand('copy');
        } catch (e) {
            ok = false;
        }
        document.body.removeChild(textarea);
        return ok;
    }

    function showToast(message, kind) {
        var container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        var toast = document.createElement('div');
        toast.className = 'toast ' + (kind === 'error' ? 'toast-error' : 'toast-ok');
        toast.textContent = message;
        container.appendChild(toast);
        window.setTimeout(function () {
            toast.classList.add('toast-hide');
            window.setTimeout(function () {
                toast.remove();
            }, TOAST_FADE_MS);
        }, TOAST_HIDE_DELAY_MS);
    }

    /* Кнопки [data-copy-field="login"|"password"]: значение берется из
       ближайшего dd. Логин — текст span в dd (всегда в DOM). Пароль —
       span[data-secret-value] в dd: этот span рендерится ТОЛЬКО в
       revealed-ветке (появляется вместе с кнопкой пароля), поэтому пароль
       не попадает в data-атрибуты и не виден до явного POST /reveal
       (аудит SECRET_REVEALED пишет сервер). */
    function initClipboardButtons() {
        document.querySelectorAll('[data-copy-field]').forEach(function (button) {
            button.addEventListener('click', function () {
                var field = button.getAttribute('data-copy-field');
                var dd = button.closest('dd');
                var value = '';
                if (dd) {
                    if (field === 'password') {
                        var secret = dd.querySelector('[data-secret-value]');
                        value = secret ? secret.textContent : '';
                    } else {
                        var valueSpan = dd.querySelector('span');
                        value = valueSpan ? valueSpan.textContent : '';
                    }
                }
                if (!value) {
                    showToast('Нечего копировать — значение не найдено', 'error');
                    return;
                }
                copyToClipboard(value).then(function (ok) {
                    if (ok) {
                        showToast(field === 'password' ? 'Пароль скопирован' : 'Логин скопирован', 'ok');
                    } else {
                        showToast('Не удалось скопировать', 'error');
                    }
                });
            });
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            initConfirmations();
            initPasswordTools();
            initClipboardButtons();
        });
    } else {
        initConfirmations();
        initPasswordTools();
        initClipboardButtons();
    }
    initBfcacheRecovery();
})();
