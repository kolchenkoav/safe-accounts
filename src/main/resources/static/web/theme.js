/*
 * Переключатель темы веб-интерфейса: тёмная (по умолчанию) и светлая.
 *
 * Подключается в <head> БЕЗ defer и применяет сохраненную тему как можно
 * раньше — защита от мигания контента (FOUC). Inline-скрипты в HTML
 * не используются (требование безопасности). Выбор хранится в localStorage:
 * это клиентское хранилище, Cache-Control: no-store статике не мешает.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'theme';
    var root = document.documentElement;

    function storedTheme() {
        try {
            var saved = window.localStorage.getItem(STORAGE_KEY);
            if (saved === 'dark' || saved === 'light') {
                return saved;
            }
        } catch (e) {
            // localStorage может быть недоступен (приватный режим) — игнорируем.
        }
        return null;
    }

    function currentTheme() {
        var attr = root.getAttribute('data-theme');
        if (attr === 'dark' || attr === 'light') {
            return attr;
        }
        // Тёмная — по умолчанию (в CSS :root тоже содержит тёмные значения,
        // поэтому тема применяется даже при выключенном JS).
        return storedTheme() || 'dark';
    }

    function applyTheme(theme) {
        root.setAttribute('data-theme', theme);
        updateToggles(theme);
    }

    function updateToggles(theme) {
        // Подпись кнопки показывает тему, на которую произойдет переход.
        var nextLabel = theme === 'dark' ? 'Светлая' : 'Тёмная';
        var currentState = theme === 'dark' ? 'тёмная' : 'светлая';
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            btn.textContent = nextLabel;
            btn.setAttribute('aria-label',
                'Переключить тему (сейчас ' + currentState + ')');
        });
    }

    function toggleTheme() {
        var next = currentTheme() === 'dark' ? 'light' : 'dark';
        try {
            window.localStorage.setItem(STORAGE_KEY, next);
        } catch (e) {
            // Без localStorage тема применится только до перезагрузки страницы.
        }
        applyTheme(next);
    }

    // Применяем тему как можно раньше (script в <head> без defer).
    applyTheme(currentTheme());

    function initToggles() {
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            btn.addEventListener('click', toggleTheme);
        });
        updateToggles(currentTheme());
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initToggles);
    } else {
        initToggles();
    }
})();
