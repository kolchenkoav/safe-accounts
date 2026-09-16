/*
 * Общая клиентская логика веб-интерфейса (Фаза 2; bfcache-фикс — Фаза 6).
 *
 * Inline-JS в HTML не используется (требование безопасности):
 * подтверждения опасных действий задаются атрибутом data-confirm
 * на <form>, обработчик — здесь. Подключается через fragments :: pageHead
 * с defer (в отличие от theme.js, которому нужен анти-FOUC порядок).
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

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initConfirmations);
    } else {
        initConfirmations();
    }
    initBfcacheRecovery();
})();
