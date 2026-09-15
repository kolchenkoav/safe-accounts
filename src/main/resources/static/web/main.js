/*
 * Общая клиентская логика веб-интерфейса (Фаза 2).
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

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initConfirmations);
    } else {
        initConfirmations();
    }
})();
