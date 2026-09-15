package com.example.safeaccounts.service;

import com.example.safeaccounts.domain.Tag;
import com.example.safeaccounts.repository.TagRepository;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Вставка нового тега в ОТДЕЛЬНОЙ транзакции (fix cycle 2, MAJOR-1).
 * <p>
 * Отдельный бин обязателен: {@code @Transactional(REQUIRES_NEW)} не работает
 * при self-invocation — прокси должен перехватить вызов извне.
 * <p>
 * {@link DataIntegrityViolationException} (гонка по UNIQUE(user_id,
 * name_lower)) ПРОПРОГАЦИРУЕТСЯ наружу: внутренняя tx откатится,
 * внешняя останется здоровой — и повторный find в TagService выполнится
 * в рабочей транзакции, а не в aborted (PG 25P02 → JpaSystemException → 500,
 * как было при retry в той же транзакции).
 * <p>
 * Осознанный трейд-офф: тег, созданный в REQUIRES_NEW, закоммитится даже при
 * откате внешней транзакции (возможен «осиротевший» тег без привязки —
 * безвреден, удаляется через /web/tags).
 */
@Component
public class TagInsertHelper {

    private final TagRepository tagRepository;

    public TagInsertHelper(TagRepository tagRepository) {
        this.tagRepository = tagRepository;
    }

    /** INSERT + немедленный flush в независимой транзакции. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Tag insert(Tag tag) {
        return tagRepository.saveAndFlush(tag);
    }
}
