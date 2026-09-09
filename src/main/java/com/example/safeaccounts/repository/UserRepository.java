package com.example.safeaccounts.repository;

import com.example.safeaccounts.domain.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);

    boolean existsByUsernameIgnoreCase(String username);

    /** Используется bootstrap'ом администратора: сработать только на пустой БД. */
    boolean existsBy();

    /** Пагинированный список пользователей для админки (Task-06). */
    Page<User> findAllByOrderByCreatedAtAsc(Pageable pageable);

    /** Пользователи, чей DEK завернут не активным KEK (ротация ключей, Task-06). */
    List<User> findByDekKekIdNot(String kekId);
}
