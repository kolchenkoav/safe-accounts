package com.example.safeaccounts.security;

import com.example.safeaccounts.domain.User;

import java.util.List;
import java.util.UUID;

/**
 * Principal для Bearer-аутентификации: пользователь + id использованного токена.
 * Никаких секретов (хэшей, DEK, сырых токенов) внутри не хранится.
 */
public record AuthUser(User user, UUID tokenId) {

    public UUID getUserId() {
        return user.getId();
    }

    public String getUsername() {
        return user.getUsername();
    }

    /** Authorities для Spring Security (hasRole('ADMIN') и т.п.). */
    public List<org.springframework.security.core.authority.SimpleGrantedAuthority> authorities() {
        return List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority(user.getRole()));
    }
}
