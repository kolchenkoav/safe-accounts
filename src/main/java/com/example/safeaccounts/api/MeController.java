package com.example.safeaccounts.api;

import com.example.safeaccounts.domain.User;
import com.example.safeaccounts.security.AuthUser;
import com.example.safeaccounts.service.TokenService;
import com.example.safeaccounts.service.UserService;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Информация о текущем пользователе и смена пароля (Task-04).
 * Наружу не отдаются хэши, DEK и служебные детали.
 */
@RestController
@RequestMapping("/api/me")
public class MeController {

    private final UserService userService;
    private final TokenService tokenService;

    public MeController(UserService userService, TokenService tokenService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    /** Текущий пользователь по Bearer-токену. */
    @GetMapping
    public MeResponse me(@AuthenticationPrincipal AuthUser principal) {
        return new MeResponse(
                principal.getUserId(),
                principal.getUsername(),
                principal.user().getRole());
    }

    /**
     * Смена пароля. Все токены пользователя отзываются, кроме текущего
     * (решение реализации, разрешено Task-04).
     */
    @PostMapping("/password")
    public ChangePasswordResponse changePassword(@AuthenticationPrincipal AuthUser principal,
                                                 @Valid @RequestBody ChangePasswordRequest request) {
        // Перезагружаем пользователя в текущей персистентной сессии (OSIV выключен).
        User managed = userService.requireUser(principal.getUserId());
        int revoked = userService.changePassword(
                managed,
                request.currentPassword(),
                request.newPassword(),
                principal.tokenId());
        return new ChangePasswordResponse(revoked);
    }
}
