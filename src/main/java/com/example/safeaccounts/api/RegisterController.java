package com.example.safeaccounts.api;

import com.example.safeaccounts.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Регистрация пользователей (Task-04). Самостоятельная регистрация
 * доступна всем (роль ROLE_USER); первые роли ADMIN назначаются только
 * через bootstrap из окружения (AdminBootstrap).
 */
@RestController
@RequestMapping("/api/auth")
public class RegisterController {

    private final UserService userService;

    public RegisterController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request) {
        userService.register(request.username(), request.password(), "ROLE_USER");
        return ResponseEntity.status(201).build();
    }
}
