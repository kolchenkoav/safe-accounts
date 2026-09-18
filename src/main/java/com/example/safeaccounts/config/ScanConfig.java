package com.example.safeaccounts.config;

import com.example.safeaccounts.service.ScanProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Регистрация свойств сканера слабых паролей ({@link ScanProperties},
 * G2 плана feat-weak-password-scan).
 */
@Configuration
@EnableConfigurationProperties(ScanProperties.class)
public class ScanConfig {
}
