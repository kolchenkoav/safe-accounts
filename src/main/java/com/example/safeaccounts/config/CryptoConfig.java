package com.example.safeaccounts.config;

import com.example.safeaccounts.crypto.CryptoProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Регистрация свойств криптомодуля (Task-03).
 * Материал ключей задается только через переменные окружения / файлы секретов.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoConfig {
}
