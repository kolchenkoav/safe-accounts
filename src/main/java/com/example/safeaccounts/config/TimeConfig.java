package com.example.safeaccounts.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * Общие инфраструктурные бины.
 * Clock вынесен в бин для тестируемости времени (TTL токенов, блокировки).
 */
@Configuration(proxyBeanMethods = false)
public class TimeConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
