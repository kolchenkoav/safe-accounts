package com.example.safeaccounts.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.dependencies.SlicesRuleDefinition.slices;

/**
 * Архитектурные правила структуры пакетов (P4 рефакторинга, ArchUnit).
 * Пиннят состояние ПОСЛЕ P1–P3: правила — страховка от регрессий при
 * будущих фичах, каждое с обоснованием. Тесты исключены из анализа.
 * <p>
 * Важно: пакеты задаются ТОЧНЫМИ префиксами
 * ({@code com.example.safeaccounts.api..} и т.п.), а не двойными
 * wildcard-ами ({@code ..web..}) — последние матчат и сторонние пакеты
 * вроде {@code org.springframework.web.*} (аннотации контроллеров).
 */
@AnalyzeClasses(packages = "com.example.safeaccounts",
        importOptions = ImportOption.DoNotIncludeTests.class)
class ArchitectureTest {

    /**
     * (а) Топ-уровневые пакеты (включая под-пакеты вида service.csv) без
     * циклов зависимостей. До P1 существовал единственный цикл
     * service ⇄ security (BearerTokenAuthenticationFilter → TokenService
     * при service → security.{AuthUser,PasswordHasher,...}); после P1
     * (AuthTokenResolver в security) циклов нет.
     */
    @ArchTest
    static final ArchRule topLevelPackagesAreFreeOfCycles =
            slices().matching("com.example.safeaccounts.(*)..")
                    .should().beFreeOfCycles();

    /**
     * (б-1) api не зависит от web: REST и Thymeleaf-UI — параллельные слои
     * поверх service; web-страницы не возвращаются из API.
     */
    @ArchTest
    static final ArchRule apiDoesNotDependOnWeb =
            noClasses().that().resideInAPackage("com.example.safeaccounts.api..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.example.safeaccounts.web..");

    /**
     * (б-2) web не зависит от api: web-контроллеры зовут сервисы напрямую,
     * а не REST-эндпоинты (план frontend, §2.1).
     */
    @ArchTest
    static final ArchRule webDoesNotDependOnApi =
            noClasses().that().resideInAPackage("com.example.safeaccounts.web..")
                    .should().dependOnClassesThat()
                    .resideInAPackage("com.example.safeaccounts.api..");

    /**
     * (в) api и web не зависят от repository и audit (после P2:
     * requireUserById в AdminService заменил прямой доступ контроллеров к
     * UserRepository; audit — сервисный слой записи событий, контроллеры
     * данные/события получают через сервисы). Контроллеры — тонкие.
     */
    @ArchTest
    static final ArchRule controllersDoNotTouchRepositories =
            noClasses().that().resideInAnyPackage(
                            "com.example.safeaccounts.api..",
                            "com.example.safeaccounts.web..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.repository..",
                            "com.example.safeaccounts.audit..");

    /**
     * (г) domain и repository — листовые слои: зависят только друг от друга
     * (JPA-аннотации на сущностях), JDK (java..), Jakarta EE (jakarta..),
     * Spring (spring-data репозитории, stereotype @Repository) и Hibernate
     * (аннотации/типы маппинга сущности AuditEvent — листовость сохраняется).
     */
    @ArchTest
    static final ArchRule domainAndRepositoryAreLeafLayers =
            classes().that().resideInAnyPackage(
                            "com.example.safeaccounts.domain..",
                            "com.example.safeaccounts.repository..")
                    .should().onlyDependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.domain..",
                            "com.example.safeaccounts.repository..",
                            "java..", "jakarta..",
                            "org.springframework..",
                            "org.hibernate.annotations..", "org.hibernate.type..");

    /**
     * (д) security — листовой слой (после P1): не зависит от service;
     * зависимости ограничены доменом, JDK, Jakarta, Spring Security,
     * slf4j (логи), BouncyCastle (Argon2 в PasswordHasher) и Jackson
     * (сериализация ProblemDetail в RateLimitFilter).
     */
    @ArchTest
    static final ArchRule securityIsLeafLayer =
            classes().that().resideInAPackage("com.example.safeaccounts.security..")
                    .should().onlyDependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.security..",
                            "com.example.safeaccounts.domain..",
                            "java..", "javax..", "jakarta..",
                            "org.springframework..", "org.slf4j..",
                            "org.bouncycastle..", "com.fasterxml.jackson..");

    /**
     * (B1) config не зависит от api/web: после P3 (ErrorPageConfig → web)
     * конфигурация не знает URL/классы web-слоя; пинним отсутствие
     * строковой связки config→web.
     */
    @ArchTest
    static final ArchRule configDoesNotDependOnControllers =
            noClasses().that().resideInAPackage("com.example.safeaccounts.config..")
                    .should().dependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.api..",
                            "com.example.safeaccounts.web..");

    /**
     * (B2) audit — листовой слой: AuditService зависит только от домена,
     * репозитория и инфраструктуры (по фактическим импортам: slf4j, Jackson
     * для detailsJson, Spring/Spring Data).
     */
    @ArchTest
    static final ArchRule auditIsLeafLayer =
            classes().that().resideInAPackage("com.example.safeaccounts.audit..")
                    .should().onlyDependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.audit..",
                            "com.example.safeaccounts.domain..",
                            "com.example.safeaccounts.repository..",
                            "java..", "jakarta..",
                            "org.springframework..", "org.slf4j..",
                            "com.fasterxml.jackson..");

    /**
     * (B3) crypto — листовой слой: в настоящее время 0 проектных рёбер;
     * зависимости — JDK (включая javax.crypto — им не покрыт java..),
     * Spring (@Component/@Value), slf4j.
     */
    @ArchTest
    static final ArchRule cryptoIsLeafLayer =
            classes().that().resideInAPackage("com.example.safeaccounts.crypto..")
                    .should().onlyDependOnClassesThat().resideInAnyPackage(
                            "com.example.safeaccounts.crypto..",
                            "java..", "javax..", "jakarta..",
                            "org.springframework..", "org.slf4j..");
}
