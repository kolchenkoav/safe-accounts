# Многоэтапная сборка (Task-07): сборка через JDK, runtime через JRE.
# В финальный образ не попадают исходники, .env, секреты и локальные файлы.

# --- Этап 1: сборка (JDK) ---------------------------------------------------
FROM eclipse-temurin:21-jdk-alpine AS build
WORKDIR /workspace

# Кэшируем зависимости Maven: сначала копируем только wrapper и pom.
COPY mvnw ./
COPY .mvn/ .mvn/
COPY pom.xml ./
RUN chmod +x mvnw && ./mvnw -q -B dependency:go-offline

# Копируем только исходники (без .env, секретов, скриптов — см. .dockerignore).
COPY src/ src/
RUN ./mvnw -q -B package -DskipTests && mv target/safe-accounts.jar /safe-accounts.jar

# --- Этап 2: extract слоеного jar (Spring Boot layertools) ------------------
FROM eclipse-temurin:21-jdk-alpine AS extract
WORKDIR /workspace
COPY --from=build /safe-accounts.jar app.jar
RUN java -Djarmode=tools -jar app.jar extract --layers --destination extracted

# --- Этап 3: runtime (JRE) --------------------------------------------------
FROM eclipse-temurin:21-jre-alpine

# Отдельный непривилегированный пользователь и группа.
RUN addgroup -S vault && adduser -S -G vault vault
WORKDIR /app

# Слоеная структура (зависимости меняются реже, чем код приложения).
COPY --from=extract /workspace/extracted/dependencies/ ./
COPY --from=extract /workspace/extracted/spring-boot-loader/ ./
COPY --from=extract /workspace/extracted/snapshot-dependencies/ ./
COPY --from=extract /workspace/extracted/application/ ./

RUN chown -R vault:vault /app
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh && chown root:root /usr/local/bin/docker-entrypoint.sh
USER vault

# Секреты задаются ТОЛЬКО через окружение или файлы секретов (монтируются),
# НИКОГДА — через ENV в Dockerfile.
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
