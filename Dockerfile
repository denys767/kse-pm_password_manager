# Multi-stage build: Maven builds backend + React frontend, JRE-only runtime.
FROM maven:3.9-eclipse-temurin-26 AS build
WORKDIR /app
COPY pom.xml ./
COPY frontend/package.json frontend/package-lock.json frontend/
COPY frontend frontend
COPY src src
RUN mvn -B package -DskipTests

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 1001 app
USER app
COPY --from=build /app/target/password-manager-*.jar /app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
