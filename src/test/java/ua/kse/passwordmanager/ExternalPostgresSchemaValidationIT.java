package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * The same guarantee as {@link FlywayMigrationIT} — Flyway's V* scripts produce
 * a schema Hibernate's {@code validate} mode accepts — for environments where
 * Testcontainers cannot reach the Docker daemon even though Docker is running.
 *
 * <p>Point {@code PM_TEST_POSTGRES_URL} at a throwaway PostgreSQL and this runs;
 * leave it unset and it is skipped. Migrations are applied by Flyway on boot,
 * so the database only has to be empty.
 */
@SpringBootTest
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "PM_TEST_POSTGRES_URL", matches = ".+")
@TestPropertySource(properties = {
        "spring.datasource.url=${PM_TEST_POSTGRES_URL}",
        "spring.datasource.username=${PM_TEST_POSTGRES_USER:postgres}",
        "spring.datasource.password=${PM_TEST_POSTGRES_PASSWORD:postgres}",
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        // No Keycloak in this test: JwtDecoder is lazy, and we only hit public endpoints.
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9/realms/none",
})
class ExternalPostgresSchemaValidationIT {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void migrationsProduceASchemaTheEntityModelValidatesAgainst() throws Exception {
        // Reaching a request at all means the context started, which means
        // Flyway ran every migration and Hibernate validated every mapping.
        mockMvc.perform(get("/api/health")).andExpect(status().isOk());
    }
}
