package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Boots the app against a real PostgreSQL with Flyway migrations applied and
 * Hibernate in validate mode — proves the V* scripts match the entity model.
 * CI-gated because it needs a Docker daemon.
 */
@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named = "CI", matches = "true")
@TestPropertySource(properties = {
        // No Keycloak in this test: JwtDecoder is lazy, and we only hit public endpoints.
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9/realms/none",
})
class FlywayMigrationIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Autowired
    private MockMvc mockMvc;

    @Test
    void migrationsMatchTheEntityModel() throws Exception {
        // Context startup already ran Flyway + Hibernate schema validation;
        // a live endpoint call confirms the app is actually serving.
        mockMvc.perform(get("/api/health")).andExpect(status().isOk());
    }
}
