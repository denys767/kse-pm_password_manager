package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import ua.kse.passwordmanager.audit.KeycloakEventController;

@SpringBootTest(properties = {"pm.allow-insecure-dev=true", "pm.audit.keycloak-events-secret=test-event-secret"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class KeycloakEventApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void acceptsValidSecretAndMapsKeycloakEvents() throws Exception {
        for (var event : new String[][] {{"LOGIN", "LOGIN"}, {"LOGIN_ERROR", "LOGIN_FAILED"}, {"LOGOUT", "LOGOUT"}}) {
            mockMvc.perform(post("/api/audit/keycloak-events")
                            .header(KeycloakEventController.SECRET_HEADER, "test-event-secret")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"type\":\"%s\",\"email\":\"audit-user@kse.org.ua\",\"details\":\"broker\"}"
                                    .formatted(event[0])))
                    .andExpect(status().isNoContent());
        }
        mockMvc.perform(get("/api/audit").param("size", "200").header("X-Dev-User", "admin@kse.org.ua")
                        .header("X-Dev-Roles", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[?(@.actorEmail == 'audit-user@kse.org.ua')].action",
                        hasItem("LOGIN")))
                .andExpect(jsonPath("$.content[?(@.actorEmail == 'audit-user@kse.org.ua')].action",
                        hasItem("LOGIN_FAILED")))
                .andExpect(jsonPath("$.content[?(@.actorEmail == 'audit-user@kse.org.ua')].action",
                        hasItem("LOGOUT")));
    }

    @Test
    void rejectsMissingOrInvalidSecretAndUnsupportedType() throws Exception {
        String body = "{\"type\":\"LOGIN\",\"email\":\"audit-user@kse.org.ua\"}";
        mockMvc.perform(post("/api/audit/keycloak-events").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/audit/keycloak-events").header(KeycloakEventController.SECRET_HEADER, "wrong")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden());
        mockMvc.perform(post("/api/audit/keycloak-events").header(KeycloakEventController.SECRET_HEADER, "test-event-secret")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"type\":\"UPDATE_PROFILE\",\"email\":\"audit-user@kse.org.ua\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void flagsBurstOfFailedLogins() throws Exception {
        for (int i = 0; i < 6; i++) {
            mockMvc.perform(post("/api/audit/keycloak-events")
                            .header(KeycloakEventController.SECRET_HEADER, "test-event-secret")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"type\":\"LOGIN_ERROR\",\"email\":\"bruteforce@kse.org.ua\"}"))
                    .andExpect(status().isNoContent());
        }
        mockMvc.perform(get("/api/audit/anomalies").header("X-Dev-User", "security@kse.org.ua")
                        .header("X-Dev-Roles", "security"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.actorEmail == 'bruteforce@kse.org.ua')].action",
                        hasItem("LOGIN_FAILED")))
                .andExpect(jsonPath("$[?(@.actorEmail == 'bruteforce@kse.org.ua')].threshold", hasItem(5)));
    }
}
