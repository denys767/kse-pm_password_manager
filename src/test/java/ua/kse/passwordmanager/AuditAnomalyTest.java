package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class AuditAnomalyTest {

    private static final String OWNER = "anomaly-owner@kse.org.ua";
    private static final String QUIET_OWNER = "anomaly-quiet@kse.org.ua";
    private static final String ADMIN = "anomaly-admin@kse.org.ua";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }

    private String createItem(String owner, String name) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), owner)
                        .content("""
                                {"name": "%s", "encryptedPassword": "Y2lwaGVy", "passwordIv": "aXY=",
                                 "itemType": "PERSONAL", "syncMode": "SERVER_SYNCED",
                                 "wrappedKey": "b3duZXJLZXk="}
                                """.formatted(name)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    private String shareWithUser(String owner, String itemId, String grantee) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner)
                        .content("""
                                {"granteeType": "USER", "grantee": "%s", "role": "VIEWER",
                                 "wrappedKey": "Z3JhbnRlZQ=="}
                                """.formatted(grantee)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    @Test
    void flagsMassRevokeButNotLightActivity() throws Exception {
        // Light, normal activity must not be flagged.
        String quietItem = createItem(QUIET_OWNER, "Quiet item");
        String quietPermission = shareWithUser(QUIET_OWNER, quietItem, "someone@kse.org.ua");
        mockMvc.perform(as(delete("/api/vault/items/" + quietItem + "/permissions/" + quietPermission),
                        QUIET_OWNER))
                .andExpect(status().isNoContent());

        // A burst of 6 revokes by the same actor exceeds the ACCESS_REVOKED
        // threshold of 5 within the detection window.
        String itemId = createItem(OWNER, "Busy item");
        for (int i = 0; i < 6; i++) {
            String grantee = "grantee" + i + "@kse.org.ua";
            String permissionId = shareWithUser(OWNER, itemId, grantee);
            mockMvc.perform(as(delete("/api/vault/items/" + itemId + "/permissions/" + permissionId), OWNER))
                    .andExpect(status().isNoContent());
        }

        mockMvc.perform(as(get("/api/audit/anomalies"), ADMIN).header("X-Dev-Roles", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.actorEmail == '%s')].action".formatted(OWNER),
                        hasItem("ACCESS_REVOKED")))
                .andExpect(jsonPath("$[?(@.actorEmail == '%s')].count".formatted(OWNER), hasItem(6)))
                .andExpect(jsonPath("$[?(@.actorEmail == '%s')].threshold".formatted(OWNER), hasItem(5)))
                .andExpect(jsonPath("$[?(@.actorEmail == '%s')]".formatted(QUIET_OWNER)).isEmpty());
    }

    @Test
    void anomaliesEndpointIsRestrictedToAdminAndSecurity() throws Exception {
        mockMvc.perform(as(get("/api/audit/anomalies"), OWNER))
                .andExpect(status().isForbidden());
        mockMvc.perform(as(get("/api/audit/anomalies"), ADMIN).header("X-Dev-Roles", "security"))
                .andExpect(status().isOk());
    }
}
