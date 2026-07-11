package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class VaultApiIntegrationTest {

    private static final String ALICE = "alice@kse.org.ua";
    private static final String BOB = "bob@kse.org.ua";
    private static final String ADMIN = "admin@kse.org.ua";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }

    private String itemJson(String name, String itemType, String syncMode) {
        return """
                {
                  "name": "%s",
                  "url": "https://example.com",
                  "username": "login",
                  "encryptedPassword": "Y2lwaGVydGV4dA==",
                  "passwordIv": "aXZpdml2aXZpdg==",
                  "tags": "test",
                  "itemType": "%s",
                  "syncMode": "%s"
                }
                """.formatted(name, itemType, syncMode);
    }

    private String createItem(String owner, String name, String itemType) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), owner)
                        .content(itemJson(name, itemType, "SERVER_SYNCED")))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    @Test
    void healthEndpointIsPublic() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }

    @Test
    void apiRequiresAuthentication() throws Exception {
        mockMvc.perform(get("/api/vault/items"))
                .andExpect(status().isForbidden());
    }

    @Test
    void ownerCanCrudOwnItem() throws Exception {
        String id = createItem(ALICE, "GitHub", "PERSONAL");

        mockMvc.perform(as(get("/api/vault/items"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '%s')].accessRole".formatted(id), hasItem("OWNER")));

        mockMvc.perform(as(get("/api/vault/items/" + id), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("GitHub"))
                .andExpect(jsonPath("$.encryptedPassword").value("Y2lwaGVydGV4dA=="));

        mockMvc.perform(as(put("/api/vault/items/" + id), ALICE)
                        .content(itemJson("GitHub (renamed)", "PERSONAL", "SERVER_SYNCED")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("GitHub (renamed)"));

        mockMvc.perform(as(post("/api/vault/items/" + id + "/copy-event"), ALICE))
                .andExpect(status().isNoContent());

        mockMvc.perform(as(delete("/api/vault/items/" + id), ALICE))
                .andExpect(status().isNoContent());

        mockMvc.perform(as(get("/api/vault/items/" + id), ALICE))
                .andExpect(status().isNotFound());
    }

    @Test
    void otherUsersCannotSeeForeignItems() throws Exception {
        String id = createItem(ALICE, "Secret service", "PERSONAL");

        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isNotFound());
        mockMvc.perform(as(put("/api/vault/items/" + id), BOB)
                        .content(itemJson("Hacked", "PERSONAL", "SERVER_SYNCED")))
                .andExpect(status().isNotFound());
        mockMvc.perform(as(delete("/api/vault/items/" + id), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void sharingGrantsAndRevokesAccess() throws Exception {
        String id = createItem(ALICE, "Team wiki", "PERSONAL");

        String permissionBody = mockMvc.perform(as(post("/api/vault/items/" + id + "/permissions"), ALICE)
                        .content("""
                                {"granteeType": "USER", "grantee": "%s", "role": "VIEWER"}
                                """.formatted(BOB)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        String permissionId = objectMapper.readTree(permissionBody).get("id").asText();

        // Sharing converts the item to SHARED; viewer can read but not edit.
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.itemType").value("SHARED"))
                .andExpect(jsonPath("$.accessRole").value("VIEWER"));
        mockMvc.perform(as(put("/api/vault/items/" + id), BOB)
                        .content(itemJson("Edited by viewer", "SHARED", "SERVER_SYNCED")))
                .andExpect(status().isForbidden());

        // Upgrading to editor allows editing.
        mockMvc.perform(as(post("/api/vault/items/" + id + "/permissions"), ALICE)
                        .content("""
                                {"granteeType": "USER", "grantee": "%s", "role": "EDITOR"}
                                """.formatted(BOB)))
                .andExpect(status().isCreated());
        mockMvc.perform(as(put("/api/vault/items/" + id), BOB)
                        .content(itemJson("Edited by editor", "SHARED", "SERVER_SYNCED")))
                .andExpect(status().isOk());

        // Only the owner manages access.
        mockMvc.perform(as(get("/api/vault/items/" + id + "/permissions"), BOB))
                .andExpect(status().isForbidden());

        mockMvc.perform(as(delete("/api/vault/items/" + id + "/permissions/" + permissionId), ALICE))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void groupSharingGrantsAccessByGroupMembership() throws Exception {
        String id = createItem(ALICE, "Infra credentials", "PERSONAL");

        mockMvc.perform(as(post("/api/vault/items/" + id + "/permissions"), ALICE)
                        .content("""
                                {"granteeType": "GROUP", "grantee": "dev-team", "role": "VIEWER"}
                                """))
                .andExpect(status().isCreated());

        mockMvc.perform(as(get("/api/vault/items/" + id), BOB).header("X-Dev-Groups", "dev-team"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessRole").value("VIEWER"));
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void localOnlyItemsAreNeverStoredOnServer() throws Exception {
        mockMvc.perform(as(post("/api/vault/items"), ALICE)
                        .content(itemJson("Local secret", "PERSONAL", "LOCAL_ONLY")))
                .andExpect(status().isBadRequest());
        mockMvc.perform(as(post("/api/vault/items"), ALICE)
                        .content(itemJson("Shared local", "SHARED", "LOCAL_ONLY")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void syncModeToggleRemovesPersonalItemFromServerButNotShared() throws Exception {
        String personalId = createItem(ALICE, "My personal", "PERSONAL");
        mockMvc.perform(as(patch("/api/vault/items/" + personalId + "/sync-mode"), ALICE)
                        .content("{\"syncMode\": \"LOCAL_ONLY\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.syncMode").value("LOCAL_ONLY"));
        mockMvc.perform(as(get("/api/vault/items/" + personalId), ALICE))
                .andExpect(status().isNotFound());

        String sharedId = createItem(ALICE, "Team shared", "SHARED");
        mockMvc.perform(as(patch("/api/vault/items/" + sharedId + "/sync-mode"), ALICE)
                        .content("{\"syncMode\": \"LOCAL_ONLY\"}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void auditLogIsRestrictedToAdminAndSecurityRoles() throws Exception {
        String id = createItem(ALICE, "Audited item", "PERSONAL");
        mockMvc.perform(as(get("/api/vault/items/" + id), ALICE))
                .andExpect(status().isOk());

        mockMvc.perform(as(get("/api/audit"), ALICE))
                .andExpect(status().isForbidden());

        mockMvc.perform(as(get("/api/audit"), ADMIN).header("X-Dev-Roles", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThan(1))))
                .andExpect(jsonPath("$[*].action", hasItem("ITEM_CREATED")))
                .andExpect(jsonPath("$[*].action", hasItem("ITEM_VIEWED")));

        mockMvc.perform(as(get("/api/audit"), ADMIN).header("X-Dev-Roles", "security"))
                .andExpect(status().isOk());
    }

    @Test
    void settingsRoundTrip() throws Exception {
        mockMvc.perform(as(get("/api/settings"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.defaultSyncMode").value("SERVER_SYNCED"))
                .andExpect(jsonPath("$.clipboardClearSeconds").value(20));

        mockMvc.perform(as(put("/api/settings"), ALICE)
                        .content("{\"defaultSyncMode\": \"LOCAL_ONLY\", \"clipboardClearSeconds\": 30}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.clipboardClearSeconds").value(30));

        mockMvc.perform(as(get("/api/settings"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.defaultSyncMode").value("LOCAL_ONLY"));
    }

    @Test
    void meEndpointReturnsIdentity() throws Exception {
        mockMvc.perform(as(get("/api/me"), ALICE)
                        .header("X-Dev-Roles", "user,admin")
                        .header("X-Dev-Groups", "dev-team"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(ALICE))
                .andExpect(jsonPath("$.roles", hasItem("ADMIN")))
                .andExpect(jsonPath("$.groups", hasItem("dev-team")));
    }
}
