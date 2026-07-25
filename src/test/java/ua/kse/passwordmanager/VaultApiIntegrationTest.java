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

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
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
                  "syncMode": "%s",
                  "wrappedKey": "b3duZXJXcmFwcGVkS2V5"
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

    private String shareWithUser(String owner, String itemId, String grantee, String role)
            throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner)
                        .content("""
                                {"granteeType": "USER", "grantee": "%s", "role": "%s",
                                 "wrappedKey": "Z3JhbnRlZVdyYXBwZWRLZXk="}
                                """.formatted(grantee, role)))
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
                .andExpect(jsonPath("$[?(@.id == '%s')].accessRole".formatted(id), hasItem("OWNER")))
                .andExpect(jsonPath("$[?(@.id == '%s')].wrappedKey".formatted(id),
                        hasItem("b3duZXJXcmFwcGVkS2V5")));

        mockMvc.perform(as(get("/api/vault/items/" + id), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("GitHub"))
                .andExpect(jsonPath("$.encryptedPassword").value("Y2lwaGVydGV4dA=="))
                .andExpect(jsonPath("$.wrappedKey").value("b3duZXJXcmFwcGVkS2V5"));

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
    void storesOnlyTemplateDiscriminatorAndReturnsIt() throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), ALICE)
                        .content("""
                                {"name":"Deploy key","encryptedPassword":"Y2lwaGVydGV4dA==",
                                 "passwordIv":"aXZpdml2aXZpdg==",
                                 "encryptedNotes":"ZW5jcnlwdGVkLXBheWxvYWQ=","notesIv":"aXY=",
                                 "type":"SSH_KEY","itemType":"PERSONAL","syncMode":"SERVER_SYNCED",
                                 "wrappedKey":"b3duZXJXcmFwcGVkS2V5"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.type").value("SSH_KEY"))
                .andReturn().getResponse().getContentAsString();
        String id = objectMapper.readTree(body).get("id").asText();

        mockMvc.perform(as(get("/api/vault/items/" + id), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("SSH_KEY"))
                .andExpect(jsonPath("$.encryptedNotes").value("ZW5jcnlwdGVkLXBheWxvYWQ="));
    }

    @Test
    void secretTypeIsImmutableAndSupportsDatabaseTemplate() throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), ALICE)
                        .content("""
                                {"name":"Primary DB","encryptedPassword":"Y2lwaGVydGV4dA==","passwordIv":"aXY=",
                                 "type":"DATABASE","itemType":"PERSONAL","syncMode":"SERVER_SYNCED",
                                 "wrappedKey":"b3duZXJXcmFwcGVkS2V5"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.type").value("DATABASE"))
                .andReturn().getResponse().getContentAsString();
        String id = objectMapper.readTree(body).get("id").asText();

        mockMvc.perform(as(put("/api/vault/items/" + id), ALICE)
                        .content(itemJson("Primary DB", "PERSONAL", "SERVER_SYNCED")
                                .replace("\"syncMode\"", "\"type\":\"LOGIN\", \"syncMode\"")))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createRequiresWrappedKey() throws Exception {
        mockMvc.perform(as(post("/api/vault/items"), ALICE)
                        .content("""
                                {"name": "No key", "encryptedPassword": "YQ==", "passwordIv": "aXY=",
                                 "itemType": "PERSONAL", "syncMode": "SERVER_SYNCED"}
                                """))
                .andExpect(status().isBadRequest());
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
        String permissionId = shareWithUser(ALICE, id, BOB, "VIEWER");

        // Sharing converts the item to SHARED; viewer gets their wrapped key.
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.itemType").value("SHARED"))
                .andExpect(jsonPath("$.accessRole").value("VIEWER"))
                .andExpect(jsonPath("$.wrappedKey").value("Z3JhbnRlZVdyYXBwZWRLZXk="));
        mockMvc.perform(as(put("/api/vault/items/" + id), BOB)
                        .content(itemJson("Edited by viewer", "SHARED", "SERVER_SYNCED")))
                .andExpect(status().isForbidden());

        // Upgrading to editor allows editing.
        shareWithUser(ALICE, id, BOB, "EDITOR");
        mockMvc.perform(as(put("/api/vault/items/" + id), BOB)
                        .content(itemJson("Edited by editor", "SHARED", "SERVER_SYNCED")))
                .andExpect(status().isOk());

        // Editors may inspect the current grants because they may add shares,
        // but only the owner may revoke or transfer them.
        mockMvc.perform(as(get("/api/vault/items/" + id + "/permissions"), BOB))
                .andExpect(status().isOk());

        mockMvc.perform(as(delete("/api/vault/items/" + id + "/permissions/" + permissionId), ALICE))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void userShareRequiresWrappedKey() throws Exception {
        String id = createItem(ALICE, "Needs key", "PERSONAL");
        mockMvc.perform(as(post("/api/vault/items/" + id + "/permissions"), ALICE)
                        .content("""
                                {"granteeType": "USER", "grantee": "%s", "role": "VIEWER"}
                                """.formatted(BOB)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void legacyKeycloakGroupShareIsRejected() throws Exception {
        String id = createItem(ALICE, "Infra credentials", "PERSONAL");

        mockMvc.perform(as(post("/api/vault/items/" + id + "/permissions"), ALICE)
                .content("""
                                {"granteeType": "GROUP", "grantee": "dev-team", "role": "VIEWER"}
                                """))
                .andExpect(status().isBadRequest());
        // A group claim in the Keycloak/dev token no longer grants visibility.
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB).header("X-Dev-Groups", "dev-team"))
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
                .andExpect(jsonPath("$.content", hasSize(greaterThan(1))))
                .andExpect(jsonPath("$.totalElements", org.hamcrest.Matchers.greaterThan(1)))
                .andExpect(jsonPath("$.content[*].action", hasItem("ITEM_CREATED")))
                .andExpect(jsonPath("$.content[*].action", hasItem("ITEM_VIEWED")));

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

    @Test
    void updateSnapshotsPreviousVersion() throws Exception {
        String id = createItem(ALICE, "Versioned", "PERSONAL");

        mockMvc.perform(as(get("/api/vault/items/" + id + "/versions"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));

        mockMvc.perform(as(put("/api/vault/items/" + id), ALICE)
                        .content(itemJson("Versioned v2", "PERSONAL", "SERVER_SYNCED")))
                .andExpect(status().isOk());

        mockMvc.perform(as(get("/api/vault/items/" + id + "/versions"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].name").value("Versioned"))
                .andExpect(jsonPath("$[0].replacedBy").value(ALICE))
                .andExpect(jsonPath("$[0].encryptedPassword").value("Y2lwaGVydGV4dA=="));

        // Version history follows item access rules.
        mockMvc.perform(as(get("/api/vault/items/" + id + "/versions"), BOB))
                .andExpect(status().isNotFound());

        // Deleting the item removes its history too.
        mockMvc.perform(as(delete("/api/vault/items/" + id), ALICE))
                .andExpect(status().isNoContent());
    }

    @Test
    void rotateKeyReplacesCiphertextAndDropsUnlistedHolders() throws Exception {
        String carol = "carol-rot@kse.org.ua";
        String id = createItem(ALICE, "Rotated secret", "PERSONAL");
        shareWithUser(ALICE, id, BOB, "VIEWER");
        shareWithUser(ALICE, id, carol, "VIEWER");

        String rotateBody = """
                {
                  "encryptedPassword": "bmV3Q2lwaGVy",
                  "passwordIv": "bmV3SXY=",
                  "wrappedKeys": [
                    {"granteeEmail": "%s", "wrappedKey": "bmV3T3duZXJXcmFwcGVk"},
                    {"granteeEmail": "%s", "wrappedKey": "bmV3Q2Fyb2xXcmFwcGVk"}
                  ]
                }
                """.formatted(ALICE, carol);
        mockMvc.perform(as(post("/api/vault/items/" + id + "/rotate-key"), ALICE).content(rotateBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedPassword").value("bmV3Q2lwaGVy"))
                .andExpect(jsonPath("$.wrappedKey").value("bmV3T3duZXJXcmFwcGVk"));

        // Carol (kept) gets the new wrapped key; Bob (excluded) loses his entirely.
        mockMvc.perform(as(get("/api/vault/items/" + id), carol))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedPassword").value("bmV3Q2lwaGVy"))
                .andExpect(jsonPath("$.wrappedKey").value("bmV3Q2Fyb2xXcmFwcGVk"));
        mockMvc.perform(as(get("/api/vault/items/" + id), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.wrappedKey").doesNotExist());
    }

    @Test
    void rotateKeyRejectsNonOwnerAndMissingOwnerEntry() throws Exception {
        String id = createItem(ALICE, "Guarded", "PERSONAL");
        shareWithUser(ALICE, id, BOB, "EDITOR");

        // Non-owner cannot rotate.
        mockMvc.perform(as(post("/api/vault/items/" + id + "/rotate-key"), BOB)
                        .content("""
                                {"encryptedPassword": "eA==", "passwordIv": "aXY=",
                                 "wrappedKeys": [{"granteeEmail": "%s", "wrappedKey": "eA=="}]}
                                """.formatted(BOB)))
                .andExpect(status().isForbidden());

        // Owner must be included in the new wrapped-key list.
        mockMvc.perform(as(post("/api/vault/items/" + id + "/rotate-key"), ALICE)
                        .content("""
                                {"encryptedPassword": "eA==", "passwordIv": "aXY=",
                                 "wrappedKeys": [{"granteeEmail": "%s", "wrappedKey": "eA=="}]}
                                """.formatted(BOB)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void keysLifecycle() throws Exception {
        String carol = "carol@kse.org.ua";
        // No keypair yet.
        mockMvc.perform(as(get("/api/keys/me"), carol))
                .andExpect(status().isNotFound());
        mockMvc.perform(as(get("/api/keys/" + carol), ALICE))
                .andExpect(status().isNotFound());

        // kdfAlgorithm is required — reject registration without it.
        mockMvc.perform(as(put("/api/keys/me"), carol).content("""
                {"publicKey": "cHVibGljS2V5", "encryptedPrivateKey": "ZW5jUHJpdg==",
                 "privateKeyIv": "aXY=", "kdfSalt": "c2FsdA=="}
                """))
                .andExpect(status().isBadRequest());

        String keysJson = """
                {"publicKey": "cHVibGljS2V5", "encryptedPrivateKey": "ZW5jUHJpdg==",
                 "privateKeyIv": "aXY=", "kdfSalt": "c2FsdA==", "kdfAlgorithm": "ARGON2ID"}
                """;
        mockMvc.perform(as(put("/api/keys/me"), carol).content(keysJson))
                .andExpect(status().isCreated());

        mockMvc.perform(as(get("/api/keys/me"), carol))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").value("cHVibGljS2V5"))
                .andExpect(jsonPath("$.kdfSalt").value("c2FsdA=="))
                .andExpect(jsonPath("$.kdfAlgorithm").value("ARGON2ID"));

        // Other users see only the public key.
        String publicView = mockMvc.perform(as(get("/api/keys/" + carol), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKey").value("cHVibGljS2V5"))
                .andReturn().getResponse().getContentAsString();
        JsonNode node = objectMapper.readTree(publicView);
        org.junit.jupiter.api.Assertions.assertFalse(node.has("encryptedPrivateKey"),
                "public view must not expose the encrypted private key");

        // Re-encrypting the same keypair (passphrase change) is allowed, and can
        // switch KDF algorithm (e.g. a legacy PBKDF2 keypair moving to Argon2id).
        mockMvc.perform(as(put("/api/keys/me"), carol).content("""
                {"publicKey": "cHVibGljS2V5", "encryptedPrivateKey": "bmV3RW5jUHJpdg==",
                 "privateKeyIv": "aXYy", "kdfSalt": "c2FsdDI=", "kdfAlgorithm": "PBKDF2"}
                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kdfAlgorithm").value("PBKDF2"));

        // Replacing with a different keypair needs force=true.
        String differentKey = """
                {"publicKey": "b3RoZXJLZXk=", "encryptedPrivateKey": "eA==",
                 "privateKeyIv": "aXY=", "kdfSalt": "c2FsdA==", "kdfAlgorithm": "ARGON2ID"}
                """;
        mockMvc.perform(as(put("/api/keys/me"), carol).content(differentKey))
                .andExpect(status().isBadRequest());
        mockMvc.perform(as(put("/api/keys/me?force=true"), carol).content(differentKey))
                .andExpect(status().isOk());
    }
}
