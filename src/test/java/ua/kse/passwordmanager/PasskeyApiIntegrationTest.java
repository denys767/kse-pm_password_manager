package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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

/** Authorization matrix for special roles: browser OAuth is a server-side
 * policy boundary and passkey keys are independent of password item keys. */
@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class PasskeyApiIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }
    private MockHttpServletRequestBuilder extension(MockHttpServletRequestBuilder request, String email) {
        return as(request, email).header("X-Dev-OAuth-Client", "kse-pm-extension")
                .header("X-Dev-OAuth-Audience", "kse-pm-extension");
    }
    private String item() throws Exception { return item("alice@kse.org.ua"); }
    private String item(String owner) throws Exception {
        String response = mvc.perform(as(post("/api/vault/items"), owner).content("""
                {"name":"Example","url":"https://login.example.test","username":"alice",
                 "encryptedPassword":"Y2lwaGVy","passwordIv":"aXY=","itemType":"PERSONAL",
                 "syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXI="}
                """)) .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(response).path("id").asText();
    }
    private String credential(String itemId) throws Exception {
        return credential(itemId, "example.test", "credential-A");
    }
    /** Tests share one database, so each needs its own relying party and
     * credential id or they collide on uq_passkey_credentials. */
    private String credential(String itemId, String rpId, String credentialId) throws Exception {
        return credential("alice@kse.org.ua", itemId, rpId, credentialId);
    }
    private String credential(String owner, String itemId, String rpId, String credentialId) throws Exception {
        String response = mvc.perform(extension(post("/api/passkeys"), owner).content("""
                {"itemId":"%s","relyingPartyId":"%s","credentialId":"%s",
                 "userHandle":"AQ","algorithm":"ES256","publicKey":"cHVibGlj",
                 "encryptedPrivateMaterial":"Y2lwaGVydGV4dA==","privateMaterialIv":"aXY=",
                 "transports":"internal","wrappedCredentialKey":"b3duZXI="}
                """.formatted(itemId, rpId, credentialId))).andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).path("id").asText();
    }
    private void vaultKeysFor(String email) throws Exception {
        mvc.perform(as(put("/api/keys/me"), email).content("""
                {"publicKey": "cHVibGljS2V5", "encryptedPrivateKey": "ZW5jUHJpdg==",
                 "privateKeyIv": "aXY=", "kdfSalt": "c2FsdA==", "kdfAlgorithm": "ARGON2ID"}
                """)).andExpect(status().isCreated());
    }

    /**
     * The gap that made PASSKEY_ONLY unusable end to end: the grant exists, the
     * authorization matrix agrees, and the grantee still sees nothing, because
     * no client ever wrapped the credential key to them. This is the endpoint
     * that tells the owner's extension what it owes, and it is the only way the
     * work gets discovered.
     */
    @Test void theOwnersExtensionIsToldWhichGranteesStillNeedACredentialKey() throws Exception {
        String owner = "dana@kse.org.ua", grantee = "erin@kse.org.ua";
        String itemId = item(owner);
        String credentialId = credential(owner, itemId, "distribution.test", "credential-D");
        vaultKeysFor(grantee);
        mvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner).content("""
                {"granteeType":"USER","grantee":"%s","role":"PASSKEY_ONLY"}
                """.formatted(grantee))).andExpect(status().isCreated());

        mvc.perform(extension(get("/api/passkeys/key-distribution"), owner))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(credentialId))
                .andExpect(jsonPath("$[0].wrappedCredentialKeyForMe").value("b3duZXI="))
                .andExpect(jsonPath("$[0].pending[0].email").value(grantee))
                .andExpect(jsonPath("$[0].pending[0].publicKey").value("cHVibGljS2V5"));

        // Once the extension has done the wrapping there is nothing left to do,
        // so the next pass is a no-op rather than a re-send.
        mvc.perform(extension(put("/api/passkeys/" + credentialId + "/wrapped-keys"), owner)
                .content("{\"userEmail\":\"%s\",\"wrappedCredentialKey\":\"ZXJpbi1rZXk=\"}".formatted(grantee)))
                .andExpect(status().isNoContent());
        mvc.perform(extension(get("/api/passkeys/key-distribution"), owner))
                .andExpect(status().isOk()).andExpect(jsonPath("$").isEmpty());

        // Same boundary as the rest of the passkey API: distributing a key
        // means unwrapping one, which the web client may not do.
        mvc.perform(as(get("/api/passkeys/key-distribution"), owner))
                .andExpect(status().isForbidden());
    }

    @Test void revokingAGrantTakesTheWrappedCredentialKeyWithIt() throws Exception {
        String owner = "frank@kse.org.ua", grantee = "grace@kse.org.ua", rpId = "revocation.test";
        String itemId = item(owner);
        String credentialId = credential(owner, itemId, rpId, "credential-F");
        vaultKeysFor(grantee);
        String permission = json.readTree(mvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner)
                .content("""
                {"granteeType":"USER","grantee":"%s","role":"PASSKEY_ONLY"}
                """.formatted(grantee))).andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString()).path("id").asText();
        mvc.perform(extension(put("/api/passkeys/" + credentialId + "/wrapped-keys"), owner)
                .content("{\"userEmail\":\"%s\",\"wrappedCredentialKey\":\"Z3JhY2Uta2V5\"}".formatted(grantee)))
                .andExpect(status().isNoContent());
        mvc.perform(extension(get("/api/passkeys?rpId=" + rpId), grantee))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].credentialId").value("credential-F"));

        mvc.perform(as(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .delete("/api/vault/items/" + itemId + "/permissions/" + permission), owner))
                .andExpect(status().isNoContent());

        mvc.perform(extension(get("/api/passkeys?rpId=" + rpId), grantee))
                .andExpect(status().isOk()).andExpect(jsonPath("$").isEmpty());
        // And the row is really gone, so re-granting later does not silently
        // resurrect a key the owner never re-issued: the grantee still sees
        // nothing, and the owner's extension is told to wrap a fresh one.
        mvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner).content("""
                {"granteeType":"USER","grantee":"%s","role":"PASSKEY_ONLY"}
                """.formatted(grantee))).andExpect(status().isCreated());
        mvc.perform(extension(get("/api/passkeys?rpId=" + rpId), grantee))
                .andExpect(status().isOk()).andExpect(jsonPath("$").isEmpty());
        mvc.perform(extension(get("/api/passkeys/key-distribution"), owner))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].pending[0].email").value(grantee));
    }

    @Test void specialRolesAndPasskeyMaterialHaveSeparateClientBoundPaths() throws Exception {
        String itemId = item();
        mvc.perform(as(post("/api/passkeys"), "alice@kse.org.ua").content("{}"))
                .andExpect(status().isForbidden());
        String credentialId = credential(itemId);
        mvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), "alice@kse.org.ua").content("""
                {"granteeType":"USER","grantee":"bob@kse.org.ua","role":"AUTOFILL_ONLY","wrappedKey":"Ym9iLWl0ZW0ta2V5"}
                """)) .andExpect(status().isCreated());
        mvc.perform(as(get("/api/vault/items/" + itemId), "bob@kse.org.ua")).andExpect(status().isNotFound());
        mvc.perform(extension(get("/api/vault/items"), "bob@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].encryptedPassword").value("Y2lwaGVy"));

        mvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), "alice@kse.org.ua").content("""
                {"granteeType":"USER","grantee":"bob@kse.org.ua","role":"PASSKEY_ONLY"}
                """)) .andExpect(status().isCreated());
        mvc.perform(extension(get("/api/vault/items"), "bob@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].encryptedPassword").doesNotExist())
                .andExpect(jsonPath("$[0].wrappedKey").doesNotExist());
        mvc.perform(extension(get("/api/passkeys?rpId=example.test"), "bob@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$").isEmpty());
        mvc.perform(extension(put("/api/passkeys/" + credentialId + "/wrapped-keys"), "alice@kse.org.ua")
                .content("{\"userEmail\":\"bob@kse.org.ua\",\"wrappedCredentialKey\":\"Ym9iLXBhc3NrZXkta2V5\"}"))
                .andExpect(status().isNoContent());
        mvc.perform(extension(get("/api/passkeys?rpId=example.test"), "bob@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$[0].credentialId").value("credential-A"))
                .andExpect(jsonPath("$[0].wrappedCredentialKey").value("Ym9iLXBhc3NrZXkta2V5"));
        mvc.perform(extension(post("/api/passkeys/" + credentialId + "/counter"), "bob@kse.org.ua")
                .content("{\"signCounter\":1}")).andExpect(status().isNoContent());
        mvc.perform(extension(post("/api/passkeys/" + credentialId + "/counter"), "bob@kse.org.ua")
                .content("{\"signCounter\":1}")).andExpect(status().isForbidden());
    }
}
