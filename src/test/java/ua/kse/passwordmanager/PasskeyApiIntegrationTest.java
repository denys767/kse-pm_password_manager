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
    private String item() throws Exception {
        String response = mvc.perform(as(post("/api/vault/items"), "alice@kse.org.ua").content("""
                {"name":"Example","url":"https://login.example.test","username":"alice",
                 "encryptedPassword":"Y2lwaGVy","passwordIv":"aXY=","itemType":"PERSONAL",
                 "syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXI="}
                """)) .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(response).path("id").asText();
    }
    private String credential(String itemId) throws Exception {
        String response = mvc.perform(extension(post("/api/passkeys"), "alice@kse.org.ua").content("""
                {"itemId":"%s","relyingPartyId":"example.test","credentialId":"credential-A",
                 "userHandle":"AQ","algorithm":"ES256","publicKey":"cHVibGlj",
                 "encryptedPrivateMaterial":"Y2lwaGVydGV4dA==","privateMaterialIv":"aXY=",
                 "transports":"internal","wrappedCredentialKey":"b3duZXI="}
                """.formatted(itemId))).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return json.readTree(response).path("id").asText();
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
