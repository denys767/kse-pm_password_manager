package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/** Contract test for the client-produced escrow boundary. The fake provider is
 * sufficient here because a real Cloud KMS key is an opt-in staging concern. */
@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RecoveryApiIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder as(
            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }
    @Test void ownerUploadsEscrowEnvelopeAndCoverageDoesNotExposeKeyMaterial() throws Exception {
        String item = mvc.perform(as(post("/api/vault/items"), "recovery-owner@kse.org.ua").content("""
                {"name":"Escrowed","encryptedPassword":"Y2lwaGVy","passwordIv":"aXY=",
                 "itemType":"PERSONAL","syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXI="}
                """))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        String id = json.readTree(item).path("id").asText();
        mvc.perform(as(get("/api/recovery/public-key"), "recovery-owner@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.algorithm").value("RSA_DECRYPT_OAEP_2048_SHA256"))
                .andExpect(jsonPath("$.pem").exists());
        mvc.perform(as(put("/api/recovery/envelopes"), "recovery-owner@kse.org.ua").content("""
                {"resourceType":"ITEM","resourceId":"%s","keyVersion":"local-dev-v1","ciphertext":"Y2lwaGVydGV4dA=="}
                """.formatted(id))).andExpect(status().isOk());
        mvc.perform(as(get("/api/recovery/coverage/me"), "recovery-owner@kse.org.ua"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.covered").value(1)).andExpect(jsonPath("$.total").value(1));
        mvc.perform(as(put("/api/recovery/envelopes"), "bob@kse.org.ua").content("""
                {"resourceType":"ITEM","resourceId":"%s","keyVersion":"local-dev-v1","ciphertext":"Y2lwaGVydGV4dA=="}
                """.formatted(id))).andExpect(status().isForbidden());
    }

}
