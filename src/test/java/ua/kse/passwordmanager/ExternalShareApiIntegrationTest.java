package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class ExternalShareApiIntegrationTest {
    private static final String ALICE = "alice-external@kse.org.ua";
    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;
    @Autowired JdbcTemplate jdbc;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request) {
        return request.header("X-Dev-User", ALICE).contentType(MediaType.APPLICATION_JSON);
    }
    private String item() throws Exception {
        String result = mockMvc.perform(as(post("/api/vault/items")).content("""
                {"name":"TOTP production","encryptedPassword":"Y2lwaGVydGV4dA==","passwordIv":"aXY=",
                 "encryptedNotes":"ZW5jcnlwdGVkLXRvdHA=","notesIv":"aXY=","type":"LOGIN",
                 "itemType":"PERSONAL","syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXJXcmFwcGVkS2V5"}
                """)).andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(result).get("id").asText();
    }
    private String share(String itemId, boolean oneTime) throws Exception {
        String result = mockMvc.perform(as(post("/api/vault/items/" + itemId + "/external-shares")).content("""
                {"encryptedPackage":"opaque-ciphertext-containing-no-plaintext","packageIv":"YWVzLWdjbS1pdg==",
                 "expiresAt":"%s","oneTime":%s}
                """.formatted(Instant.now().plusSeconds(300), oneTime)))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(result).get("id").asText();
    }

    @Test
    void publicReaderGetsOnlyOpaquePackageAndOneTimeLinkIsGoneAfterRead() throws Exception {
        String shareId = share(item(), true);
        mockMvc.perform(get("/api/external-shares/" + shareId)).andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedPackage").value("opaque-ciphertext-containing-no-plaintext"))
                .andExpect(jsonPath("$.packageIv").value("YWVzLWdjbS1pdg=="))
                .andExpect(jsonPath("$.fragmentKey").doesNotExist());
        mockMvc.perform(get("/api/external-shares/" + shareId)).andExpect(status().isGone());
    }

    @Test
    void expiredAndRevokedLinksReturnGone() throws Exception {
        String itemId = item();
        String expired = share(itemId, false);
        jdbc.update("update external_shares set expires_at = ? where id = ?", Timestamp.from(Instant.now().minusSeconds(1)), UUID.fromString(expired));
        mockMvc.perform(get("/api/external-shares/" + expired)).andExpect(status().isGone());

        String active = share(itemId, false);
        mockMvc.perform(as(delete("/api/vault/items/" + itemId + "/external-shares/" + active))).andExpect(status().isNoContent());
        mockMvc.perform(get("/api/external-shares/" + active)).andExpect(status().isGone());
    }
}
