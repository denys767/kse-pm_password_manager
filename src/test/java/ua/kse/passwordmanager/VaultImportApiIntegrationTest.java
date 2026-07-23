package ua.kse.passwordmanager;

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
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class VaultImportApiIntegrationTest {
    @Autowired MockMvc mockMvc;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request) {
        return request.header("X-Dev-User", "csv-owner@kse.org.ua").header("X-Dev-Roles", "user")
                .contentType(MediaType.APPLICATION_JSON);
    }

    @Test
    void previewIsReadOnlyAndInvalidBatchDoesNotCreatePartialRows() throws Exception {
        String create = """
            {"action":"CREATE","item":{"name":"CSV transactional item","encryptedPassword":"YQ==","passwordIv":"aXY=",
            "itemType":"PERSONAL","syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXI="}}
            """;
        String batch = "{\"commands\":[" + create
                + ",{\"action\":\"DELETE\",\"itemId\":\"00000000-0000-0000-0000-000000000001\",\"expectedUpdatedAt\":\"2026-01-01T00:00:00Z\"}]}";
        mockMvc.perform(as(post("/api/vault/imports/preview")).content("{\"commands\":[" + create + "]}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.createCount").value(1));
        mockMvc.perform(as(get("/api/vault/items")))
                .andExpect(jsonPath("$[?(@.name == 'CSV transactional item')]").isEmpty());
        mockMvc.perform(as(post("/api/vault/imports/commit")).content(batch))
                .andExpect(status().isNotFound());
        mockMvc.perform(as(get("/api/vault/items")))
                .andExpect(jsonPath("$[?(@.name == 'CSV transactional item')]").isEmpty());

        mockMvc.perform(as(post("/api/vault/imports/commit")).content("{\"commands\":[" + create + "]}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.createCount").value(1));
        mockMvc.perform(as(get("/api/vault/items")))
                .andExpect(jsonPath("$[?(@.name == 'CSV transactional item')]").exists());
    }
}
