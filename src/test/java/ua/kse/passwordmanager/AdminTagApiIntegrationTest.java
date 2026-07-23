package ua.kse.passwordmanager;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
class AdminTagApiIntegrationTest {
    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper objectMapper;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email, String roles) {
        return request.header("X-Dev-User", email).header("X-Dev-Roles", roles)
                .contentType(MediaType.APPLICATION_JSON);
    }

    private String item(String name, String tags) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), "tag-owner@kse.org.ua", "user").content("""
                {"name":"%s","encryptedPassword":"YQ==","passwordIv":"aXY=",
                 "tags":"%s","itemType":"PERSONAL","syncMode":"SERVER_SYNCED","wrappedKey":"b3duZXI="}
                """.formatted(name, tags))).andExpect(status().isCreated()).andReturn()
                .getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    @Test
    void localAdminCanRenameAndDeleteServerTagsCaseInsensitively() throws Exception {
        String first = item("Tagged one", "Finance, Team");
        String second = item("Tagged two", "finance, Other");

        mockMvc.perform(as(get("/api/admin/tags"), "viewer@kse.org.ua", "user"))
                .andExpect(status().isForbidden());
        mockMvc.perform(as(get("/api/admin/tags"), "tag-admin@kse.org.ua", "admin"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.name == 'Finance')].usageCount").value(2));

        mockMvc.perform(as(patch("/api/admin/tags/finance"), "tag-admin@kse.org.ua", "admin")
                        .content("{\"newName\":\"Budget\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.name").value("Budget"))
                .andExpect(jsonPath("$.usageCount").value(2));
        mockMvc.perform(as(get("/api/vault/items/" + first), "tag-owner@kse.org.ua", "user"))
                .andExpect(jsonPath("$.tags").value("Budget,Team"));
        mockMvc.perform(as(get("/api/vault/items/" + second), "tag-owner@kse.org.ua", "user"))
                .andExpect(jsonPath("$.tags").value("Budget,Other"));

        mockMvc.perform(as(delete("/api/admin/tags/budget"), "tag-admin@kse.org.ua", "admin"))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(get("/api/vault/items/" + first), "tag-owner@kse.org.ua", "user"))
                .andExpect(jsonPath("$.tags").value("Team"));
        mockMvc.perform(as(get("/api/vault/items/" + second), "tag-owner@kse.org.ua", "user"))
                .andExpect(jsonPath("$.tags").value("Other"));
    }
}
