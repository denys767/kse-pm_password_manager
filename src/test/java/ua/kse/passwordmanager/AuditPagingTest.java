package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
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
class AuditPagingTest {

    private static final String ADMIN = "paging-admin@kse.org.ua";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }

    private MockHttpServletRequestBuilder asAdmin(MockHttpServletRequestBuilder request) {
        return request.header("X-Dev-User", ADMIN).header("X-Dev-Roles", "admin");
    }

    private String createItem(String owner, String name) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), owner)
                        .content("""
                                {
                                  "name": "%s",
                                  "url": "https://example.com",
                                  "username": "login",
                                  "encryptedPassword": "Y2lwaGVydGV4dA==",
                                  "passwordIv": "aXZpdml2aXZpdg==",
                                  "tags": "test",
                                  "itemType": "PERSONAL",
                                  "syncMode": "SERVER_SYNCED",
                                  "wrappedKey": "b3duZXJXcmFwcGVkS2V5"
                                }
                                """.formatted(name)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    @Test
    void pageSizeIsRespectedAndTotalElementsCoversAllPages() throws Exception {
        String owner = "paging-owner-1@kse.org.ua";
        for (int i = 0; i < 5; i++) {
            createItem(owner, "Paging item " + i);
        }

        mockMvc.perform(asAdmin(get("/api/audit"))
                        .param("page", "0").param("size", "2")
                        .param("actorEmail", owner).param("action", "ITEM_CREATED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(2)))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(2))
                .andExpect(jsonPath("$.totalElements").value(5))
                .andExpect(jsonPath("$.totalPages").value(3));

        mockMvc.perform(asAdmin(get("/api/audit"))
                        .param("page", "2").param("size", "2")
                        .param("actorEmail", owner).param("action", "ITEM_CREATED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.totalElements").value(5));
    }

    @Test
    void filtersByActorAndActionNarrowResults() throws Exception {
        String owner = "paging-owner-2@kse.org.ua";
        createItem(owner, "Filtered item");

        mockMvc.perform(asAdmin(get("/api/audit"))
                        .param("actorEmail", owner).param("action", "ITEM_CREATED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[*].actorEmail", everyItem(org.hamcrest.Matchers.is(owner))))
                .andExpect(jsonPath("$.content[*].action", everyItem(org.hamcrest.Matchers.is("ITEM_CREATED"))));

        mockMvc.perform(asAdmin(get("/api/audit"))
                        .param("actorEmail", "someone-else@kse.org.ua"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)))
                .andExpect(jsonPath("$.totalElements").value(0));
    }

    @Test
    void sizeIsClampedToMaximum() throws Exception {
        mockMvc.perform(asAdmin(get("/api/audit")).param("size", "9999"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(lessThanOrEqualTo(200))));
    }
}
