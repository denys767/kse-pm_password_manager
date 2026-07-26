package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import ua.kse.passwordmanager.directory.WorkspaceGroup;
import ua.kse.passwordmanager.directory.WorkspaceGroupRepository;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

/**
 * The Google Directory is unreachable in this context (no credentials are
 * configured, so the live client answers 502). The share picker still has to
 * offer the people the synchronizer already materialized — otherwise a Google
 * problem means nobody in the organization can share a password.
 */
@SpringBootTest(properties = {
        "pm.allow-insecure-dev=true",
        // Stands in for "Google cannot be reached": with no configured client the
        // live side answers 502, which is what a broken credential looks like to
        // every caller. A developer .env must not silently make this test talk to
        // the real Directory.
        "pm.google-workspace.service-account-email=",
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class DirectoryFallbackApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WorkspaceUserRepository users;

    @Autowired
    private WorkspaceGroupRepository groups;

    @BeforeEach
    void seedSnapshot() {
        WorkspaceUser colleague = new WorkspaceUser("directory-fallback@kse.org.ua");
        users.save(colleague);
        groups.save(new WorkspaceGroup("fallback-team@kse.org.ua", true));
    }

    @Test
    void suggestionsAreServedFromTheSnapshotWhileGoogleIsUnavailable() throws Exception {
        mockMvc.perform(get("/api/directory/principals?query=directory-fallback&types=USER")
                        .header("X-Dev-User", "someone@kse.org.ua").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].email", hasItem("directory-fallback@kse.org.ua")));
    }

    @Test
    void groupSuggestionsFallBackTooAndKeepGovernanceVisibility() throws Exception {
        mockMvc.perform(get("/api/directory/principals?query=fallback-team&types=GROUP")
                        .header("X-Dev-User", "someone@kse.org.ua").contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].email", hasItem("fallback-team@kse.org.ua")));
    }
}
