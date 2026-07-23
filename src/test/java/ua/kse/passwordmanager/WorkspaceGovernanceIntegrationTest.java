package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import ua.kse.passwordmanager.directory.*;

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class WorkspaceGovernanceIntegrationTest {
    @Autowired MockMvc mockMvc;
    @Autowired WorkspaceUserRepository users;
    @Autowired WorkspaceGroupRepository groups;

    @BeforeEach
    void clearWorkspaceSnapshot() {
        groups.deleteAll();
        users.deleteAll();
    }

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder as(
            org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request, String email, String roles) {
        return request.header("X-Dev-User", email).header("X-Dev-Roles", roles).contentType(MediaType.APPLICATION_JSON);
    }

    @Test
    void localAdminOverrideGrantsAdminApiAndRevocationBlocksEveryAuthenticatedApi() throws Exception {
        WorkspaceUser operator = new WorkspaceUser("operator@kse.org.ua");
        operator.setRoleOverride(WorkspaceRoleOverride.ADMIN);
        users.save(operator);

        mockMvc.perform(as(get("/api/admin/workspace/users"), "operator@kse.org.ua", "user"))
                .andExpect(status().isOk());

        WorkspaceUser revoked = new WorkspaceUser("revoked@kse.org.ua");
        revoked.setStatus(WorkspaceAccountStatus.REVOKED);
        users.save(revoked);
        mockMvc.perform(as(get("/api/vault/items"), "revoked@kse.org.ua", "user"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Account access has been suspended, revoked, or removed from Workspace"));
    }

    @Test
    void localUserOverrideWinsGoogleAdminAndGroupVisibilityCanBeChanged() throws Exception {
        WorkspaceUser googleAdmin = new WorkspaceUser("google-admin@kse.org.ua");
        googleAdmin.setRoleOverride(WorkspaceRoleOverride.USER);
        users.save(googleAdmin);
        WorkspaceGroup group = new WorkspaceGroup("new-group@kse.org.ua", false);
        groups.save(group);

        mockMvc.perform(as(get("/api/admin/workspace/users"), "google-admin@kse.org.ua", "admin"))
                .andExpect(status().isForbidden());
        mockMvc.perform(as(patch("/api/admin/workspace/groups/new-group@kse.org.ua"), "root@kse.org.ua", "admin")
                        .content("{\"visibleToUsers\":true}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.visibleToUsers").value(true));
    }

    @Test
    void localRolesReplaceDevOrKeycloakRoleClaimsForMethodSecurityOnEveryRequest() throws Exception {
        WorkspaceUser governed = new WorkspaceUser("governed@kse.org.ua");
        governed.setRoleOverride(WorkspaceRoleOverride.USER);
        users.save(governed);

        // A token/header claiming admin cannot bypass a local demotion.
        mockMvc.perform(as(get("/api/audit"), "governed@kse.org.ua", "admin"))
                .andExpect(status().isForbidden());

        governed.setRoleOverride(WorkspaceRoleOverride.ADMIN);
        users.save(governed);
        // The same identity is promoted on the next request, without another token.
        mockMvc.perform(as(get("/api/audit"), "governed@kse.org.ua", "user"))
                .andExpect(status().isOk());

        governed.setRoleOverride(WorkspaceRoleOverride.SECURITY);
        users.save(governed);
        mockMvc.perform(as(get("/api/audit"), "governed@kse.org.ua", "admin"))
                .andExpect(status().isOk());
        mockMvc.perform(as(get("/api/admin/workspace/users"), "governed@kse.org.ua", "admin"))
                .andExpect(status().isForbidden());
    }

    @Test
    void genericPatchCannotRevokeOrRemoveTheFinalActiveAdministrator() throws Exception {
        WorkspaceUser administrator = new WorkspaceUser("sole-admin@kse.org.ua");
        administrator.setRoleOverride(WorkspaceRoleOverride.ADMIN);
        users.save(administrator);

        mockMvc.perform(as(patch("/api/admin/workspace/users/sole-admin@kse.org.ua"), "sole-admin@kse.org.ua", "user")
                        .content("{\"status\":\"REVOKED\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(as(patch("/api/admin/workspace/users/sole-admin@kse.org.ua"), "sole-admin@kse.org.ua", "user")
                        .content("{\"roleOverride\":\"USER\"}"))
                .andExpect(status().isBadRequest());
    }
}
