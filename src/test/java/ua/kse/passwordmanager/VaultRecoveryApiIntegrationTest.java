package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
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
import ua.kse.passwordmanager.directory.WorkspaceGroup;
import ua.kse.passwordmanager.directory.WorkspaceGroupRepository;
import ua.kse.passwordmanager.directory.WorkspaceMembership;
import ua.kse.passwordmanager.directory.WorkspaceMembershipRepository;

/**
 * The reset flow of a user who lost their vault passphrase: they can no longer
 * wrap a key for anyone, so every path here has to work with the wrapped keys
 * that already exist.
 */
@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class VaultRecoveryApiIntegrationTest {

    private static final String ALICE = "reset-alice@kse.org.ua";
    private static final String BOB = "reset-bob@kse.org.ua";
    private static final String CAROL = "reset-carol@kse.org.ua";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WorkspaceGroupRepository workspaceGroups;

    @Autowired
    private WorkspaceMembershipRepository workspaceMemberships;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }

    private String createItem(String owner, String name) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), owner)
                        .content("""
                                {"name": "%s", "encryptedPassword": "Y2lwaGVy", "passwordIv": "aXY=",
                                 "itemType": "SHARED", "syncMode": "SERVER_SYNCED", "wrappedKey": "b3duZXI="}
                                """.formatted(name)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    private void shareWithUser(String owner, String itemId, String grantee, String role, boolean withKey)
            throws Exception {
        mockMvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner)
                        .content(withKey
                                ? """
                                {"granteeType": "USER", "grantee": "%s", "role": "%s", "wrappedKey": "Z3JhbnRlZQ=="}
                                """.formatted(grantee, role)
                                : """
                                {"granteeType": "USER", "grantee": "%s", "role": "%s"}
                                """.formatted(grantee, role)))
                .andExpect(status().isCreated());
    }

    /** A group share with no wrapped keys ever provisioned to its members: the
     * only case left that can leave a shared item with zero item-key holders,
     * now that every USER role (PASSKEY_ONLY included) requires one. */
    private void shareWithUnprovisionedGroup(String owner, String itemId, String groupEmail, String member)
            throws Exception {
        workspaceGroups.save(new WorkspaceGroup(groupEmail, true));
        workspaceMemberships.save(new WorkspaceMembership(groupEmail, member));
        mockMvc.perform(as(post("/api/vault/items/" + itemId + "/permissions"), owner)
                        .content("""
                                {"granteeType": "GROUP", "grantee": "%s", "directorySubjectId": "%s", "role": "VIEWER"}
                                """.formatted(groupEmail, groupEmail)))
                .andExpect(status().isCreated());
    }

    private String transfer(String owner, String kind, String resourceId, String successor) throws Exception {
        return mockMvc.perform(as(post("/api/vault/ownership-transfers"), owner)
                        .content("""
                                {"kind": "%s", "resourceId": "%s", "successorEmail": "%s"}
                                """.formatted(kind, resourceId, successor)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    @Test
    void resetImpactOffersOnlyRecipientsThatHoldAWrappedKey() throws Exception {
        String itemId = createItem(ALICE, "Shared login");
        shareWithUser(ALICE, itemId, BOB, "VIEWER", true);
        // PASSKEY_ONLY now requires a wrapped item key too (the extension
        // needs it to autofill), so Carol holds one and is a candidate too —
        // same as any other key-holding grantee.
        shareWithUser(ALICE, itemId, CAROL, "PASSKEY_ONLY", true);

        mockMvc.perform(as(get("/api/vault/reset-impact"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.blockers[?(@.id == '%s')].candidates[*].email".formatted(itemId),
                        hasItem(BOB)))
                .andExpect(jsonPath("$.blockers[?(@.id == '%s')].candidates[*].email".formatted(itemId),
                        hasItem(CAROL)))
                .andExpect(jsonPath("$.blockers[?(@.id == '%s')].candidates[*].email".formatted(itemId),
                        hasSize(2)));

        mockMvc.perform(as(post("/api/vault/ownership-transfers"), ALICE)
                        .content("""
                                {"kind": "ITEM", "resourceId": "%s", "successorEmail": "%s"}
                                """.formatted(itemId, CAROL)))
                .andExpect(status().isOk());
    }

    @Test
    void itemTransferAnswersWithTheRefreshedImpactAndDropsTheSuccessorGrant() throws Exception {
        String itemId = createItem(ALICE, "Handover");
        shareWithUser(ALICE, itemId, BOB, "VIEWER", true);

        String impact = transfer(ALICE, "ITEM", itemId, BOB);
        // The body is the impact, not an empty 200 the browser cannot parse.
        org.junit.jupiter.api.Assertions.assertTrue(objectMapper.readTree(impact).get("allowed").asBoolean());
        org.junit.jupiter.api.Assertions.assertEquals(0, objectMapper.readTree(impact).get("blockers").size());

        // Bob owns it now, and no longer appears as a grantee of his own item.
        mockMvc.perform(as(get("/api/vault/items/" + itemId + "/permissions"), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
        mockMvc.perform(as(get("/api/vault/items/" + itemId), ALICE))
                .andExpect(status().isNotFound());
    }

    @Test
    void sharedItemWithNoPossibleSuccessorIsStrandedRatherThanBlocking() throws Exception {
        String itemId = createItem(ALICE, "Group-only, unprovisioned");
        // Every USER role (PASSKEY_ONLY included) now requires a wrapped item
        // key, so the only remaining way for a shared item to have zero
        // key-holders is a group whose members were never provisioned one.
        shareWithUnprovisionedGroup(ALICE, itemId, "reset-team@kse.org.ua", BOB);

        mockMvc.perform(as(get("/api/vault/reset-impact"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.blockers", hasSize(0)))
                .andExpect(jsonPath("$.stranded[*].id", hasItem(itemId)));

        mockMvc.perform(as(post("/api/vault/reset"), ALICE)
                        .content("""
                                {"confirmation": "RESET VAULT",
                                 "keys": {"publicKey": "cHVibGlj", "encryptedPrivateKey": "cHJpdmF0ZQ==",
                                          "privateKeyIv": "aXY=", "kdfSalt": "c2FsdA==", "kdfAlgorithm": "ARGON2ID"}}
                                """))
                .andExpect(status().isOk());
        mockMvc.perform(as(get("/api/vault/items/" + itemId), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void collectionTransferPromotesTheSuccessorToManager() throws Exception {
        String collectionId = mockMvc.perform(as(post("/api/collections"), ALICE)
                        .content("""
                                {"name": "Handover team", "wrappedKeyForSelf": "c2VsZg=="}
                                """))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        collectionId = objectMapper.readTree(collectionId).get("id").asText();
        mockMvc.perform(as(post("/api/collections/" + collectionId + "/members"), ALICE)
                        .content("""
                                {"email": "%s", "role": "VIEWER", "wrappedKey": "bWVtYmVy"}
                                """.formatted(BOB)))
                .andExpect(status().isCreated());

        mockMvc.perform(as(get("/api/vault/reset-impact"), ALICE))
                .andExpect(jsonPath("$.blockers[?(@.id == '%s')].candidates[*].email".formatted(collectionId),
                        hasItem(BOB)));

        transfer(ALICE, "COLLECTION", collectionId, BOB);

        // Without the promotion the new owner would be left as a VIEWER.
        mockMvc.perform(as(get("/api/collections"), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '%s')].myRole".formatted(collectionId), hasItem("MANAGER")));
    }
}
