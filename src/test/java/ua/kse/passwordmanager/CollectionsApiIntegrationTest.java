package ua.kse.passwordmanager;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import ua.kse.passwordmanager.keycloak.KeycloakAdminClient;
import ua.kse.passwordmanager.collections.AllowedKeycloakGroup;
import ua.kse.passwordmanager.collections.AllowedKeycloakGroupRepository;

import static org.mockito.Mockito.when;

@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class CollectionsApiIntegrationTest {

    private static final String ALICE = "alice-col@kse.org.ua";
    private static final String BOB = "bob-col@kse.org.ua";
    private static final String CAROL = "carol-col@kse.org.ua";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private KeycloakAdminClient keycloakAdminClient;

    @Autowired
    private AllowedKeycloakGroupRepository allowedGroups;

    private MockHttpServletRequestBuilder as(MockHttpServletRequestBuilder request, String email) {
        return request.header("X-Dev-User", email).contentType(MediaType.APPLICATION_JSON);
    }

    private String createCollection(String owner, String name) throws Exception {
        String body = mockMvc.perform(as(post("/api/collections"), owner)
                        .content("""
                                {"name": "%s", "wrappedKeyForSelf": "c2VsZldyYXBwZWQ="}
                                """.formatted(name)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.myRole").value("MANAGER"))
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    private String addMember(String manager, String collectionId, String email, String role)
            throws Exception {
        String body = mockMvc.perform(as(post("/api/collections/" + collectionId + "/members"), manager)
                        .content("""
                                {"email": "%s", "role": "%s", "wrappedKey": "bWVtYmVyV3JhcHBlZA=="}
                                """.formatted(email, role)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    private String createItem(String owner, String name) throws Exception {
        String body = mockMvc.perform(as(post("/api/vault/items"), owner)
                        .content("""
                                {"name": "%s", "encryptedPassword": "Y2lwaGVy", "passwordIv": "aXY=",
                                 "itemType": "PERSONAL", "syncMode": "SERVER_SYNCED",
                                 "wrappedKey": "b3duZXJLZXk="}
                                """.formatted(name)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return objectMapper.readTree(body).get("id").asText();
    }

    private void putInCollection(String owner, String itemId, String collectionId) throws Exception {
        mockMvc.perform(as(put("/api/vault/items/" + itemId + "/collection"), owner)
                        .content("""
                                {"collectionId": "%s", "wrappedKey": "Y29sV3JhcHBlZA==", "wrappedKeyIv": "Y2l2"}
                                """.formatted(collectionId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.collectionId").value(collectionId))
                .andExpect(jsonPath("$.itemType").value("SHARED"));
    }

    @Test
    void memberSeesAndDecryptChainFieldsOfCollectionItems() throws Exception {
        String collectionId = createCollection(ALICE, "Infra");
        addMember(ALICE, collectionId, BOB, "VIEWER");
        String itemId = createItem(ALICE, "DB root");
        putInCollection(ALICE, itemId, collectionId);

        // Bob sees the item with his collection role and the collection-wrapped key.
        mockMvc.perform(as(get("/api/vault/items/" + itemId), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessRole").value("VIEWER"))
                .andExpect(jsonPath("$.collectionId").value(collectionId))
                .andExpect(jsonPath("$.collectionWrappedKey").value("Y29sV3JhcHBlZA=="))
                .andExpect(jsonPath("$.collectionWrappedKeyIv").value("Y2l2"));

        mockMvc.perform(as(get("/api/vault/items"), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].id", hasItem(itemId)));

        // Bob also sees his collection with his wrapped key.
        mockMvc.perform(as(get("/api/collections"), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '%s')].myWrappedKey".formatted(collectionId),
                        hasItem("bWVtYmVyV3JhcHBlZA==")))
                .andExpect(jsonPath("$[?(@.id == '%s')].myRole".formatted(collectionId),
                        hasItem("VIEWER")));
    }

    @Test
    void collectionRolesGovernItemEditing() throws Exception {
        String collectionId = createCollection(ALICE, "Team");
        addMember(ALICE, collectionId, BOB, "VIEWER");
        addMember(ALICE, collectionId, CAROL, "EDITOR");
        String itemId = createItem(ALICE, "Wiki admin");
        putInCollection(ALICE, itemId, collectionId);

        String update = """
                {"name": "Wiki admin v2", "encryptedPassword": "Y2lwaGVyMg==", "passwordIv": "aXYy",
                 "itemType": "SHARED", "syncMode": "SERVER_SYNCED"}
                """;
        mockMvc.perform(as(put("/api/vault/items/" + itemId), BOB).content(update))
                .andExpect(status().isForbidden());
        mockMvc.perform(as(put("/api/vault/items/" + itemId), CAROL).content(update))
                .andExpect(status().isOk());
    }

    @Test
    void revokingMembershipRemovesAccess() throws Exception {
        String collectionId = createCollection(ALICE, "Finance");
        String memberId = addMember(ALICE, collectionId, BOB, "VIEWER");
        String itemId = createItem(ALICE, "Bank");
        putInCollection(ALICE, itemId, collectionId);

        mockMvc.perform(as(get("/api/vault/items/" + itemId), BOB))
                .andExpect(status().isOk());

        mockMvc.perform(as(delete("/api/collections/" + collectionId + "/members/" + memberId), ALICE))
                .andExpect(status().isNoContent());

        mockMvc.perform(as(get("/api/vault/items/" + itemId), BOB))
                .andExpect(status().isNotFound());
        mockMvc.perform(as(get("/api/collections"), BOB))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '%s')]".formatted(collectionId), hasSize(0)));
    }

    @Test
    void onlyManagerManagesMembers() throws Exception {
        String collectionId = createCollection(ALICE, "Managed");
        addMember(ALICE, collectionId, BOB, "EDITOR");

        mockMvc.perform(as(post("/api/collections/" + collectionId + "/members"), BOB)
                        .content("""
                                {"email": "%s", "role": "VIEWER", "wrappedKey": "eA=="}
                                """.formatted(CAROL)))
                .andExpect(status().isForbidden());

        // Non-members can't even see the collection.
        mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), CAROL))
                .andExpect(status().isNotFound());

        // The owner cannot be removed.
        String ownerMemberId = objectMapper
                .readTree(mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), ALICE))
                        .andReturn().getResponse().getContentAsString())
                .get(0).get("id").asText();
        mockMvc.perform(as(delete("/api/collections/" + collectionId + "/members/" + ownerMemberId), ALICE))
                .andExpect(status().isBadRequest());
    }

    @Test
    void managerGetsOnlyNewKeycloakGroupSuggestions() throws Exception {
        String collectionId = createCollection(ALICE, "Suggested");
        addMember(ALICE, collectionId, BOB, "EDITOR");
        when(keycloakAdminClient.membersOfGroup("dev-team"))
                .thenReturn(java.util.List.of(ALICE, BOB, CAROL));

        mockMvc.perform(as(get("/api/collections/" + collectionId
                        + "/keycloak-suggestions?group=dev-team"), ALICE))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0]").value(CAROL));
        mockMvc.perform(as(get("/api/collections/" + collectionId
                        + "/keycloak-suggestions?group=dev-team"), BOB))
                .andExpect(status().isForbidden());
    }

    @Test
    void groupSyncKeepsNewMemberPendingThenBlocksRemovedMemberUntilManagerRotates() throws Exception {
        allowedGroups.save(new AllowedKeycloakGroup("dev-team"));
        String collectionId = objectMapper.readTree(mockMvc.perform(as(post("/api/collections"), ALICE)
                        .content("""
                                {"name":"Managed by group","keycloakGroup":"dev-team","wrappedKeyForSelf":"c2VsZg=="}
                                """))
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString()).get("id").asText();
        when(keycloakAdminClient.membersOfGroup("dev-team")).thenReturn(java.util.List.of(ALICE, BOB));

        mockMvc.perform(as(post("/api/collections/" + collectionId + "/sync-group"), ALICE))
                .andExpect(status().isNoContent());
        JsonNode syncedMembers = objectMapper.readTree(mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), ALICE))
                        .andExpect(status().isOk()).andExpect(jsonPath("$[?(@.memberEmail == '" + BOB + "')].status")
                                .value("PENDING_PROVISIONING"))
                        .andReturn().getResponse().getContentAsString());
        String pendingId = memberId(syncedMembers, BOB);
        mockMvc.perform(as(get("/api/collections"), BOB))
                .andExpect(status().isOk()).andExpect(jsonPath("$", hasSize(0)));

        mockMvc.perform(as(post("/api/collections/" + collectionId + "/members"), ALICE)
                        .content("{\"email\":\"" + BOB + "\",\"role\":\"VIEWER\",\"wrappedKey\":\"Ym9i\"}"))
                .andExpect(status().isCreated()).andExpect(jsonPath("$.status").value("ACTIVE"));
        mockMvc.perform(as(get("/api/collections"), BOB)).andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(collectionId));

        when(keycloakAdminClient.membersOfGroup("dev-team")).thenReturn(java.util.List.of(ALICE));
        mockMvc.perform(as(post("/api/collections/" + collectionId + "/sync-group"), ALICE))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(get("/api/collections"), BOB)).andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
        mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), ALICE))
                .andExpect(status().isOk()).andExpect(jsonPath("$[?(@.memberEmail == '" + BOB + "')].status")
                        .value("PENDING_REMOVAL"));

        String ownerId = memberId(objectMapper.readTree(mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), ALICE))
                .andReturn().getResponse().getContentAsString()), ALICE);
        mockMvc.perform(as(post("/api/collections/" + collectionId + "/rotate-key"), ALICE)
                        .content("{\"memberWrappedKeys\":[{\"memberId\":\"" + ownerId + "\",\"wrappedKey\":\"bmV3\"}],\"itemWrappedKeys\":[]}"))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(delete("/api/collections/" + collectionId + "/members/" + pendingId), ALICE))
                .andExpect(status().isNoContent());
    }

    @Test
    void itemCollectionAssignmentRules() throws Exception {
        String collectionId = createCollection(ALICE, "Rules");
        addMember(ALICE, collectionId, BOB, "VIEWER");
        String itemId = createItem(ALICE, "Assignable");

        // Missing wrapped key → 400.
        mockMvc.perform(as(put("/api/vault/items/" + itemId + "/collection"), ALICE)
                        .content("{\"collectionId\": \"%s\"}".formatted(collectionId)))
                .andExpect(status().isBadRequest());

        // A non-member owner can't assign to a collection they're not in.
        String carolItem = createItem(CAROL, "Carol item");
        mockMvc.perform(as(put("/api/vault/items/" + carolItem + "/collection"), CAROL)
                        .content("""
                                {"collectionId": "%s", "wrappedKey": "eA==", "wrappedKeyIv": "aXY="}
                                """.formatted(collectionId)))
                .andExpect(status().isNotFound());

        putInCollection(ALICE, itemId, collectionId);

        // Items in a collection must stay server-synced.
        mockMvc.perform(as(patch("/api/vault/items/" + itemId + "/sync-mode"), ALICE)
                        .content("{\"syncMode\": \"LOCAL_ONLY\"}"))
                .andExpect(status().isBadRequest());

        // A collection with items cannot be deleted.
        mockMvc.perform(as(delete("/api/collections/" + collectionId), ALICE))
                .andExpect(status().isBadRequest());

        // Remove from collection → collection becomes deletable.
        mockMvc.perform(as(put("/api/vault/items/" + itemId + "/collection"), ALICE)
                        .content("{\"collectionId\": null}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.collectionId").doesNotExist());
        mockMvc.perform(as(delete("/api/collections/" + collectionId), ALICE))
                .andExpect(status().isNoContent());
    }

    private String memberIdOf(String collectionId, String manager, String email) throws Exception {
        String body = mockMvc.perform(as(get("/api/collections/" + collectionId + "/members"), manager))
                .andReturn().getResponse().getContentAsString();
        for (JsonNode member : objectMapper.readTree(body)) {
            if (member.get("memberEmail").asText().equalsIgnoreCase(email)) {
                return member.get("id").asText();
            }
        }
        throw new AssertionError("No member " + email + " in collection " + collectionId);
    }

    @Test
    void rotateKeyUpdatesRemainingMembersAndCollectionItemsButNotRemovedMember() throws Exception {
        String collectionId = createCollection(ALICE, "Rotate");
        String bobMemberId = addMember(ALICE, collectionId, BOB, "VIEWER");
        addMember(ALICE, collectionId, CAROL, "VIEWER");
        String itemId = createItem(ALICE, "Rotatable");
        putInCollection(ALICE, itemId, collectionId);

        String aliceMemberId = memberIdOf(collectionId, ALICE, ALICE);
        String carolMemberId = memberIdOf(collectionId, ALICE, CAROL);

        String rotateBody = """
                {
                  "memberWrappedKeys": [
                    {"memberId": "%s", "wrappedKey": "bmV3QWxpY2VXcmFwcGVk"},
                    {"memberId": "%s", "wrappedKey": "bmV3Q2Fyb2xXcmFwcGVk"}
                  ],
                  "itemWrappedKeys": [
                    {"itemId": "%s", "wrappedKey": "bmV3SXRlbUtleQ==", "wrappedKeyIv": "bmV3SXRlbUl2"}
                  ]
                }
                """.formatted(aliceMemberId, carolMemberId, itemId);
        mockMvc.perform(as(post("/api/collections/" + collectionId + "/rotate-key"), ALICE)
                        .content(rotateBody))
                .andExpect(status().isNoContent());
        mockMvc.perform(as(delete("/api/collections/" + collectionId + "/members/" + bobMemberId), ALICE))
                .andExpect(status().isNoContent());

        // Carol (kept) sees the new collection key and the new item wrap.
        mockMvc.perform(as(get("/api/collections"), CAROL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.id == '%s')].myWrappedKey".formatted(collectionId),
                        hasItem("bmV3Q2Fyb2xXcmFwcGVk")));
        mockMvc.perform(as(get("/api/vault/items/" + itemId), CAROL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.collectionWrappedKey").value("bmV3SXRlbUtleQ=="))
                .andExpect(jsonPath("$.collectionWrappedKeyIv").value("bmV3SXRlbUl2"));

        // Bob (removed) has no access at all — rotation plus revoke together.
        mockMvc.perform(as(get("/api/vault/items/" + itemId), BOB))
                .andExpect(status().isNotFound());
    }

    @Test
    void rotateKeyRequiresManagerAndValidatesItemMembership() throws Exception {
        String collectionId = createCollection(ALICE, "GuardedRotate");
        addMember(ALICE, collectionId, BOB, "EDITOR");

        mockMvc.perform(as(post("/api/collections/" + collectionId + "/rotate-key"), BOB)
                        .content("{\"memberWrappedKeys\": [], \"itemWrappedKeys\": []}"))
                .andExpect(status().isForbidden());

        String otherCollectionId = createCollection(CAROL, "Other");
        String otherItemId = createItem(CAROL, "Not in Rotate");
        putInCollection(CAROL, otherItemId, otherCollectionId);

        String badBody = """
                {"memberWrappedKeys": [], "itemWrappedKeys": [
                  {"itemId": "%s", "wrappedKey": "eA==", "wrappedKeyIv": "aXY="}
                ]}
                """.formatted(otherItemId);
        mockMvc.perform(as(post("/api/collections/" + collectionId + "/rotate-key"), ALICE)
                        .content(badBody))
                .andExpect(status().isBadRequest());
    }

    private static String memberId(JsonNode members, String email) {
        for (JsonNode member : members) {
            if (email.equals(member.get("memberEmail").asText())) return member.get("id").asText();
        }
        throw new AssertionError("Member not found: " + email);
    }
}
