package ua.kse.passwordmanager.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.google.DelegatedTokenMinter;
import ua.kse.passwordmanager.keys.UserKeysRepository;

/**
 * Google Directory REST client. Delegated Directory access tokens are minted
 * by the shared {@link DelegatedTokenMinter} — a service-account key, workload
 * identity federation, or Application Default Credentials, depending on
 * deployment; see {@link ua.kse.passwordmanager.google.GoogleCredentialsConfiguration}.
 */
@Component
// Not @ConditionalOnProperty: that matches an empty value too, so an
// unconfigured deployment would construct this bean and fail startup instead
// of falling back to UnavailableWorkspaceDirectoryClient's explicit 502.
@ConditionalOnExpression("'${pm.google-workspace.service-account-email:}'.trim() != ''")
public class GoogleWorkspaceDirectoryClient implements WorkspaceDirectoryClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GoogleWorkspaceDirectoryClient.class);
    private static final List<String> SCOPES = List.of(
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly");
    // Paths are pre-encoded here with enc(); VALUES_ONLY stops RestClient's
    // default TEMPLATE_AND_VALUES factory from percent-encoding them a second
    // time (which turned "%40"/"%3A" into "%2540"/"%253A" and made every email
    // lookup 404 and every search query 400).
    private final RestClient http = RestClient.builder().uriBuilderFactory(directoryUriFactory()).build();
    private final ObjectMapper json;
    private final UserKeysRepository keys;
    private final DelegatedTokenMinter minter;
    private final String customer;
    private final String domain;
    private final String adminEmail;

    public GoogleWorkspaceDirectoryClient(ObjectMapper json, UserKeysRepository keys, DelegatedTokenMinter minter,
            @Value("${pm.google-workspace.admin-email}") String adminEmail,
            @Value("${pm.google-workspace.customer-id:my_customer}") String customer,
            @Value("${pm.google-workspace.domain}") String domain) {
        this.json = json; this.keys = keys; this.minter = minter; this.customer = customer;
        this.domain = domain.toLowerCase(Locale.ROOT); this.adminEmail = adminEmail;
    }

    /**
     * How this deployment authenticates to Google, and whether that credential
     * can keep working unattended.
     *
     * <p>A credential minted by {@code gcloud auth application-default login} is
     * a <em>user</em> credential: Google's reauth policy expires it after hours
     * ({@code invalid_grant / invalid_rapt}), and no amount of retrying fixes
     * that — a human has to log in again. A service-account key, workload
     * identity federation, or an identity attached to the host renews itself
     * indefinitely.
     */
    @Override public DirectoryCredentialSummary credentials() {
        return minter.describe();
    }

    /**
     * Reports the credential mode once the application is up, and proves the
     * credential actually works. Without this, a deployment whose credentials
     * cannot survive the night looks healthy until the first user tries to
     * share something.
     */
    @org.springframework.context.event.EventListener(org.springframework.boot.context.event.ApplicationReadyEvent.class)
    public void reportCredentialMode() {
        DirectoryCredentialSummary summary = credentials();
        if (summary.unattended()) {
            log.info("Google Workspace credentials: {} ({})", summary.mode(), summary.detail());
        } else {
            log.warn("Google Workspace credentials are NOT usable unattended: {}. Directory sync, sharing "
                    + "suggestions and group provisioning will stop working when the credential expires. "
                    + "Configure workload identity federation (GOOGLE_WORKSPACE federation.* settings), run "
                    + "under an attached service account, or mount a service-account key "
                    + "(GOOGLE_WORKSPACE_CREDENTIALS_PATH).", summary.detail());
        }
        // Probing Google is a network call: never let it hold up startup.
        java.util.concurrent.CompletableFuture.runAsync(this::warmToken);
    }

    /**
     * Keeps a valid delegated token in hand and turns a credential problem into
     * a log line and an admin-visible status well before a user runs into it.
     */
    @org.springframework.scheduling.annotation.Scheduled(
            fixedDelayString = "${pm.google-workspace.token-refresh-ms:600000}",
            initialDelayString = "${pm.google-workspace.token-refresh-ms:600000}")
    public void warmToken() {
        try {
            minter.mint(adminEmail, SCOPES);
        } catch (RuntimeException e) {
            // Already logged and recorded by the minter; nothing further to do
            // here besides not letting the scheduled task die.
        }
    }

    @Override public List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit) {
        String safe = searchTerm(query);
        java.util.Map<String, DirectoryPrincipal> found = new java.util.LinkedHashMap<>();
        if (types.contains(DirectoryPrincipal.Type.USER)) {
            // Directory search matches a single field per request and only by
            // prefix (with the trailing "*"); an autocomplete over "Денис" must
            // therefore hit the name fields too, not just the email.
            for (String leg : safe.isBlank() ? List.of("") : List.of("email:" + safe + "*",
                    "givenName:" + safe + "*", "familyName:" + safe + "*")) {
                for (DirectoryPrincipal principal : users(leg, limit)) {
                    found.putIfAbsent(principal.type() + ":" + principal.id(), principal);
                }
            }
        }
        if (types.contains(DirectoryPrincipal.Type.GROUP)) {
            for (String leg : safe.isBlank() ? List.of("") : List.of("email:" + safe + "*", "name:" + safe + "*")) {
                for (DirectoryPrincipal principal : groups(leg, limit)) {
                    found.putIfAbsent(principal.type() + ":" + principal.id(), principal);
                }
            }
        }
        return found.values().stream().sorted(Comparator.comparing(DirectoryPrincipal::displayName, String.CASE_INSENSITIVE_ORDER))
                .limit(limit).toList();
    }

    /** One unquoted prefix token. The Directory query grammar rejects the
     * request outright otherwise (a bare "email:de" without "*" is a 400 for
     * groups and an exact-match miss for users; a space starts a second term). */
    private static String searchTerm(String query) {
        String cleaned = query == null ? "" : query.trim().replaceAll("[*\"'():\\\\]", "");
        int space = cleaned.indexOf(' ');
        return space < 0 ? cleaned : cleaned.substring(0, space);
    }

    @Override public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
        // A 404 means "no such principal", not a directory outage: surface it as
        // empty so the caller can report a clean "not found" instead of the
        // generic "Google Workspace Directory request failed" gateway error.
        return getIfPresent((type == DirectoryPrincipal.Type.USER ? "users/" : "groups/") + enc(id))
                .flatMap(node -> type == DirectoryPrincipal.Type.USER ? user(node) : group(node));
    }

    @Override public List<String> memberEmails(String groupId) {
        return memberEmails(groupId, new java.util.HashSet<>()).stream().distinct().sorted().toList();
    }

    /** Directory membership lists can contain nested GROUP members. Traverse
     * them by immutable ID with a cycle guard; do not rely on Keycloak claims
     * or a server-side derived-membership flag. */
    private List<String> memberEmails(String groupId, java.util.Set<String> visitedGroups) {
        if (!visitedGroups.add(groupId)) return List.of();
        List<String> emails = new ArrayList<>(); String page = null;
        do {
            String path = "groups/" + enc(groupId) + "/members?maxResults=200" + (page == null ? "" : "&pageToken=" + enc(page));
            JsonNode root = get(path);
            for (JsonNode member : root.path("members")) {
                if ("USER".equals(member.path("type").asText()) && isInternal(member.path("email").asText())) emails.add(member.path("email").asText().toLowerCase(Locale.ROOT));
                if ("GROUP".equals(member.path("type").asText())) {
                    String nestedId = member.path("id").asText(member.path("email").asText());
                    if (!nestedId.isBlank()) emails.addAll(memberEmails(nestedId, visitedGroups));
                }
            }
            page = root.path("nextPageToken").isMissingNode() ? null : root.path("nextPageToken").asText(null);
        } while (page != null && !page.isBlank());
        return emails;
    }

    @Override public List<DirectoryUser> listUsers() {
        List<DirectoryUser> users = new ArrayList<>(); String page = null;
        do {
            String path = "users?customer=" + enc(customer) + "&maxResults=500&orderBy=EMAIL"
                    + (page == null ? "" : "&pageToken=" + enc(page));
            JsonNode root = get(path);
            for (JsonNode node : root.path("users")) {
                String email = node.path("primaryEmail").asText();
                if (isInternal(email)) users.add(new DirectoryUser(node.path("id").asText(),
                        email.toLowerCase(Locale.ROOT), node.path("name").path("fullName").asText(email),
                        node.path("isAdmin").asBoolean(false), node.path("suspended").asBoolean(false),
                        node.path("thumbnailPhotoEtag").asText(null)));
            }
            page = root.path("nextPageToken").asText(null);
        } while (page != null && !page.isBlank());
        return users;
    }

    @Override public List<DirectoryGroup> listGroups() {
        List<DirectoryGroup> groups = new ArrayList<>(); String page = null;
        do {
            String path = "groups?customer=" + enc(customer) + "&maxResults=200&orderBy=EMAIL"
                    + (page == null ? "" : "&pageToken=" + enc(page));
            JsonNode root = get(path);
            for (JsonNode node : root.path("groups")) {
                String email = node.path("email").asText();
                if (isInternal(email)) {
                    long count; try { count = Long.parseLong(node.path("directMembersCount").asText("0")); }
                    catch (NumberFormatException ignored) { count = 0; }
                    groups.add(new DirectoryGroup(node.path("id").asText(), email.toLowerCase(Locale.ROOT),
                            node.path("name").asText(email), count));
                }
            }
            page = root.path("nextPageToken").asText(null);
        } while (page != null && !page.isBlank());
        return groups;
    }

    /** @param query a complete Directory query expression ("email:ann*"), or blank to list. */
    private List<DirectoryPrincipal> users(String query, int limit) {
        String path = "users?customer=" + enc(customer) + "&maxResults=" + Math.min(limit, 100) + "&orderBy=EMAIL";
        if (!query.isBlank()) path += "&query=" + enc(query);
        return searchLeg(path, "users").map(this::user).flatMap(Optional::stream).toList();
    }
    private List<DirectoryPrincipal> groups(String query, int limit) {
        String path = "groups?customer=" + enc(customer) + "&maxResults=" + Math.min(limit, 100) + "&orderBy=EMAIL";
        if (!query.isBlank()) path += "&query=" + enc(query);
        return searchLeg(path, "groups").map(this::group).flatMap(Optional::stream).toList();
    }
    /**
     * One field's worth of an autocomplete. A query expression this Directory
     * rejects (or a domain with no groups at all) means "no suggestions from
     * this field" and must not blank the whole picker.
     *
     * <p>Anything else — an expired credential, a 403, a network failure — is a
     * real outage and is deliberately allowed out: swallowing it turned every
     * credential problem into a picker that silently showed nobody, and hid the
     * failure from the caller that can still answer from the local snapshot.
     */
    private java.util.stream.Stream<JsonNode> searchLeg(String path, String collection) {
        try {
            return stream(get(path).path(collection));
        } catch (BadGatewayException e) {
            if (e.getCause() instanceof org.springframework.web.client.HttpClientErrorException rejected
                    && rejected.getStatusCode() == org.springframework.http.HttpStatus.BAD_REQUEST) {
                log.warn("Google Workspace Directory rejected a search leg ({}): {}", path, rejected.getMessage());
                return java.util.stream.Stream.empty();
            }
            throw e;
        }
    }
    private Optional<DirectoryPrincipal> user(JsonNode n) {
        String email = n.path("primaryEmail").asText();
        if (!isInternal(email) || n.path("suspended").asBoolean(false)) return Optional.empty();
        String name = n.path("name").path("fullName").asText(email);
        return Optional.of(new DirectoryPrincipal(DirectoryPrincipal.Type.USER, n.path("id").asText(), email, name, keys.existsById(email.toLowerCase(Locale.ROOT)), null, true, null));
    }
    private Optional<DirectoryPrincipal> group(JsonNode n) {
        String email = n.path("email").asText(); if (!isInternal(email)) return Optional.empty();
        long count; try { count = Long.parseLong(n.path("directMembersCount").asText("0")); } catch (NumberFormatException e) { count = 0; }
        // visibleToUsers is governance state, not Directory data; DirectoryController
        // resolves and overwrites it before this principal reaches a caller. The
        // avatar is likewise hydrated there from the local Workspace snapshot.
        return Optional.of(new DirectoryPrincipal(DirectoryPrincipal.Type.GROUP, n.path("id").asText(), email, n.path("name").asText(email), false, count, true, null));
    }
    private JsonNode get(String path) {
        try {
            AccessToken token = minter.mint(adminEmail, SCOPES);
            String body = http.get().uri(path).header("Authorization", "Bearer " + token.getTokenValue()).retrieve().body(String.class);
            return json.readTree(body);
        } catch (BadGatewayException e) { throw e; }
        catch (Exception e) { throw new BadGatewayException("Google Workspace Directory request failed", e); }
    }
    /** Like {@link #get} but a 404 (principal does not exist) is an expected
     * empty result rather than a gateway failure. */
    private Optional<JsonNode> getIfPresent(String path) {
        try {
            return Optional.of(get(path));
        } catch (BadGatewayException e) {
            if (e.getCause() instanceof org.springframework.web.client.HttpClientErrorException.NotFound) {
                return Optional.empty();
            }
            throw e;
        }
    }
    /**
     * Downloads a user's profile photo and returns it as a data: URI.
     *
     * users.photos.get answers base64url (RFC 4648 §5) rather than standard
     * base64, and 404s for an account that never set a photo — an expected
     * answer, not a gateway failure.
     */
    @Override public Optional<String> userPhotoDataUrl(String userKey) {
        return getIfPresent("users/" + enc(userKey) + "/photos/thumbnail").flatMap(node -> {
            String data = node.path("photoData").asText(null);
            if (data == null || data.isBlank()) return Optional.empty();
            byte[] decoded;
            try {
                decoded = java.util.Base64.getUrlDecoder().decode(data);
            } catch (IllegalArgumentException e) {
                log.warn("Google Workspace returned an undecodable photo for {}", userKey);
                return Optional.empty();
            }
            String mime = node.path("mimeType").asText("image/jpeg");
            return Optional.of("data:" + mime + ";base64," + java.util.Base64.getEncoder().encodeToString(decoded));
        });
    }

    private boolean isInternal(String email) { return email != null && email.toLowerCase(Locale.ROOT).endsWith("@" + domain); }
    private static DefaultUriBuilderFactory directoryUriFactory() {
        DefaultUriBuilderFactory factory = new DefaultUriBuilderFactory("https://admin.googleapis.com/admin/directory/v1/");
        factory.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.VALUES_ONLY);
        return factory;
    }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static java.util.stream.Stream<JsonNode> stream(JsonNode node) { Collection<JsonNode> values = new ArrayList<>(); node.forEach(values::add); return values.stream(); }
}
