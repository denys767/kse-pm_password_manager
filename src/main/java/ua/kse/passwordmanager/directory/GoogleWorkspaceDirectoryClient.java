package ua.kse.passwordmanager.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.DefaultUriBuilderFactory;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.keys.UserKeysRepository;

/**
 * Google Directory REST client. No service-account key ever exists on disk:
 * tokens for the delegated Workspace admin are minted by (1) calling the IAM
 * Credentials API's signJwt as the caller's own Application Default
 * Credentials (which only needs roles/iam.serviceAccountTokenCreator on the
 * target service account) and (2) exchanging the signed JWT assertion at
 * Google's OAuth token endpoint for a domain-wide-delegated access token.
 * This is the keyless equivalent of ServiceAccountCredentials.createDelegated.
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
    private final RestClient iamCredentials = RestClient.create("https://iamcredentials.googleapis.com/v1/");
    private final RestClient oauth = RestClient.create("https://oauth2.googleapis.com/");
    private final ObjectMapper json;
    private final UserKeysRepository keys;
    private final String customer;
    private final String domain;
    private final String serviceAccountEmail;
    private final String adminEmail;
    private final GoogleCredentials callerCredentials;
    private volatile AccessToken delegatedToken;

    public GoogleWorkspaceDirectoryClient(ObjectMapper json, UserKeysRepository keys,
            @Value("${pm.google-workspace.service-account-email}") String serviceAccountEmail,
            @Value("${pm.google-workspace.admin-email}") String adminEmail,
            @Value("${pm.google-workspace.customer-id:my_customer}") String customer,
            @Value("${pm.google-workspace.domain}") String domain) {
        this.json = json; this.keys = keys; this.customer = customer; this.domain = domain.toLowerCase(Locale.ROOT);
        this.serviceAccountEmail = serviceAccountEmail; this.adminEmail = adminEmail;
        try {
            this.callerCredentials = GoogleCredentials.getApplicationDefault()
                    .createScoped("https://www.googleapis.com/auth/iam");
        } catch (IOException e) {
            throw new IllegalStateException("Cannot load Application Default Credentials to impersonate "
                    + serviceAccountEmail + " (run `gcloud auth application-default login` or attach the "
                    + "caller identity to the compute resource)", e);
        }
    }

    /** Mints (and caches until near-expiry) a domain-wide-delegated access
     * token for {@code adminEmail} without ever touching a private key. */
    private synchronized AccessToken directoryToken() {
        AccessToken cached = delegatedToken;
        if (cached != null && cached.getExpirationTime() != null
                && cached.getExpirationTime().toInstant().isAfter(Instant.now().plusSeconds(60))) {
            return cached;
        }
        AccessToken minted = mintDelegatedToken();
        delegatedToken = minted;
        return minted;
    }

    private AccessToken mintDelegatedToken() {
        try {
            AccessToken caller = callerCredentials.refreshAccessToken();
            long now = Instant.now().getEpochSecond();
            ObjectNode claims = json.createObjectNode()
                    .put("iss", serviceAccountEmail)
                    .put("sub", adminEmail)
                    .put("scope", String.join(" ", SCOPES))
                    .put("aud", "https://oauth2.googleapis.com/token")
                    .put("iat", now)
                    .put("exp", now + 3600);
            String signJwtBody = json.createObjectNode().put("payload", claims.toString()).toString();
            String signResponse = iamCredentials.post()
                    .uri("projects/-/serviceAccounts/{email}:signJwt", serviceAccountEmail)
                    .header("Authorization", "Bearer " + caller.getTokenValue())
                    .header("Content-Type", "application/json")
                    .body(signJwtBody).retrieve().body(String.class);
            String signedJwt = json.readTree(signResponse).path("signedJwt").asText();

            String form = "grant_type=" + enc("urn:ietf:params:oauth:grant-type:jwt-bearer")
                    + "&assertion=" + enc(signedJwt);
            String tokenResponse = oauth.post().uri("token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form).retrieve().body(String.class);
            JsonNode tokenNode = json.readTree(tokenResponse);
            String accessToken = tokenNode.path("access_token").asText();
            long expiresIn = tokenNode.path("expires_in").asLong(3600);
            return new AccessToken(accessToken, Date.from(Instant.now().plusSeconds(expiresIn)));
        } catch (Exception e) {
            throw new BadGatewayException("Cannot mint delegated Google Workspace access token", e);
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
    /** One field's worth of an autocomplete. A leg the Directory rejects (or a
     * domain with no groups at all) must degrade to "no suggestions from this
     * field", never to a 502 that blanks the whole picker. */
    private java.util.stream.Stream<JsonNode> searchLeg(String path, String collection) {
        try {
            return stream(get(path).path(collection));
        } catch (RuntimeException e) {
            log.warn("Google Workspace Directory search leg failed ({}): {}", path, e.getMessage());
            return java.util.stream.Stream.empty();
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
            AccessToken token = directoryToken();
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
