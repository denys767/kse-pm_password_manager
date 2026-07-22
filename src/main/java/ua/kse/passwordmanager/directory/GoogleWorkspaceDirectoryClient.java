package ua.kse.passwordmanager.directory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.keys.UserKeysRepository;

/**
 * Google Directory REST client. Tokens are minted from a service-account key;
 * the account is delegated to a Workspace administrator in production.
 */
@Component
@ConditionalOnProperty(name = "pm.google-workspace.credentials-path")
public class GoogleWorkspaceDirectoryClient implements WorkspaceDirectoryClient {
    private static final List<String> SCOPES = List.of(
            "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.readonly",
            "https://www.googleapis.com/auth/admin.directory.group.member.readonly");
    private final RestClient http = RestClient.create("https://admin.googleapis.com/admin/directory/v1/");
    private final ObjectMapper json;
    private final UserKeysRepository keys;
    private final String customer;
    private final String domain;
    private final GoogleCredentials credentials;

    public GoogleWorkspaceDirectoryClient(ObjectMapper json, UserKeysRepository keys,
            @Value("${pm.google-workspace.credentials-path}") String credentialsPath,
            @Value("${pm.google-workspace.admin-email}") String adminEmail,
            @Value("${pm.google-workspace.customer-id:my_customer}") String customer,
            @Value("${pm.google-workspace.domain}") String domain) {
        this.json = json; this.keys = keys; this.customer = customer; this.domain = domain.toLowerCase(Locale.ROOT);
        try (FileInputStream in = new FileInputStream(credentialsPath)) {
            ServiceAccountCredentials service = ServiceAccountCredentials.fromStream(in);
            this.credentials = service.createScoped(SCOPES).createDelegated(adminEmail);
        } catch (IOException e) { throw new IllegalStateException("Cannot load Google Workspace credentials", e); }
    }

    @Override public List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit) {
        String safe = query == null ? "" : query.trim();
        List<DirectoryPrincipal> found = new ArrayList<>();
        if (types.contains(DirectoryPrincipal.Type.USER)) found.addAll(users(safe, limit));
        if (types.contains(DirectoryPrincipal.Type.GROUP)) found.addAll(groups(safe, limit));
        return found.stream().sorted(Comparator.comparing(DirectoryPrincipal::displayName, String.CASE_INSENSITIVE_ORDER))
                .limit(limit).toList();
    }

    @Override public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
        try {
            JsonNode node = get((type == DirectoryPrincipal.Type.USER ? "users/" : "groups/") + enc(id));
            return type == DirectoryPrincipal.Type.USER ? user(node) : group(node);
        } catch (BadGatewayException e) { throw e; }
        catch (RuntimeException e) { return Optional.empty(); }
    }

    @Override public List<String> memberEmails(String groupId) {
        List<String> emails = new ArrayList<>(); String page = null;
        do {
            String path = "groups/" + enc(groupId) + "/members?includeDerivedMembership=true&maxResults=200" + (page == null ? "" : "&pageToken=" + enc(page));
            JsonNode root = get(path);
            for (JsonNode member : root.path("members")) {
                if ("USER".equals(member.path("type").asText()) && isInternal(member.path("email").asText())) emails.add(member.path("email").asText().toLowerCase(Locale.ROOT));
            }
            page = root.path("nextPageToken").isMissingNode() ? null : root.path("nextPageToken").asText(null);
        } while (page != null && !page.isBlank());
        return emails.stream().distinct().sorted().toList();
    }

    private List<DirectoryPrincipal> users(String query, int limit) {
        String path = "users?customer=" + enc(customer) + "&maxResults=" + Math.min(limit, 100) + "&orderBy=EMAIL";
        if (!query.isBlank()) path += "&query=" + enc("email:" + query);
        return stream(get(path).path("users")).map(this::user).flatMap(Optional::stream).toList();
    }
    private List<DirectoryPrincipal> groups(String query, int limit) {
        String path = "groups?customer=" + enc(customer) + "&maxResults=" + Math.min(limit, 100) + "&orderBy=EMAIL";
        if (!query.isBlank()) path += "&query=" + enc("email:" + query);
        return stream(get(path).path("groups")).map(this::group).flatMap(Optional::stream).toList();
    }
    private Optional<DirectoryPrincipal> user(JsonNode n) {
        String email = n.path("primaryEmail").asText();
        if (!isInternal(email) || n.path("suspended").asBoolean(false)) return Optional.empty();
        String name = n.path("name").path("fullName").asText(email);
        return Optional.of(new DirectoryPrincipal(DirectoryPrincipal.Type.USER, n.path("id").asText(), email, name, keys.existsById(email.toLowerCase(Locale.ROOT)), null));
    }
    private Optional<DirectoryPrincipal> group(JsonNode n) {
        String email = n.path("email").asText(); if (!isInternal(email)) return Optional.empty();
        long count; try { count = Long.parseLong(n.path("directMembersCount").asText("0")); } catch (NumberFormatException e) { count = 0; }
        return Optional.of(new DirectoryPrincipal(DirectoryPrincipal.Type.GROUP, n.path("id").asText(), email, n.path("name").asText(email), false, count));
    }
    private JsonNode get(String path) {
        try {
            AccessToken token = credentials.refreshAccessToken();
            String body = http.get().uri(path).header("Authorization", "Bearer " + token.getTokenValue()).retrieve().body(String.class);
            return json.readTree(body);
        } catch (Exception e) { throw new BadGatewayException("Google Workspace Directory request failed", e); }
    }
    private boolean isInternal(String email) { return email != null && email.toLowerCase(Locale.ROOT).endsWith("@" + domain); }
    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static java.util.stream.Stream<JsonNode> stream(JsonNode node) { Collection<JsonNode> values = new ArrayList<>(); node.forEach(values::add); return values.stream(); }
}
