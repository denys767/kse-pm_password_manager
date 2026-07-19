package ua.kse.passwordmanager.keycloak;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import ua.kse.passwordmanager.common.BadGatewayException;

/** Read-only Keycloak Admin REST client used to suggest, never provision, collection members. */
@Component
public class KeycloakAdminClient {

    private final RestClient http;
    private final URI issuer;
    private final String realm;
    private final String clientSecret;

    @Autowired
    public KeycloakAdminClient(RestClient.Builder builder,
                               @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer,
                               @Value("${pm.keycloak.admin-client-secret:}") String clientSecret) {
        this(builder.build(), issuer, clientSecret);
    }

    KeycloakAdminClient(RestClient http, String issuer, String clientSecret) {
        this.http = http;
        this.issuer = URI.create(issuer.replaceAll("/+$", ""));
        String path = this.issuer.getPath();
        int realmIndex = path.lastIndexOf("/realms/");
        if (realmIndex < 0 || realmIndex + "/realms/".length() >= path.length()) {
            throw new IllegalArgumentException("Keycloak issuer must end with /realms/{realm}");
        }
        this.realm = path.substring(realmIndex + "/realms/".length());
        this.clientSecret = clientSecret;
    }

    public List<String> membersOfGroup(String groupName) {
        String token = accessToken();
        Group[] groups = get(groupsUri(groupName), token, Group[].class);
        Group group = Arrays.stream(groups == null ? new Group[0] : groups)
                .filter(candidate -> groupName.equals(candidate.name()))
                .findFirst()
                .orElse(null);
        if (group == null) {
            return List.of();
        }
        User[] members = get(adminUri("groups/" + group.id() + "/members"), token, User[].class);
        return Arrays.stream(members == null ? new User[0] : members)
                .map(User::email)
                .filter(Objects::nonNull)
                .filter(email -> !email.isBlank())
                .toList();
    }

    private String accessToken() {
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new BadGatewayException("KEYCLOAK_ADMIN_CLIENT_SECRET is not configured");
        }
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", "kse-pm-admin");
        form.add("client_secret", clientSecret);
        Token token;
        try {
            token = http.post().uri(issuer + "/protocol/openid-connect/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form)
                    .retrieve().body(Token.class);
        } catch (RuntimeException e) {
            throw new BadGatewayException("Keycloak admin token request failed", e);
        }
        if (token == null || token.accessToken() == null || token.accessToken().isBlank()) {
            throw new BadGatewayException("Keycloak admin token response did not include access_token");
        }
        return token.accessToken();
    }

    private <T> T get(URI uri, String token, Class<T> bodyType) {
        try {
            return http.get().uri(uri).headers(headers -> headers.setBearerAuth(token))
                    .retrieve().body(bodyType);
        } catch (RuntimeException e) {
            throw new BadGatewayException("Keycloak admin request failed", e);
        }
    }

    private URI groupsUri(String groupName) {
        return URI.create(adminUri("groups").toString() + "?search="
                + java.net.URLEncoder.encode(groupName, java.nio.charset.StandardCharsets.UTF_8));
    }

    private URI adminUri(String suffix) {
        String basePath = issuer.getPath().substring(0, issuer.getPath().lastIndexOf("/realms/"));
        return URI.create(issuer.getScheme() + "://" + issuer.getAuthority() + basePath
                + "/admin/realms/" + realm + "/" + suffix);
    }

    private record Token(@JsonProperty("access_token") String accessToken) { }
    private record Group(String id, String name) { }
    private record User(String email) { }
}
