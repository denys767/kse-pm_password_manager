package ua.kse.passwordmanager.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Public bootstrap config for the SPA: which auth mode is active and, for
 * OIDC, where Keycloak lives. Contains no secrets — the client id of a
 * public PKCE client is not confidential.
 */
@RestController
public class ConfigController {

    private final Environment environment;

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}")
    private String issuerUri;

    @Value("${pm.oidc.client-id:kse-pm-web}")
    private String clientId;

    // Fixed by the "key" field pinned in extension/public/manifest.json — Chrome
    // derives the extension ID from that key, so it does not change per deployment.
    @Value("${pm.extension.id:plpbigigggfkcpcbkejobhmjjfnnpomh}")
    private String extensionId;

    public ConfigController(Environment environment) {
        this.environment = environment;
    }

    @GetMapping("/api/config")
    public FrontendConfig config() {
        boolean dev = environment.matchesProfiles("dev");
        if (dev || issuerUri.isBlank()) {
            return new FrontendConfig("dev-headers", null, null, null, extensionId);
        }
        // issuer-uri looks like https://sso.example.com/realms/kse-pm
        int marker = issuerUri.lastIndexOf("/realms/");
        String keycloakUrl = marker > 0 ? issuerUri.substring(0, marker) : issuerUri;
        String realm = marker > 0 ? issuerUri.substring(marker + "/realms/".length()) : "";
        return new FrontendConfig("oidc", keycloakUrl, realm, clientId, extensionId);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FrontendConfig(String authMode, String keycloakUrl, String realm,
                                 String clientId, String extensionId) {
    }
}
