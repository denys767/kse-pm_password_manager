package ua.kse.passwordmanager.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.directory.DirectoryCredentialSummary;

/**
 * Workload Identity Federation as the caller identity: the app authenticates
 * to our own Keycloak as a confidential client using {@code client_credentials}
 * (a machine grant — no human, no reauth policy to expire it), exchanges that
 * OIDC token at Google STS for a federated access token, and uses it exactly
 * like a service-account token to call {@code signJwt}. No Google private key
 * ever exists, and nothing in the chain requires a human to keep it alive.
 *
 * <p>This is the recommended mode off GCP: it needs no downloaded
 * service-account key (workspace admins often will not authorize one) and no
 * GCE/GKE metadata server (not available on-prem).
 */
public class FederatedCallerTokenSource implements CallerTokenSource {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(FederatedCallerTokenSource.class);
    private final org.springframework.web.client.RestClient keycloak;
    private final org.springframework.web.client.RestClient sts;
    private final ObjectMapper json;
    private final String clientId;
    private final String clientSecret;
    private final String audience;
    private volatile String cachedToken;
    private volatile Instant cachedExpiry = Instant.EPOCH;
    private volatile String lastError;

    public FederatedCallerTokenSource(ObjectMapper json, String tokenUrl, String stsUrl, String clientId,
            String clientSecret, String audience) {
        this.json = json;
        this.keycloak = org.springframework.web.client.RestClient.create(tokenUrl);
        this.sts = org.springframework.web.client.RestClient.create(stsUrl);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.audience = audience;
    }

    @Override public synchronized String token() {
        if (cachedToken != null && cachedExpiry.isAfter(Instant.now().plusSeconds(60))) {
            return cachedToken;
        }
        try {
            String federated = exchange(clientCredentialsToken());
            cachedToken = federated;
            // Federated STS tokens are short-lived (typically one hour) and Google
            // does not report their exact expiry in a way worth trusting further
            // out than this; re-minting a few minutes early costs one extra round
            // trip and is cheaper than risking a stale token.
            cachedExpiry = Instant.now().plusSeconds(2700);
            lastError = null;
            return federated;
        } catch (RuntimeException e) {
            lastError = rootCause(e);
            if (cachedToken != null && cachedExpiry.isAfter(Instant.now())) {
                log.warn("Could not renew the federated Google caller token; using the cached one until {}: {}",
                        cachedExpiry, lastError);
                return cachedToken;
            }
            throw e;
        }
    }

    @Override public DirectoryCredentialSummary describe() {
        return new DirectoryCredentialSummary("workload-identity-federation", true,
                "Workload identity federation via Keycloak client " + clientId, lastError);
    }

    /** A machine-to-machine OIDC token from Keycloak: {@code client_credentials}
     * involves no human and nothing that a reauth policy can revoke. */
    private String clientCredentialsToken() {
        try {
            String form = "grant_type=client_credentials&client_id=" + enc(clientId)
                    + "&client_secret=" + enc(clientSecret);
            String response = keycloak.post()
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form).retrieve().body(String.class);
            String token = json.readTree(response).path("access_token").asText();
            if (token.isBlank()) throw new IllegalStateException("Keycloak returned no access_token");
            return token;
        } catch (Exception e) {
            throw new BadGatewayException("Cannot obtain a Keycloak client-credentials token for federation", e);
        }
    }

    /** Exchanges the Keycloak OIDC token at Google STS for a federated access
     * token scoped to call the IAM Credentials API. */
    private String exchange(String subjectToken) {
        try {
            String form = "grant_type=" + enc("urn:ietf:params:oauth:grant-type:token-exchange")
                    + "&requested_token_type=" + enc("urn:ietf:params:oauth:token-type:access_token")
                    + "&subject_token_type=" + enc("urn:ietf:params:oauth:token-type:jwt")
                    + "&subject_token=" + enc(subjectToken)
                    + "&audience=" + enc(audience)
                    + "&scope=" + enc("https://www.googleapis.com/auth/iam");
            String response = sts.post().uri("token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(form).retrieve().body(String.class);
            JsonNode node = json.readTree(response);
            String accessToken = node.path("access_token").asText();
            if (accessToken.isBlank()) throw new IllegalStateException("Google STS returned no access_token");
            return accessToken;
        } catch (Exception e) {
            throw new BadGatewayException("Cannot exchange the federated token at Google STS", e);
        }
    }

    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }

    private static String rootCause(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        String message = cause.getMessage();
        return message == null ? cause.getClass().getSimpleName() : message.replaceAll("\\s+", " ").trim();
    }
}
