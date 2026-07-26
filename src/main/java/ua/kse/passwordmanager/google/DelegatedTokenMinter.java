package ua.kse.passwordmanager.google;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.auth.oauth2.AccessToken;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.directory.DirectoryCredentialSummary;

/**
 * Mints (and caches until near-expiry) domain-wide-delegated access tokens
 * for any subject email — the shared token path for both the Directory client
 * and the Drive attachment store, so both benefit from the same caching,
 * near-expiry margin and stale-token fallback instead of each re-implementing
 * it.
 *
 * <p>Two ways to sign the delegation assertion, selected once at construction:
 * a service-account key signs it locally (works anywhere, but needs a
 * downloaded private key); otherwise a {@link CallerTokenSource} — workload
 * identity federation or Application Default Credentials — signs it by
 * calling the IAM Credentials API's {@code signJwt} and exchanging the result
 * at Google's OAuth token endpoint. Either way the resulting Directory/Drive
 * access token is short-lived and cached until near-expiry.
 */
public class DelegatedTokenMinter {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DelegatedTokenMinter.class);
    private final ObjectMapper json;
    private final org.springframework.web.client.RestClient iamCredentials =
            org.springframework.web.client.RestClient.create("https://iamcredentials.googleapis.com/v1/");
    private final org.springframework.web.client.RestClient oauth =
            org.springframework.web.client.RestClient.create("https://oauth2.googleapis.com/");
    private final String serviceAccountEmail;
    private final String keyPath;
    private final CallerTokenSource callerTokenSource;
    private final Map<String, AccessToken> cache = new ConcurrentHashMap<>();
    private volatile GoogleCredentials delegatedKeyCredentials;
    private volatile String lastError;

    /** Service-account key mode: {@code keyPath} non-blank, {@code callerTokenSource} unused. */
    public DelegatedTokenMinter(ObjectMapper json, String serviceAccountEmail, String keyPath) {
        this(json, serviceAccountEmail, keyPath, null);
    }

    /** Keyless mode: signs via {@code callerTokenSource} + the IAM Credentials API. */
    public DelegatedTokenMinter(ObjectMapper json, String serviceAccountEmail, CallerTokenSource callerTokenSource) {
        this(json, serviceAccountEmail, "", callerTokenSource);
    }

    private DelegatedTokenMinter(ObjectMapper json, String serviceAccountEmail, String keyPath,
            CallerTokenSource callerTokenSource) {
        this.json = json;
        this.serviceAccountEmail = serviceAccountEmail;
        this.keyPath = keyPath == null ? "" : keyPath.trim();
        this.callerTokenSource = callerTokenSource;
    }

    public DirectoryCredentialSummary describe() {
        if (!keyPath.isEmpty()) {
            return new DirectoryCredentialSummary("service-account-key", true,
                    "Domain-wide delegation with the service-account key at " + keyPath, lastError);
        }
        DirectoryCredentialSummary callerSummary = callerTokenSource.describe();
        return new DirectoryCredentialSummary(callerSummary.mode(), callerSummary.unattended(),
                callerSummary.detail(), lastError == null ? callerSummary.lastError() : lastError);
    }

    /** A delegated access token for {@code subjectEmail}, cached per (subject,
     * scopes) until 60 seconds before expiry. Falls back to a still-valid
     * cached token if renewal fails: the caller identity can start failing
     * (reauth, revoked grant, a Keycloak outage) at any moment, and there is
     * no reason to break Directory/Drive calls before the token already in
     * hand actually expires. */
    public AccessToken mint(String subjectEmail, List<String> scopes) {
        String cacheKey = subjectEmail + "|" + String.join(",", scopes);
        AccessToken cached = cache.get(cacheKey);
        if (cached != null && expiresAfter(cached, Instant.now().plusSeconds(60))) {
            return cached;
        }
        try {
            AccessToken minted = keyPath.isEmpty() ? mintViaCallerToken(subjectEmail, scopes)
                    : mintWithServiceAccountKey(subjectEmail, scopes);
            cache.put(cacheKey, minted);
            lastError = null;
            return minted;
        } catch (BadGatewayException e) {
            lastError = rootCause(e);
            if (cached != null && expiresAfter(cached, Instant.now())) {
                log.warn("Could not renew the delegated Google token for {}; using the cached one until {}: {}",
                        subjectEmail, cached.getExpirationTime(), lastError);
                return cached;
            }
            throw e;
        }
    }

    private static boolean expiresAfter(AccessToken token, Instant moment) {
        return token.getExpirationTime() != null && token.getExpirationTime().toInstant().isAfter(moment);
    }

    /** Domain-wide delegation straight from a service-account key: the key
     * signs the assertion locally, so there is no caller identity in the
     * chain that can expire, no IAM Credentials call, and nothing to
     * re-authenticate. The key is read from disk on every reload rather than
     * held forever, so rotating the mounted file takes effect without a
     * restart. */
    private AccessToken mintWithServiceAccountKey(String subjectEmail, List<String> scopes) {
        try {
            GoogleCredentials delegated = delegatedKeyCredentials;
            if (delegated == null) {
                try (InputStream key = Files.newInputStream(Path.of(keyPath))) {
                    delegated = ServiceAccountCredentials.fromStream(key);
                }
                delegatedKeyCredentials = delegated;
            }
            GoogleCredentials scopedDelegated = ((ServiceAccountCredentials) delegated)
                    .createScoped(scopes).createDelegated(subjectEmail);
            scopedDelegated.refresh();
            AccessToken token = scopedDelegated.getAccessToken();
            if (token == null) throw new IllegalStateException("Google returned no access token");
            return token;
        } catch (Exception e) {
            // Drop the cached credential so a rotated or repaired key file is
            // picked up by the next attempt.
            delegatedKeyCredentials = null;
            log.error("Cannot mint a domain-wide-delegated token with the service-account key at {} for {}: {}",
                    keyPath, subjectEmail, rootCause(e), e);
            throw new BadGatewayException("Google Workspace Directory is temporarily unavailable", e);
        }
    }

    /** Signs and exchanges the delegation assertion using the caller token
     * source (federation or ADC) to authorize the IAM Credentials API call. */
    private AccessToken mintViaCallerToken(String subjectEmail, List<String> scopes) {
        try {
            String callerToken = callerTokenSource.token();
            long now = Instant.now().getEpochSecond();
            ObjectNode claims = json.createObjectNode()
                    .put("iss", serviceAccountEmail)
                    .put("sub", subjectEmail)
                    .put("scope", String.join(" ", scopes))
                    .put("aud", "https://oauth2.googleapis.com/token")
                    .put("iat", now)
                    .put("exp", now + 3600);
            String signJwtBody = json.createObjectNode().put("payload", claims.toString()).toString();
            String signResponse = iamCredentials.post()
                    .uri("projects/-/serviceAccounts/{email}:signJwt", serviceAccountEmail)
                    .header("Authorization", "Bearer " + callerToken)
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
        } catch (RuntimeException e) {
            throw wrapped(e, subjectEmail);
        } catch (Exception e) {
            throw wrapped(e, subjectEmail);
        }
    }

    /** Google reports a stale/reauth-required refresh token as invalid_grant;
     * the fix is operator action (renew federation or ADC), so name it in the
     * message. */
    private static RuntimeException wrapped(Exception failure, String subjectEmail) {
        if (failure instanceof BadGatewayException b) return b;
        String message = String.valueOf(rootCause(failure));
        String hint = "";
        if (message.contains("invalid_rapt") || message.contains("reauth")) {
            hint = ". The caller identity needs a fresh Google reauthentication: run "
                    + "`gcloud auth application-default login`, or configure workload identity federation / an "
                    + "attached service account so no user credential is involved";
        } else if (message.contains("invalid_grant")) {
            hint = ". The caller identity's credentials are expired or revoked: check workload identity "
                    + "federation (Keycloak client secret, GCP IAM binding) or the attached service account";
        }
        log.error("Cannot mint delegated Google access token for {}: {}{}", subjectEmail, message, hint, failure);
        return new BadGatewayException("Google Workspace Directory is temporarily unavailable", failure);
    }

    private static String rootCause(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        String message = cause.getMessage();
        return message == null ? cause.getClass().getSimpleName() : message.replaceAll("\\s+", " ").trim();
    }

    private static String enc(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
