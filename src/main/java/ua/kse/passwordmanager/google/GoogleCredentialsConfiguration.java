package ua.kse.passwordmanager.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Picks how this deployment signs Google domain-wide-delegation assertions,
 * in order of preference:
 *
 * <ol>
 *   <li>a mounted service-account key ({@code credentials-path}) — signs
 *       locally, works anywhere, but needs a downloaded private key that
 *       Workspace admins may not authorize;
 *   <li>workload identity federation ({@code federation.token-url}) — the app
 *       authenticates to our own Keycloak with a machine grant and exchanges
 *       that token at Google STS; keyless and works off GCP, the recommended
 *       mode when a key is not an option;
 *   <li>Application Default Credentials — an attached service account on
 *       GCE/GKE (keyless) or, failing that, a {@code gcloud auth
 *       application-default login} user credential that cannot survive
 *       unattended.
 * </ol>
 *
 * <p>Every mode is exposed through the same {@link DelegatedTokenMinter}, so
 * {@code GoogleWorkspaceDirectoryClient} and {@code GoogleDriveAttachmentStore}
 * share one cache, one near-expiry margin and one stale-token fallback.
 */
@Configuration
public class GoogleCredentialsConfiguration {

    /**
     * The single condition every Google-backed bean shares, so a deployment
     * either has working credentials or falls back to the {@code Unavailable*}
     * clients as a unit. They used to disagree — the Drive store activated on
     * either setting while the Directory client needed the service-account
     * email — so a key-only configuration got a live Drive store and a silently
     * unavailable Directory.
     *
     * <p>Not {@code @ConditionalOnProperty}: that matches a declared-but-empty
     * value, so a deployment that maps these settings through without setting
     * them would construct the beans and fail startup instead of degrading.
     */
    public static final String CONFIGURED = "'${pm.google-workspace.service-account-email:}'.trim() != '' "
            + "or '${pm.google-workspace.credentials-path:}'.trim() != ''";

    @Bean
    @ConditionalOnExpression(CONFIGURED)
    DelegatedTokenMinter delegatedTokenMinter(ObjectMapper json,
            @Value("${pm.google-workspace.service-account-email:}") String serviceAccountEmail,
            @Value("${pm.google-workspace.credentials-path:}") String keyPath,
            @Value("${pm.google-workspace.federation.token-url:}") String federationTokenUrl,
            @Value("${pm.google-workspace.federation.sts-url:https://sts.googleapis.com/v1/}") String federationStsUrl,
            @Value("${pm.google-workspace.federation.client-id:}") String federationClientId,
            @Value("${pm.google-workspace.federation.client-secret:}") String federationClientSecret,
            @Value("${pm.google-workspace.federation.audience:}") String federationAudience) {
        String key = keyPath == null ? "" : keyPath.trim();
        if (!key.isEmpty()) {
            return new DelegatedTokenMinter(json, serviceAccountEmail, key);
        }
        CallerTokenSource callerTokenSource = federationTokenUrl != null && !federationTokenUrl.isBlank()
                ? new FederatedCallerTokenSource(json, federationTokenUrl, federationStsUrl, federationClientId,
                        federationClientSecret, federationAudience)
                : new ApplicationDefaultCallerTokenSource(serviceAccountEmail);
        return new DelegatedTokenMinter(json, serviceAccountEmail, callerTokenSource);
    }
}
