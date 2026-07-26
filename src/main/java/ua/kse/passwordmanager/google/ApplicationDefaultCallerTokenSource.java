package ua.kse.passwordmanager.google;

import com.google.auth.oauth2.GoogleCredentials;
import java.io.IOException;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.directory.DirectoryCredentialSummary;

/**
 * Application Default Credentials as the caller identity: an attached service
 * account on GCE/GKE (keyless, renews itself indefinitely) or, if a human ran
 * {@code gcloud auth application-default login}, a user credential that
 * Google's reauth policy expires within hours ({@code invalid_grant} /
 * {@code invalid_rapt}) — reported as {@code unattended = false} so an
 * operator sees the problem before a user does.
 */
public class ApplicationDefaultCallerTokenSource implements CallerTokenSource {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ApplicationDefaultCallerTokenSource.class);
    private final String serviceAccountEmail;
    private volatile GoogleCredentials credentials;

    public ApplicationDefaultCallerTokenSource(String serviceAccountEmail) {
        this.serviceAccountEmail = serviceAccountEmail;
        this.credentials = load(false);
    }

    @Override public String token() {
        GoogleCredentials current = credentials;
        try {
            if (current == null) {
                current = load(true);
                credentials = current;
            }
            return current.refreshAccessToken().getTokenValue();
        } catch (RuntimeException | IOException first) {
            log.warn("Refreshing Application Default Credentials for {} failed ({}); reloading and retrying once",
                    serviceAccountEmail, rootCause(first));
            GoogleCredentials reloaded = load(true);
            credentials = reloaded;
            try {
                return reloaded.refreshAccessToken().getTokenValue();
            } catch (IOException retry) {
                throw new BadGatewayException("Cannot refresh Application Default Credentials", retry);
            }
        }
    }

    @Override public DirectoryCredentialSummary describe() {
        GoogleCredentials adc = credentials;
        if (adc == null) {
            return new DirectoryCredentialSummary("none", false,
                    "No credentials: set pm.google-workspace.credentials-path, workload identity federation, or "
                            + "provide Application Default Credentials for " + serviceAccountEmail, null);
        }
        boolean unattended = !(adc instanceof com.google.auth.oauth2.UserCredentials);
        String type = adc.getClass().getSimpleName();
        return new DirectoryCredentialSummary(unattended ? "impersonation" : "impersonation-user-adc", unattended,
                unattended
                        ? type + " impersonating " + serviceAccountEmail
                        : "gcloud user credentials impersonating " + serviceAccountEmail
                                + " — Google's reauth policy expires these within hours; not usable unattended",
                null);
    }

    private GoogleCredentials load(boolean required) {
        try {
            return GoogleCredentials.getApplicationDefault().createScoped("https://www.googleapis.com/auth/iam");
        } catch (IOException e) {
            if (required) {
                log.error("Cannot load Application Default Credentials to impersonate {} (run "
                        + "`gcloud auth application-default login` or attach the caller identity to the "
                        + "compute resource): {}", serviceAccountEmail, e.getMessage(), e);
                throw new BadGatewayException("Google Workspace Directory is temporarily unavailable", e);
            }
            log.warn("Application Default Credentials are not available yet; Google Workspace Directory calls "
                    + "will fail until they are (run `gcloud auth application-default login` or attach the "
                    + "caller identity to the compute resource): {}", e.getMessage());
            return null;
        }
    }

    private static String rootCause(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        String message = cause.getMessage();
        return message == null ? cause.getClass().getSimpleName() : message.replaceAll("\\s+", " ").trim();
    }
}
