package ua.kse.passwordmanager.directory;

/**
 * How this deployment authenticates to Google Workspace.
 *
 * @param mode       identifier of the credential source
 * @param unattended whether the credential renews itself indefinitely. A
 *                   {@code gcloud auth application-default login} credential is
 *                   a user credential: Google's reauth policy expires it within
 *                   hours ({@code invalid_grant / invalid_rapt}) and only a
 *                   human can renew it, so it can never serve a 24/7 deployment.
 * @param detail     human-readable description for the admin screen and logs
 * @param lastError  last credential failure, or null while the credential works
 */
public record DirectoryCredentialSummary(String mode, boolean unattended, String detail, String lastError) {

    public static DirectoryCredentialSummary notConfigured() {
        return new DirectoryCredentialSummary("not-configured", false,
                "Google Workspace Directory is not configured for this deployment", null);
    }
}
