package ua.kse.passwordmanager.google;

import ua.kse.passwordmanager.directory.DirectoryCredentialSummary;

/**
 * The identity that calls the IAM Credentials API's {@code signJwt} on the
 * target service account to sign a domain-wide-delegation assertion. Whether
 * this identity can renew itself forever (a service account, a federated
 * workload identity) or dies after hours (a {@code gcloud auth
 * application-default login} user credential) is exactly what {@link
 * DirectoryCredentialSummary#unattended()} reports.
 */
public interface CallerTokenSource {
    /** A Google access token for the caller identity. Callers must not cache
     * this beyond a single request: implementations already cache and
     * refresh internally. */
    String token();

    DirectoryCredentialSummary describe();
}
