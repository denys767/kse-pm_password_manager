package ua.kse.passwordmanager.directory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import ua.kse.passwordmanager.google.ApplicationDefaultCallerTokenSource;
import ua.kse.passwordmanager.google.DelegatedTokenMinter;
import ua.kse.passwordmanager.google.FederatedCallerTokenSource;
import ua.kse.passwordmanager.keys.UserKeysRepository;

/**
 * A deployment has to be able to tell, without waiting for the outage, whether
 * its Google credential can run unattended.
 */
class DirectoryCredentialModeTest {
    private static final String SERVICE_ACCOUNT = "directory-sync@example.iam.gserviceaccount.com";
    private static final String ADMIN = "workspace-admin@kse.org.ua";

    private GoogleWorkspaceDirectoryClient client(DelegatedTokenMinter minter) {
        return new GoogleWorkspaceDirectoryClient(new ObjectMapper(), mock(UserKeysRepository.class), minter,
                ADMIN, "my_customer", "kse.org.ua");
    }

    @Test
    void aServiceAccountKeyIsUnattended() {
        DelegatedTokenMinter minter = new DelegatedTokenMinter(new ObjectMapper(), SERVICE_ACCOUNT,
                "/run/secrets/workspace-sa.json");
        DirectoryCredentialSummary summary = client(minter).credentials();

        assertThat(summary.mode()).isEqualTo("service-account-key");
        assertThat(summary.unattended()).isTrue();
        assertThat(summary.detail()).contains("/run/secrets/workspace-sa.json");
    }

    @Test
    void workloadIdentityFederationIsUnattended() {
        DelegatedTokenMinter minter = new DelegatedTokenMinter(new ObjectMapper(), SERVICE_ACCOUNT,
                new FederatedCallerTokenSource(new ObjectMapper(),
                        "https://auth.pm.example.com/realms/kse-pm/protocol/openid-connect/token",
                        "https://sts.googleapis.com/v1/", "kse-pm-federation", "secret",
                        "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/kse-pm/providers/keycloak"));
        DirectoryCredentialSummary summary = client(minter).credentials();

        assertThat(summary.mode()).isEqualTo("workload-identity-federation");
        assertThat(summary.unattended()).isTrue();
    }

    @Test
    void gcloudUserCredentialsAreReportedAsUnusableUnattended() {
        DelegatedTokenMinter minter = new DelegatedTokenMinter(new ObjectMapper(), SERVICE_ACCOUNT,
                new ApplicationDefaultCallerTokenSource(SERVICE_ACCOUNT));
        DirectoryCredentialSummary summary = client(minter).credentials();
        // Only meaningful on a host that actually has `gcloud auth
        // application-default login` credentials.
        Assumptions.assumeTrue(summary.mode().equals("impersonation-user-adc"));

        assertThat(summary.unattended()).isFalse();
        assertThat(summary.detail()).contains("reauth policy");
    }

    @Test
    void anUnconfiguredDeploymentReportsItSafely() {
        assertThat(new UnavailableWorkspaceDirectoryClient().credentials().mode()).isEqualTo("not-configured");
        assertThat(new UnavailableWorkspaceDirectoryClient().credentials().unattended()).isFalse();
    }
}
