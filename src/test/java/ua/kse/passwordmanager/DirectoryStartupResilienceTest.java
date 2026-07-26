package ua.kse.passwordmanager;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import ua.kse.passwordmanager.directory.GoogleWorkspaceDirectoryClient;
import ua.kse.passwordmanager.directory.ResilientWorkspaceDirectoryClient;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;

/**
 * Workspace credentials that cannot be resolved used to abort startup: the
 * client loaded Application Default Credentials in its constructor. A host
 * whose ADC expired (or is subject to Google's reauth policy) must still boot —
 * Directory calls fail with 502 until the credentials work again.
 */
@SpringBootTest(properties = {
        "pm.allow-insecure-dev=true",
        "pm.google-workspace.service-account-email=directory-sync@example.iam.gserviceaccount.com",
        "pm.google-workspace.admin-email=workspace-admin@kse.org.ua",
        // Keep the schedulers away from the network for the duration of the test.
        "pm.google-workspace.sync-initial-delay-ms=600000",
        "pm.google-workspace.bootstrap-initial-delay-ms=600000",
})
@ActiveProfiles("dev")
class DirectoryStartupResilienceTest {

    @Autowired
    private WorkspaceDirectoryClient directory;

    @Autowired
    private GoogleWorkspaceDirectoryClient google;

    @Test
    void applicationStartsWithTheGoogleClientEvenWhenCallerCredentialsAreUnusable() {
        // Callers get the resilient wrapper; the live Google client behind it is
        // what used to abort startup when credentials could not be resolved.
        assertThat(directory).isInstanceOf(ResilientWorkspaceDirectoryClient.class);
        assertThat(google).isNotNull();
        assertThat(google.credentials().mode()).isNotEqualTo("not-configured");
    }
}
