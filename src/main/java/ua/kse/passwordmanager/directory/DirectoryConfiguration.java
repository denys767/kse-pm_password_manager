package ua.kse.passwordmanager.directory;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import ua.kse.passwordmanager.keys.UserKeysRepository;

@Configuration
class DirectoryConfiguration {

    /**
     * Everything talks to this wrapper: live Google Directory, with the
     * materialized snapshot as the answer of last resort so a credential or
     * network problem degrades sharing instead of stopping it. An unconfigured
     * deployment keeps the explicit 502 of
     * {@link UnavailableWorkspaceDirectoryClient} as its live side.
     */
    @Bean
    @Primary
    WorkspaceDirectoryClient workspaceDirectoryClient(ObjectProvider<GoogleWorkspaceDirectoryClient> google,
            WorkspaceUserRepository users, WorkspaceGroupRepository groups,
            WorkspaceMembershipRepository memberships, UserKeysRepository keys) {
        GoogleWorkspaceDirectoryClient configured = google.getIfAvailable();
        WorkspaceDirectoryClient live = configured != null ? configured : new UnavailableWorkspaceDirectoryClient();
        return new ResilientWorkspaceDirectoryClient(live,
                new LocalDirectorySnapshotClient(users, groups, memberships, keys));
    }
}
