package ua.kse.passwordmanager;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.ActiveProfiles;
import ua.kse.passwordmanager.directory.DirectoryGroup;
import ua.kse.passwordmanager.directory.DirectoryPrincipal;
import ua.kse.passwordmanager.directory.DirectoryUser;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;
import ua.kse.passwordmanager.directory.WorkspaceDirectorySyncService;
import ua.kse.passwordmanager.directory.WorkspaceMembershipRepository;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

/**
 * Drives the sync the way the scheduler does — through {@code scheduledSync()}
 * on the real, proxied bean — rather than by calling the transactional write
 * method directly.
 *
 * <p>That distinction is the whole point. The write half used to live on this
 * same bean, so {@code scheduledSync()} reached it by self-invocation, its
 * {@code @Transactional} never applied, and the first bulk membership delete
 * threw TransactionRequiredException on every pass in production. The unit
 * tests all called the write method directly, where nothing is proxied, and so
 * saw none of it.
 */
@SpringBootTest(properties = {
        "pm.allow-insecure-dev=true",
        "pm.google-workspace.service-account-email=",
        "spring.main.allow-bean-definition-overriding=true",
        // The scheduler must not race this test's explicit invocation.
        "spring.task.scheduling.enabled=false",
})
@ActiveProfiles("dev")
@Import(WorkspaceDirectorySyncTransactionIT.StubDirectory.class)
class WorkspaceDirectorySyncTransactionIT {

    private static final String GROUP = "sync-it-team@kse.org.ua";
    private static final String MEMBER = "sync-it-member@kse.org.ua";

    @Autowired
    private WorkspaceDirectorySyncService sync;

    @Autowired
    private WorkspaceMembershipRepository memberships;

    @Autowired
    private WorkspaceUserRepository users;

    @Test
    void scheduledSyncMaterializesMembershipsInsideATransaction() {
        sync.scheduledSync();

        assertThat(sync.status().lastError()).isNull();
        assertThat(sync.status().lastSuccessAt()).isNotNull();
        assertThat(users.findById(MEMBER)).isPresent();
        assertThat(memberships.findByGroupEmail(GROUP))
                .extracting(m -> m.getMemberEmail())
                .containsExactly(MEMBER);
    }

    @Test
    void aSecondPassReplacesMembershipsRatherThanCollidingWithThem() {
        sync.scheduledSync();
        sync.scheduledSync();

        assertThat(sync.status().lastError()).isNull();
        // The delete-then-reinsert path is where a missing transaction and a
        // deferred (rather than bulk) delete both show up.
        assertThat(memberships.findByGroupEmail(GROUP)).hasSize(1);
    }

    @TestConfiguration
    static class StubDirectory {
        @Bean
        @Primary
        WorkspaceDirectoryClient workspaceDirectoryClient() {
            return new WorkspaceDirectoryClient() {
                @Override public List<DirectoryUser> listUsers() {
                    return List.of(new DirectoryUser("1", MEMBER, "Sync IT Member", false, false, null));
                }
                @Override public List<DirectoryGroup> listGroups() {
                    return List.of(new DirectoryGroup("group-1", GROUP, "Sync IT Team", 1));
                }
                @Override public List<String> memberEmails(String groupId) { return List.of(MEMBER); }
                @Override public Optional<String> userPhotoDataUrl(String userKey) { return Optional.empty(); }
                @Override public List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit) {
                    return List.of();
                }
                @Override public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
                    return Optional.empty();
                }
            };
        }
    }
}
