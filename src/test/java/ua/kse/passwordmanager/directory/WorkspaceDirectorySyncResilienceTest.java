package ua.kse.passwordmanager.directory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import ua.kse.passwordmanager.common.BadGatewayException;

/**
 * A Google outage or an expired caller credential must never escape into the
 * scheduler, and the deployment must not have to wait a full sync interval to
 * recover once it is fixed.
 */
class WorkspaceDirectorySyncResilienceTest {

    private final WorkspaceDirectoryClient directory = mock(WorkspaceDirectoryClient.class);
    private final WorkspaceUserRepository users = mock(WorkspaceUserRepository.class);
    private final WorkspaceGroupRepository groups = mock(WorkspaceGroupRepository.class);
    private final WorkspaceMembershipRepository memberships = mock(WorkspaceMembershipRepository.class);
    private final WorkspaceDirectorySnapshotWriter writer =
            new WorkspaceDirectorySnapshotWriter(directory, users, groups, memberships);
    private final WorkspaceDirectorySyncService service = new WorkspaceDirectorySyncService(writer, users);

    @Test
    void scheduledSyncSwallowsDirectoryFailuresAndRecordsThem() {
        when(directory.listUsers()).thenThrow(new BadGatewayException("Cannot mint delegated Google Workspace access token"));

        assertThatCode(service::scheduledSync).doesNotThrowAnyException();

        WorkspaceDirectorySyncService.DirectoryStatus status = service.status();
        assertThat(status.lastSuccessAt()).isNull();
        assertThat(status.lastAttemptAt()).isNotNull();
        assertThat(status.lastError()).contains("Cannot mint delegated");
        assertThat(status.consecutiveFailures()).isEqualTo(1);
    }

    @Test
    void anyRuntimeFailureIsContainedToo() {
        when(directory.listUsers()).thenThrow(new IllegalStateException("connection reset"));

        assertThatCode(service::scheduledSync).doesNotThrowAnyException();
        assertThat(service.status().lastError()).isEqualTo("connection reset");
    }

    @Test
    void bootstrapRetriesWhileTheSnapshotIsEmptyAndStopsOnceItIsNot() {
        when(users.count()).thenReturn(0L);
        when(directory.listUsers()).thenThrow(new BadGatewayException("directory down"));

        service.bootstrapSync();
        verify(directory).listUsers();
        assertThat(service.status().consecutiveFailures()).isEqualTo(1);

        // Another instance already populated the snapshot: no more retries.
        when(users.count()).thenReturn(7L);
        service.bootstrapSync();
        verify(directory).listUsers();
    }

    @Test
    void bootstrapStopsAfterTheFirstSuccess() {
        when(users.count()).thenReturn(0L);
        when(directory.listUsers()).thenReturn(java.util.List.of(
                new DirectoryUser("1", "someone@kse.org.ua", "Someone", false, false, null)));
        when(directory.listGroups()).thenReturn(java.util.List.of());
        when(users.findById("someone@kse.org.ua")).thenReturn(java.util.Optional.empty());
        when(users.findAll()).thenReturn(java.util.List.of());
        when(groups.count()).thenReturn(0L);

        service.bootstrapSync();
        assertThat(service.status().lastSuccessAt()).isNotNull();
        assertThat(service.status().lastError()).isNull();

        // count() still answers 0 here; the recorded success alone must stop it.
        service.bootstrapSync();
        verify(directory, never().description("no second attempt after a success")).userPhotoDataUrl("someone@kse.org.ua");
        verify(directory, org.mockito.Mockito.times(1)).listUsers();
    }
}
