package ua.kse.passwordmanager.directory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import ua.kse.passwordmanager.common.BadGatewayException;

/**
 * When Google is unreachable, sharing has to keep working from the snapshot the
 * synchronizer already materialized — that is the difference between "the
 * picker shows nobody" and "the picker shows slightly older data".
 */
class ResilientDirectoryFallbackTest {

    private final WorkspaceDirectoryClient live = mock(WorkspaceDirectoryClient.class);
    private final WorkspaceDirectoryClient snapshot = mock(WorkspaceDirectoryClient.class);
    private final ResilientWorkspaceDirectoryClient client = new ResilientWorkspaceDirectoryClient(live, snapshot);

    private static DirectoryPrincipal principal(String email) {
        return new DirectoryPrincipal(DirectoryPrincipal.Type.USER, "id-" + email, email, email, true, null, true, null);
    }

    @Test
    void suggestionsComeFromTheSnapshotWhenGoogleIsDown() {
        when(live.search(anyString(), anyList(), anyInt()))
                .thenThrow(new BadGatewayException("Google Workspace Directory is temporarily unavailable"));
        when(snapshot.search(anyString(), anyList(), anyInt()))
                .thenReturn(List.of(principal("colleague@kse.org.ua")));

        List<DirectoryPrincipal> found = client.search("coll", List.of(DirectoryPrincipal.Type.USER), 50);

        assertThat(found).extracting(DirectoryPrincipal::email).containsExactly("colleague@kse.org.ua");
        assertThat(client.servingFromSnapshotSince()).isNotNull();
    }

    @Test
    void recipientValidationAndGroupMembersAlsoFallBack() {
        when(live.find(any(), anyString())).thenThrow(new BadGatewayException("unavailable"));
        when(snapshot.find(any(), anyString())).thenReturn(Optional.of(principal("colleague@kse.org.ua")));
        when(live.memberEmails(anyString())).thenThrow(new BadGatewayException("unavailable"));
        when(snapshot.memberEmails(anyString())).thenReturn(List.of("member@kse.org.ua"));

        assertThat(client.find(DirectoryPrincipal.Type.USER, "colleague@kse.org.ua")).isPresent();
        assertThat(client.memberEmails("group-id")).containsExactly("member@kse.org.ua");
    }

    @Test
    void aRecoveredDirectoryStopsTheDegradedMarker() {
        when(live.search(anyString(), anyList(), anyInt()))
                .thenThrow(new BadGatewayException("unavailable"))
                .thenReturn(List.of(principal("fresh@kse.org.ua")));
        when(snapshot.search(anyString(), anyList(), anyInt())).thenReturn(List.of());

        client.search("x", List.of(DirectoryPrincipal.Type.USER), 10);
        assertThat(client.servingFromSnapshotSince()).isNotNull();

        client.search("x", List.of(DirectoryPrincipal.Type.USER), 10);
        assertThat(client.servingFromSnapshotSince()).isNull();
    }

    @Test
    void theSynchronizerNeverReadsTheSnapshotAsIfItWereGoogle() {
        when(live.listUsers()).thenThrow(new BadGatewayException("unavailable"));

        // Falling back here would let the snapshot confirm itself and reset the
        // sync's freshness while Google is still unreachable.
        assertThatThrownBy(client::listUsers).isInstanceOf(BadGatewayException.class);
        org.mockito.Mockito.verify(snapshot, org.mockito.Mockito.never()).listUsers();
    }
}
