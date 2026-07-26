package ua.kse.passwordmanager.directory;

import java.util.List;
import java.util.Optional;

/** Read-only boundary around Google Workspace Directory. */
public interface WorkspaceDirectoryClient {
    List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit);
    Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id);
    List<String> memberEmails(String groupId);

    /** Full, paginated directory projections used only by the materialized
     * directory synchronizer.  Search remains the interactive API. */
    List<DirectoryUser> listUsers();
    List<DirectoryGroup> listGroups();

    /** A user's Google profile photo as a data: URI; empty when the account has
     * none. Only the synchronizer calls this — interactive paths read the
     * materialized copy instead. */
    Optional<String> userPhotoDataUrl(String userKey);

    /** What this deployment authenticates with, and whether that credential can
     * keep working unattended. Surfaced on the admin screen. */
    default DirectoryCredentialSummary credentials() {
        return DirectoryCredentialSummary.notConfigured();
    }
}
