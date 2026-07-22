package ua.kse.passwordmanager.directory;

import java.util.List;
import java.util.Optional;

/** Read-only boundary around Google Workspace Directory. */
public interface WorkspaceDirectoryClient {
    List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit);
    Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id);
    List<String> memberEmails(String groupId);
}
