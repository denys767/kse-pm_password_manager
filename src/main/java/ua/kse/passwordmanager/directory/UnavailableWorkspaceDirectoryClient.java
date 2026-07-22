package ua.kse.passwordmanager.directory;

import java.util.List;
import java.util.Optional;
import ua.kse.passwordmanager.common.BadGatewayException;

/** Makes missing production credentials explicit instead of silently falling back to Keycloak. */
class UnavailableWorkspaceDirectoryClient implements WorkspaceDirectoryClient {
    private BadGatewayException unavailable() { return new BadGatewayException("Google Workspace Directory is not configured"); }
    public List<DirectoryPrincipal> search(String q, List<DirectoryPrincipal.Type> t, int l) { throw unavailable(); }
    public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type t, String id) { throw unavailable(); }
    public List<String> memberEmails(String id) { throw unavailable(); }
}
