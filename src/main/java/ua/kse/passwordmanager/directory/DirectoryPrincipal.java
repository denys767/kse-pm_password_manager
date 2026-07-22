package ua.kse.passwordmanager.directory;

/** A safe, minimal projection of a Google Workspace user or group. */
public record DirectoryPrincipal(Type type, String id, String email, String displayName,
                                 boolean vaultKeyAvailable, Long memberCount) {
    public enum Type { USER, GROUP }
}
