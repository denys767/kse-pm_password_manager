package ua.kse.passwordmanager.directory;

/** A safe, minimal projection of a Google Workspace user or group.
 * {@code visibleToUsers} is meaningless for USER principals (always true);
 * for GROUP principals it reflects workspace governance and lets admin
 * callers, who see hidden groups too, tell them apart in the UI. */
public record DirectoryPrincipal(Type type, String id, String email, String displayName,
                                 boolean vaultKeyAvailable, Long memberCount, boolean visibleToUsers) {
    public enum Type { USER, GROUP }
}
