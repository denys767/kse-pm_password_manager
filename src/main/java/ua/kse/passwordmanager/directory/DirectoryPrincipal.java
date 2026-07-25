package ua.kse.passwordmanager.directory;

/** A safe, minimal projection of a Google Workspace user or group.
 *
 * @param avatarDataUrl the principal's Google profile photo as a data: URI,
 *                      hydrated from the local Workspace snapshot rather than
 *                      fetched from Google per keystroke; null for groups and
 *                      for users without a photo.
 */
public record DirectoryPrincipal(Type type, String id, String email, String displayName,
                                 boolean vaultKeyAvailable, Long memberCount, String avatarDataUrl) {
    public enum Type { USER, GROUP }

    public DirectoryPrincipal withAvatar(String dataUrl) {
        return new DirectoryPrincipal(type, id, email, displayName, vaultKeyAvailable, memberCount, dataUrl);
    }
}
