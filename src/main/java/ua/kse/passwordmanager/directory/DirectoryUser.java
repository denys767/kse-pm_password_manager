package ua.kse.passwordmanager.directory;

/** Non-secret Google Workspace user projection.
 *
 * @param photoEtag Google's thumbnailPhotoEtag, or null when the account has no
 *                  profile photo. It changes whenever the photo changes, so the
 *                  synchronizer can skip downloading an unchanged image.
 */
public record DirectoryUser(String id, String email, String displayName,
                            boolean admin, boolean suspended, String photoEtag) {}
