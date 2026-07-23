package ua.kse.passwordmanager.directory;

/** Non-secret Google Workspace user projection. */
public record DirectoryUser(String id, String email, String displayName,
                            boolean admin, boolean suspended) {}
