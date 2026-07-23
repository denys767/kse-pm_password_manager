package ua.kse.passwordmanager.directory;

/** Non-secret Google Workspace group projection. */
public record DirectoryGroup(String id, String email, String displayName, long directMembersCount) {}
