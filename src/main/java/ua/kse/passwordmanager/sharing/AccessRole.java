package ua.kse.passwordmanager.sharing;

/** Effective access level of a user on a vault item. Owner can do everything,
 * editor can modify, viewer can only read/copy. */
public enum AccessRole {
    NONE,
    VIEWER,
    EDITOR,
    OWNER;

    public boolean canRead() {
        return this != NONE;
    }

    public boolean canEdit() {
        return this == OWNER || this == EDITOR;
    }

    public boolean isOwner() {
        return this == OWNER;
    }
}
