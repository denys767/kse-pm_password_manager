package ua.kse.passwordmanager.collections;

/** Member role inside a collection. MANAGER manages members and edits items,
 * EDITOR edits items, VIEWER reads/copies. */
public enum CollectionRole {
    VIEWER,
    EDITOR,
    MANAGER;

    public boolean canEditItems() {
        return this == EDITOR || this == MANAGER;
    }

    public boolean canManageMembers() {
        return this == MANAGER;
    }
}
