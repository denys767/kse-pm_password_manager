package ua.kse.passwordmanager.sharing;

/** Role granted through sharing. OWNER is never stored as a permission —
 * ownership lives on the item itself. */
public enum PermissionRole {
    VIEWER,
    EDITOR
}
