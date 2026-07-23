package ua.kse.passwordmanager.sharing;

/** Role granted through sharing. OWNER is never stored as a permission —
 * ownership lives on the item itself. */
public enum PermissionRole {
    VIEWER,
    EDITOR,
    /** May receive the encrypted item only from the dedicated extension client. */
    AUTOFILL_ONLY,
    /** May use separately wrapped passkeys, never the item's password key. */
    PASSKEY_ONLY;

    public AccessRole accessRole() {
        return switch (this) {
            case VIEWER -> AccessRole.VIEWER;
            case EDITOR -> AccessRole.EDITOR;
            case AUTOFILL_ONLY -> AccessRole.AUTOFILL_ONLY;
            case PASSKEY_ONLY -> AccessRole.PASSKEY_ONLY;
        };
    }

    public boolean requiresItemKey() {
        return this != PASSKEY_ONLY;
    }
}
