package ua.kse.passwordmanager.sharing;

/** Role granted through sharing. OWNER is never stored as a permission —
 * ownership lives on the item itself. */
public enum PermissionRole {
    VIEWER,
    EDITOR,
    /** May receive the encrypted item only from the dedicated extension client. */
    AUTOFILL_ONLY,
    /** May autofill and use passkeys through the extension client; the web
     * client never receives the ciphertext, so the raw password stays
     * unreadable, unrevealable and unexportable there. */
    PASSKEY_ONLY;

    public AccessRole accessRole() {
        return switch (this) {
            case VIEWER -> AccessRole.VIEWER;
            case EDITOR -> AccessRole.EDITOR;
            case AUTOFILL_ONLY -> AccessRole.AUTOFILL_ONLY;
            case PASSKEY_ONLY -> AccessRole.PASSKEY_ONLY;
        };
    }

    /** Every role needs the item key wrapped for the recipient — even
     * PASSKEY_ONLY, whose extension client autofills with it while the web
     * client is still denied the ciphertext (see AccessRole.mayReceivePasswordMaterial). */
    public boolean requiresItemKey() {
        return true;
    }
}
