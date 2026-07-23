package ua.kse.passwordmanager.sharing;

/** Effective access level of a user on a vault item. Owner can do everything,
 * editor can modify, viewer can only read/copy. */
public enum AccessRole {
    NONE,
    VIEWER,
    EDITOR,
    AUTOFILL_ONLY,
    PASSKEY_ONLY,
    OWNER;

    /** Normal web-vault read capability. Special roles deliberately do not
     * unlock ciphertext via the ordinary record API. */
    public boolean canReadItemCiphertext() {
        return this == OWNER || this == EDITOR || this == VIEWER;
    }

    public boolean canEditItem() {
        return this == OWNER || this == EDITOR;
    }

    public boolean canCreateShares() { return this == OWNER || this == EDITOR; }
    public boolean canDeleteItem() { return this == OWNER; }
    public boolean canTransferOwnership() { return this == OWNER; }
    public boolean canRevokeGrants() { return this == OWNER; }

    /** Password ciphertext and its item key are intentionally never returned
     * to PASSKEY_ONLY. AUTOFILL_ONLY is a server policy boundary: it is only
     * released to the dedicated browser-extension OAuth audience. */
    public boolean mayReceivePasswordMaterial(boolean extensionClient) {
        return switch (this) {
            case NONE, PASSKEY_ONLY -> false;
            case AUTOFILL_ONLY -> extensionClient;
            case VIEWER, EDITOR, OWNER -> true;
        };
    }

    public boolean mayUsePasskeys() {
        return this != NONE && this != AUTOFILL_ONLY;
    }

    public boolean isOwner() {
        return this == OWNER;
    }

    /** Capability-based merge, intentionally independent of enum order. */
    public static AccessRole mostPermissive(AccessRole left, AccessRole right) {
        if (left == OWNER || right == OWNER) return OWNER;
        if (left == EDITOR || right == EDITOR) return EDITOR;
        if (left == VIEWER || right == VIEWER) return VIEWER;
        if (left == AUTOFILL_ONLY || right == AUTOFILL_ONLY) return AUTOFILL_ONLY;
        if (left == PASSKEY_ONLY || right == PASSKEY_ONLY) return PASSKEY_ONLY;
        return NONE;
    }
}
