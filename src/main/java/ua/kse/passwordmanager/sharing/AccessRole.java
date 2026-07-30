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

    /** Password ciphertext and its item key are a server policy boundary for
     * AUTOFILL_ONLY and PASSKEY_ONLY alike: both are released only to the
     * dedicated browser-extension OAuth audience, never to the web client.
     * That is what keeps PASSKEY_ONLY's raw password unreadable in the app
     * while still letting the extension autofill it. */
    public boolean mayReceivePasswordMaterial(boolean extensionClient) {
        return switch (this) {
            case NONE -> false;
            case AUTOFILL_ONLY, PASSKEY_ONLY -> extensionClient;
            case VIEWER, EDITOR, OWNER -> true;
        };
    }

    public boolean mayUsePasskeys() {
        return this != NONE && this != AUTOFILL_ONLY;
    }

    public boolean isOwner() {
        return this == OWNER;
    }

    /**
     * Capability-based merge, intentionally independent of enum order.
     * PASSKEY_ONLY outranks AUTOFILL_ONLY because it strictly dominates it —
     * both autofill through the extension, only PASSKEY_ONLY may use passkeys.
     * Ranking them the other way meant that holding PASSKEY_ONLY directly and
     * AUTOFILL_ONLY through a group *lost* passkey access, so adding a grant
     * took a capability away.
     */
    public static AccessRole mostPermissive(AccessRole left, AccessRole right) {
        if (left == OWNER || right == OWNER) return OWNER;
        if (left == EDITOR || right == EDITOR) return EDITOR;
        if (left == VIEWER || right == VIEWER) return VIEWER;
        if (left == PASSKEY_ONLY || right == PASSKEY_ONLY) return PASSKEY_ONLY;
        if (left == AUTOFILL_ONLY || right == AUTOFILL_ONLY) return AUTOFILL_ONLY;
        return NONE;
    }
}
