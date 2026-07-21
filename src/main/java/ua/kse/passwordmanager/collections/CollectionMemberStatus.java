package ua.kse.passwordmanager.collections;

/** A pending row has no wrapped collection key and therefore no E2E access. */
public enum CollectionMemberStatus {
    ACTIVE,
    PENDING_PROVISIONING,
    PENDING_REMOVAL;

    public boolean hasCryptographicAccess() {
        return this == ACTIVE;
    }
}
