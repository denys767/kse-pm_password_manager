package ua.kse.passwordmanager.vault;

import java.time.Instant;
import java.util.UUID;
import ua.kse.passwordmanager.sharing.AccessRole;

public record PasswordItemResponse(
        UUID id,
        String name,
        String url,
        String username,
        String encryptedPassword,
        String passwordIv,
        String encryptedNotes,
        String notesIv,
        String tags,
        String ownerEmail,
        SecretType type,
        ItemType itemType,
        SyncMode syncMode,
        AccessRole accessRole,
        /** Item key wrapped with the requesting user's public key; null when the
         * caller's access comes from a collection or bare group permission. */
        String wrappedKey,
        UUID collectionId,
        /** Item key wrapped AES-GCM with the collection key (members unwrap the
         * collection key first, then this). */
        String collectionWrappedKey,
        String collectionWrappedKeyIv,
        Instant createdAt,
        Instant updatedAt) {

    public static PasswordItemResponse from(PasswordItem item, AccessRole accessRole,
                                            String wrappedKey) {
        return from(item, accessRole, wrappedKey, true);
    }

    /** Metadata remains visible to all readers; encrypted password/notes and
     * every route to the item key are withheld for restricted roles. */
    public static PasswordItemResponse from(PasswordItem item, AccessRole accessRole,
                                            String wrappedKey, boolean extensionClient) {
        boolean includeMaterial = accessRole.mayReceivePasswordMaterial(extensionClient);
        return new PasswordItemResponse(
                item.getId(),
                item.getName(),
                item.getUrl(),
                item.getUsername(),
                includeMaterial ? item.getEncryptedPassword() : null,
                includeMaterial ? item.getPasswordIv() : null,
                includeMaterial ? item.getEncryptedNotes() : null,
                includeMaterial ? item.getNotesIv() : null,
                item.getTags(),
                item.getOwnerEmail(),
                item.getType(),
                item.getItemType(),
                item.getSyncMode(),
                accessRole,
                includeMaterial ? wrappedKey : null,
                includeMaterial ? item.getCollectionId() : null,
                includeMaterial ? item.getCollectionWrappedKey() : null,
                includeMaterial ? item.getCollectionWrappedKeyIv() : null,
                item.getCreatedAt(),
                item.getUpdatedAt());
    }
}
