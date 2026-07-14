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
        return new PasswordItemResponse(
                item.getId(),
                item.getName(),
                item.getUrl(),
                item.getUsername(),
                item.getEncryptedPassword(),
                item.getPasswordIv(),
                item.getEncryptedNotes(),
                item.getNotesIv(),
                item.getTags(),
                item.getOwnerEmail(),
                item.getItemType(),
                item.getSyncMode(),
                accessRole,
                wrappedKey,
                item.getCollectionId(),
                item.getCollectionWrappedKey(),
                item.getCollectionWrappedKeyIv(),
                item.getCreatedAt(),
                item.getUpdatedAt());
    }
}
