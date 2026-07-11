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
        Instant createdAt,
        Instant updatedAt) {

    public static PasswordItemResponse from(PasswordItem item, AccessRole accessRole) {
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
                item.getCreatedAt(),
                item.getUpdatedAt());
    }
}
