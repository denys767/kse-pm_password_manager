package ua.kse.passwordmanager.vault;

import java.time.Instant;
import java.util.UUID;

public record ItemVersionResponse(
        UUID id,
        String name,
        String url,
        String username,
        String encryptedPassword,
        String passwordIv,
        String encryptedNotes,
        String notesIv,
        String replacedBy,
        Instant replacedAt) {

    public static ItemVersionResponse from(ItemVersion version) {
        return new ItemVersionResponse(
                version.getId(),
                version.getName(),
                version.getUrl(),
                version.getUsername(),
                version.getEncryptedPassword(),
                version.getPasswordIv(),
                version.getEncryptedNotes(),
                version.getNotesIv(),
                version.getReplacedBy(),
                version.getReplacedAt());
    }
}
