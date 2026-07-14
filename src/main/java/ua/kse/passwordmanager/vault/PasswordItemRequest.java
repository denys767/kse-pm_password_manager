package ua.kse.passwordmanager.vault;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record PasswordItemRequest(
        @NotBlank @Size(max = 255) String name,
        @Size(max = 2048) String url,
        @Size(max = 255) String username,
        @NotBlank @Size(max = 4096) String encryptedPassword,
        @NotBlank @Size(max = 255) String passwordIv,
        @Size(max = 16384) String encryptedNotes,
        @Size(max = 255) String notesIv,
        @Size(max = 1024) String tags,
        @NotNull ItemType itemType,
        @NotNull SyncMode syncMode,
        /** Item AES key wrapped with the owner's public key; required on create. */
        @Size(max = 4096) String wrappedKey) {
}
