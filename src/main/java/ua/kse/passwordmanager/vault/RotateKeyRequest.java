package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import java.util.List;

/**
 * Rotates the item's AES key: a fresh key encrypts the fields client-side and
 * is re-wrapped for every remaining key holder. Used when revoking a
 * recipient's access so the removed key holder cannot decrypt anything
 * written after the rotation.
 */
public record RotateKeyRequest(
        @NotBlank @Size(max = 4096) String encryptedPassword,
        @NotBlank @Size(max = 255) String passwordIv,
        @Size(max = 16384) String encryptedNotes,
        @Size(max = 255) String notesIv,
        @NotEmpty List<@Valid WrappedKeyEntry> wrappedKeys) {

    public record WrappedKeyEntry(
            @NotBlank @Size(max = 255) String granteeEmail,
            @NotBlank @Size(max = 4096) String wrappedKey) {
    }
}
