package ua.kse.passwordmanager.collections;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.UUID;

/**
 * Rotates a collection's AES key: the manager generates a fresh key,
 * re-wraps it (RSA) for every member who keeps their access, and re-wraps
 * every collection item's (unchanged) item key with the new collection key.
 * Used when removing a member so they cannot decrypt anything written after
 * the rotation.
 */
public record RotateCollectionKeyRequest(
        List<@Valid MemberKeyEntry> memberWrappedKeys,
        List<@Valid ItemKeyEntry> itemWrappedKeys) {

    public record MemberKeyEntry(
            @NotNull UUID memberId,
            @NotBlank @Size(max = 4096) String wrappedKey) {
    }

    public record ItemKeyEntry(
            @NotNull UUID itemId,
            @NotBlank @Size(max = 4096) String wrappedKey,
            @NotBlank @Size(max = 255) String wrappedKeyIv) {
    }
}
