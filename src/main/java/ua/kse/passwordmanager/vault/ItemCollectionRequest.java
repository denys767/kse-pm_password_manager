package ua.kse.passwordmanager.vault;

import jakarta.validation.constraints.Size;
import java.util.UUID;

/** Assign the item to a collection (or remove with collectionId = null).
 * wrappedKey/IV: the item key wrapped AES-GCM with the collection key. */
public record ItemCollectionRequest(
        UUID collectionId,
        @Size(max = 4096) String wrappedKey,
        @Size(max = 255) String wrappedKeyIv) {
}
