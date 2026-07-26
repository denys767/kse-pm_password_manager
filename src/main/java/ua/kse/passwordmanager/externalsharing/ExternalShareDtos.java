package ua.kse.passwordmanager.externalsharing;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class ExternalShareDtos {
    private ExternalShareDtos() { }

    /**
     * The ciphertext ceiling an over-large share is rejected at. Generous on
     * purpose: it exists to stop an absurd payload, not to express a product
     * limit. The old 65535 was a column width doing policy by accident, and a
     * long SSH key was enough to exceed it once AES-GCM and Base64 had had
     * their way with it.
     */
    public static final int MAX_ENCRYPTED_PACKAGE_CHARS = 1_000_000;

    public record CreateRequest(
            @NotBlank @Size(max = MAX_ENCRYPTED_PACKAGE_CHARS) String encryptedPackage,
            @NotBlank @Size(max = 255) String packageIv,
            @NotNull @Future Instant expiresAt,
            boolean oneTime) { }

    public record CreatedResponse(UUID id, Instant expiresAt, boolean oneTime) { }

    /** Never includes the URL-fragment key, which is not known to this server. */
    public record PublicPackageResponse(String encryptedPackage, String packageIv,
                                        Instant expiresAt, boolean oneTime) { }
}
