package ua.kse.passwordmanager.externalsharing;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.UUID;

public final class ExternalShareDtos {
    private ExternalShareDtos() { }

    public record CreateRequest(
            @NotBlank @Size(max = 65535) String encryptedPackage,
            @NotBlank @Size(max = 255) String packageIv,
            @NotNull @Future Instant expiresAt,
            boolean oneTime) { }

    public record CreatedResponse(UUID id, Instant expiresAt, boolean oneTime) { }

    /** Never includes the URL-fragment key, which is not known to this server. */
    public record PublicPackageResponse(String encryptedPackage, String packageIv,
                                        Instant expiresAt, boolean oneTime) { }
}
