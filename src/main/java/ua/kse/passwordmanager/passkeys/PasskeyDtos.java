package ua.kse.passwordmanager.passkeys;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.UUID;

public final class PasskeyDtos {
    private PasskeyDtos() { }
    public record CreateRequest(@NotNull UUID itemId, @NotBlank @Size(max = 253) String relyingPartyId,
            @NotBlank @Size(max = 1024) String credentialId, @NotBlank @Size(max = 1024) String userHandle,
            @Pattern(regexp = "ES256") String algorithm, @NotBlank @Size(max = 4096) String publicKey,
            @NotBlank @Size(max = 16384) String encryptedPrivateMaterial, @NotBlank @Size(max = 255) String privateMaterialIv,
            @Size(max = 1024) String transports, @NotBlank @Size(max = 4096) String wrappedCredentialKey) { }
    public record WrappedKeyRequest(@NotBlank @Size(max = 255) String userEmail,
                                    @NotBlank @Size(max = 4096) String wrappedCredentialKey) { }
    public record CounterRequest(long signCounter) { }
    public record Response(UUID id, UUID itemId, String relyingPartyId, String credentialId, String userHandle,
            String algorithm, String publicKey, String encryptedPrivateMaterial, String privateMaterialIv,
            String transports, long signCounter, String wrappedCredentialKey) { }
}
