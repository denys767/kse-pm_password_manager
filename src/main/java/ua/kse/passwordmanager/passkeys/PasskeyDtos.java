package ua.kse.passwordmanager.passkeys;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
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

    /**
     * One credential the caller owns that somebody entitled to use it cannot
     * yet, because no wrapped key exists for them.
     *
     * @param wrappedCredentialKeyForMe the owner's own copy, to unwrap with the
     *        vault private key and re-wrap to each pending public key
     * @param pending grantees still missing a key, with the public key to wrap to
     */
    public record KeyDistribution(UUID id, UUID itemId, String itemName, String relyingPartyId,
                                  String wrappedCredentialKeyForMe, List<PendingGrantee> pending) { }

    public record PendingGrantee(String email, String publicKey) { }
    public record CounterRequest(long signCounter) { }
    public record Response(UUID id, UUID itemId, String relyingPartyId, String credentialId, String userHandle,
            String algorithm, String publicKey, String encryptedPrivateMaterial, String privateMaterialIv,
            String transports, long signCounter, String wrappedCredentialKey) { }
}
