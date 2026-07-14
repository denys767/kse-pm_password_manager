package ua.kse.passwordmanager.keys;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public record UserKeysDto(
        String email,
        @NotBlank @Size(max = 2048) String publicKey,
        @NotBlank @Size(max = 8192) String encryptedPrivateKey,
        @NotBlank @Size(max = 255) String privateKeyIv,
        @NotBlank @Size(max = 255) String kdfSalt,
        Instant updatedAt) {

    public static UserKeysDto from(UserKeys keys) {
        return new UserKeysDto(keys.getEmail(), keys.getPublicKey(), keys.getEncryptedPrivateKey(),
                keys.getPrivateKeyIv(), keys.getKdfSalt(), keys.getUpdatedAt());
    }
}
