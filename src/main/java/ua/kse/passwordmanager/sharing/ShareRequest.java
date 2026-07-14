package ua.kse.passwordmanager.sharing;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record ShareRequest(
        @NotNull GranteeType granteeType,
        @NotBlank @Size(max = 255) String grantee,
        @NotNull PermissionRole role,
        /** Item AES key wrapped with the grantee's public key; required for USER shares. */
        @Size(max = 4096) String wrappedKey) {
}
