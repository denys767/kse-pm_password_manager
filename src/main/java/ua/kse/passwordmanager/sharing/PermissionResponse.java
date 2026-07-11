package ua.kse.passwordmanager.sharing;

import java.time.Instant;
import java.util.UUID;

public record PermissionResponse(
        UUID id,
        GranteeType granteeType,
        String grantee,
        PermissionRole role,
        String grantedBy,
        Instant createdAt) {

    public static PermissionResponse from(Permission permission) {
        return new PermissionResponse(
                permission.getId(),
                permission.getGranteeType(),
                permission.getGrantee(),
                permission.getRole(),
                permission.getGrantedBy(),
                permission.getCreatedAt());
    }
}
