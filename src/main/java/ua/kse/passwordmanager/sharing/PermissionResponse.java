package ua.kse.passwordmanager.sharing;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.time.Instant;
import java.util.UUID;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record PermissionResponse(
        UUID id,
        GranteeType granteeType,
        String grantee,
        PermissionRole role,
        String grantedBy,
        Instant createdAt,
        PermissionStatus status,
        String directorySubjectId,
        String directoryDisplayName,
        /** Set for group shares until collections land: members without a
         * provisioned wrapped key cannot decrypt the item. */
        String warning,
        /** Null for USER grantees. For GROUP grantees, whether workspace
         * governance currently marks this group visible to non-admin users. */
        Boolean groupVisibleToUsers) {

    public static PermissionResponse from(Permission permission) {
        return from(permission, null, null);
    }

    public static PermissionResponse from(Permission permission, String warning, Boolean groupVisibleToUsers) {
        return new PermissionResponse(
                permission.getId(),
                permission.getGranteeType(),
                permission.getGrantee(),
                permission.getRole(),
                permission.getGrantedBy(),
                permission.getCreatedAt(),
                permission.getStatus(),
                permission.getDirectorySubjectId(),
                permission.getDirectoryDisplayName(),
                warning,
                groupVisibleToUsers);
    }
}
