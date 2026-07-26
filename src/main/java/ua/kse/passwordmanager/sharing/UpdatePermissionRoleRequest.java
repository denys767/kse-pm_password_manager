package ua.kse.passwordmanager.sharing;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** Changes the role of an existing grant. The wrapped key is only needed when
 * the new role requires one and the grantee does not already hold it. */
public record UpdatePermissionRoleRequest(
        @NotNull PermissionRole role,
        @Size(max = 4096) String wrappedKey) {
}
