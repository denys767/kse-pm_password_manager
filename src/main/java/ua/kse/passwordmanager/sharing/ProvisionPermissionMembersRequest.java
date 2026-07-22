package ua.kse.passwordmanager.sharing;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;

public record ProvisionPermissionMembersRequest(@NotEmpty List<@Valid Entry> members) {
    public record Entry(@NotBlank @Size(max = 255) String email,
                        @NotBlank @Size(max = 4096) String wrappedKey) { }
}
