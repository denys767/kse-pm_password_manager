package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

public record VaultImportBatchRequest(@NotEmpty List<@Valid VaultImportCommand> commands) {
}
