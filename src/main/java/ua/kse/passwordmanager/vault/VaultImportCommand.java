package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.UUID;

/** A single encrypted import command. `expectedUpdatedAt` prevents a CSV
 * update/delete from overwriting a record changed after it was exported. */
public record VaultImportCommand(
        @NotNull VaultImportAction action,
        UUID itemId,
        Instant expectedUpdatedAt,
        @Valid PasswordItemRequest item) {
}
