package ua.kse.passwordmanager.vault;

import jakarta.validation.constraints.NotNull;

public record SyncModeRequest(@NotNull SyncMode syncMode) {
}
