package ua.kse.passwordmanager.settings;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import ua.kse.passwordmanager.vault.SyncMode;

public record SettingsDto(
        @NotNull SyncMode defaultSyncMode,
        @Min(5) @Max(120) int clipboardClearSeconds) {

    public static SettingsDto from(UserSettings settings) {
        return new SettingsDto(settings.getDefaultSyncMode(), settings.getClipboardClearSeconds());
    }
}
