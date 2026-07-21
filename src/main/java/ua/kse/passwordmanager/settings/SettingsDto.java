package ua.kse.passwordmanager.settings;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import ua.kse.passwordmanager.vault.SyncMode;

public record SettingsDto(
        @NotNull SyncMode defaultSyncMode,
        @Min(5) @Max(120) int clipboardClearSeconds,
        /** Client-resized data: URI (PNG/JPEG); capped well above a small square avatar's size. */
        @Size(max = 300_000) String avatarDataUrl) {

    public static SettingsDto from(UserSettings settings) {
        return new SettingsDto(settings.getDefaultSyncMode(), settings.getClipboardClearSeconds(),
                settings.getAvatarDataUrl());
    }
}
