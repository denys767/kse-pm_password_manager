package ua.kse.passwordmanager.settings;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import ua.kse.passwordmanager.vault.SyncMode;

public record SettingsDto(
        @NotNull SyncMode defaultSyncMode,
        @Min(5) @Max(120) int clipboardClearSeconds,
        /**
         * The Google Workspace profile photo, or null when the account has none.
         * Read-only: avatars are synced from Google and cannot be uploaded here,
         * so a PUT echoing this value back never writes it anywhere.
         */
        @JsonProperty(access = JsonProperty.Access.READ_ONLY) String avatarDataUrl) {

    public static SettingsDto from(UserSettings settings, String avatarDataUrl) {
        return new SettingsDto(settings.getDefaultSyncMode(), settings.getClipboardClearSeconds(),
                avatarDataUrl);
    }
}
