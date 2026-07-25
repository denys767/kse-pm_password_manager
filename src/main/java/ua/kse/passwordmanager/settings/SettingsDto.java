package ua.kse.passwordmanager.settings;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import ua.kse.passwordmanager.vault.SyncMode;

public record SettingsDto(
        @NotNull SyncMode defaultSyncMode,
        @Min(5) @Max(120) int clipboardClearSeconds,
        /** Client-resized data: URI (PNG/JPEG); capped well above a small square avatar's size. */
        @Size(max = 300_000) String avatarDataUrl,
        /**
         * What the UI should actually render: the Google Workspace profile photo
         * when there is one, otherwise {@link #avatarDataUrl}. Read-only — a PUT
         * echoing it back must not persist Google's image into the manual column,
         * or clearing the manual avatar would become impossible.
         */
        @JsonProperty(access = JsonProperty.Access.READ_ONLY) String effectiveAvatarDataUrl) {

    public static SettingsDto from(UserSettings settings, String effectiveAvatarDataUrl) {
        return new SettingsDto(settings.getDefaultSyncMode(), settings.getClipboardClearSeconds(),
                settings.getAvatarDataUrl(), effectiveAvatarDataUrl);
    }
}
