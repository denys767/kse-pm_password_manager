package ua.kse.passwordmanager.settings;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import ua.kse.passwordmanager.vault.SyncMode;

@Entity
@Table(name = "user_settings")
public class UserSettings {

    @Id
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SyncMode defaultSyncMode = SyncMode.SERVER_SYNCED;

    /** How long a copied password stays in the clipboard before the UI clears it. */
    @Column(nullable = false)
    private int clipboardClearSeconds = 20;

    /** Client-resized data: URI (PNG/JPEG), shown in the topbar and to other members in Collections. */
    @Column(name = "avatar_data_url", columnDefinition = "text")
    private String avatarDataUrl;

    protected UserSettings() {
    }

    public UserSettings(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public SyncMode getDefaultSyncMode() {
        return defaultSyncMode;
    }

    public void setDefaultSyncMode(SyncMode defaultSyncMode) {
        this.defaultSyncMode = defaultSyncMode;
    }

    public int getClipboardClearSeconds() {
        return clipboardClearSeconds;
    }

    public void setClipboardClearSeconds(int clipboardClearSeconds) {
        this.clipboardClearSeconds = clipboardClearSeconds;
    }

    public String getAvatarDataUrl() {
        return avatarDataUrl;
    }

    public void setAvatarDataUrl(String avatarDataUrl) {
        this.avatarDataUrl = avatarDataUrl;
    }
}
