package ua.kse.passwordmanager.directory;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "workspace_users")
public class WorkspaceUser {
    @Id private String email;
    @Column(name = "directory_id") private String directoryId;
    @Column(nullable = false) private String displayName;
    @Column(nullable = false) private boolean googleAdmin;
    @Enumerated(EnumType.STRING) @Column(name = "role_override") private WorkspaceRoleOverride roleOverride;
    @Enumerated(EnumType.STRING) @Column(name = "local_status", nullable = false) private WorkspaceAccountStatus localStatus = WorkspaceAccountStatus.ACTIVE;
    @Column(name = "google_suspended", nullable = false) private boolean googleSuspended;
    @Column(name = "directory_present", nullable = false) private boolean directoryPresent = true;
    @Column(name = "avatar_data_url", columnDefinition = "text") private String avatarDataUrl;
    @Column(name = "avatar_etag") private String avatarEtag;
    @Column(nullable = false) private Instant syncedAt = Instant.now();

    protected WorkspaceUser() {}
    public WorkspaceUser(String email) { this.email = email; this.displayName = email; }
    public String getEmail() { return email; }
    public String getDirectoryId() { return directoryId; }
    public String getDisplayName() { return displayName; }
    public boolean isGoogleAdmin() { return googleAdmin; }
    public WorkspaceRoleOverride getRoleOverride() { return roleOverride; }
    public WorkspaceAccountStatus getStatus() { return localStatus; }
    public boolean isGoogleSuspended() { return googleSuspended; }
    public boolean isDirectoryPresent() { return directoryPresent; }
    public Instant getSyncedAt() { return syncedAt; }
    /** Google profile photo as a data: URI, or null when the account has none. */
    public String getAvatarDataUrl() { return avatarDataUrl; }
    public String getAvatarEtag() { return avatarEtag; }
    /** True when Google reports a photo whose etag differs from the stored copy. */
    public boolean needsAvatarRefresh(String photoEtag) {
        if (photoEtag == null || photoEtag.isBlank()) return false;
        return !photoEtag.equals(avatarEtag) || avatarDataUrl == null;
    }
    public void setAvatar(String dataUrl, String etag) { avatarDataUrl = dataUrl; avatarEtag = etag; }
    /** Google no longer reports a photo: drop the materialized copy so the UI
     * falls back to the manual avatar or initials. */
    public void clearAvatar() { avatarDataUrl = null; avatarEtag = null; }
    public void updateFromGoogle(DirectoryUser source) {
        directoryId = source.id(); displayName = source.displayName(); googleAdmin = source.admin();
        googleSuspended = source.suspended(); directoryPresent = true;
        syncedAt = Instant.now();
    }
    public void setRoleOverride(WorkspaceRoleOverride value) { roleOverride = value; }
    public void setStatus(WorkspaceAccountStatus value) { localStatus = value; }
    public void setDirectoryPresent(boolean value) { directoryPresent = value; syncedAt = Instant.now(); }
    public WorkspaceRoleOverride effectiveRole() {
        return roleOverride != null ? roleOverride : (googleAdmin ? WorkspaceRoleOverride.ADMIN : WorkspaceRoleOverride.USER);
    }
    public boolean hasEffectiveAccess() {
        return localStatus == WorkspaceAccountStatus.ACTIVE && !googleSuspended && directoryPresent;
    }
}
