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
