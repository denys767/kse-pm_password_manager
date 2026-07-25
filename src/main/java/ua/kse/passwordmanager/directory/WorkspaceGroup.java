package ua.kse.passwordmanager.directory;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "workspace_groups")
public class WorkspaceGroup {
    @Id private String email;
    @Column(name = "directory_id") private String directoryId;
    @Column(nullable = false) private String displayName;
    @Column(nullable = false) private boolean visibleToUsers = true;
    @Column(name = "directory_present", nullable = false) private boolean directoryPresent = true;
    @Column(nullable = false) private Instant syncedAt = Instant.now();
    protected WorkspaceGroup() {}
    public WorkspaceGroup(String email, boolean visible) { this.email = email; this.displayName = email; this.visibleToUsers = visible; }
    public String getEmail() { return email; }
    public String getDirectoryId() { return directoryId; }
    public String getDisplayName() { return displayName; }
    public boolean isVisibleToUsers() { return visibleToUsers; }
    public boolean isDirectoryPresent() { return directoryPresent; }
    public Instant getSyncedAt() { return syncedAt; }
    public void updateFromGoogle(DirectoryGroup source) { directoryId = source.id(); displayName = source.displayName(); directoryPresent = true; syncedAt = Instant.now(); }
    public void setVisibleToUsers(boolean value) { visibleToUsers = value; }
    public void setDirectoryPresent(boolean value) { directoryPresent = value; if (!value) visibleToUsers = false; syncedAt = Instant.now(); }
}
