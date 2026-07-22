package ua.kse.passwordmanager.sharing;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;
import ua.kse.passwordmanager.vault.PasswordItem;

@Entity
@Table(name = "permissions",
        uniqueConstraints = @UniqueConstraint(columnNames = {"item_id", "granteeType", "grantee"}))
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private PasswordItem item;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private GranteeType granteeType;

    /** User email or group name, stored lowercase. */
    @Column(nullable = false)
    private String grantee;

    /** Immutable Google Directory ID for new shares; null only for legacy rows. */
    @Column
    private String directorySubjectId;

    @Column
    private String directoryDisplayName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PermissionStatus status = PermissionStatus.ACTIVE;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PermissionRole role;

    @Column(nullable = false)
    private String grantedBy;

    @Column(nullable = false)
    private Instant createdAt;

    protected Permission() {
    }

    public Permission(PasswordItem item, GranteeType granteeType, String grantee,
                      PermissionRole role, String grantedBy) {
        this.item = item;
        this.granteeType = granteeType;
        this.grantee = grantee;
        this.role = role;
        this.grantedBy = grantedBy;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public PasswordItem getItem() {
        return item;
    }

    public GranteeType getGranteeType() {
        return granteeType;
    }

    public String getGrantee() {
        return grantee;
    }

    public String getDirectorySubjectId() { return directorySubjectId; }
    public String getDirectoryDisplayName() { return directoryDisplayName; }
    public PermissionStatus getStatus() { return status; }
    public boolean isActive() { return status == PermissionStatus.ACTIVE; }
    public void setDirectorySubject(String id, String displayName) { this.directorySubjectId = id; this.directoryDisplayName = displayName; }
    public void setStatus(PermissionStatus status) { this.status = status; }

    public PermissionRole getRole() {
        return role;
    }

    public void setRole(PermissionRole role) {
        this.role = role;
    }

    public String getGrantedBy() {
        return grantedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
