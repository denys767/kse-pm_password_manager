package ua.kse.passwordmanager.sharing;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "permission_members", uniqueConstraints = @UniqueConstraint(columnNames = {"permission_id", "memberEmail"}))
public class PermissionMember {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "permission_id") private Permission permission;
    @Column(nullable = false) private String memberEmail;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private PermissionMemberStatus status;
    @Column(nullable = false) private Instant createdAt = Instant.now();
    protected PermissionMember() { }
    public PermissionMember(Permission permission, String memberEmail, PermissionMemberStatus status) { this.permission = permission; this.memberEmail = memberEmail; this.status = status; }
    public UUID getId() { return id; }
    public Permission getPermission() { return permission; }
    public String getMemberEmail() { return memberEmail; }
    public PermissionMemberStatus getStatus() { return status; }
    public void setStatus(PermissionMemberStatus status) { this.status = status; }
}
