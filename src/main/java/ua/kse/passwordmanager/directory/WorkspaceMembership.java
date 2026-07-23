package ua.kse.passwordmanager.directory;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "workspace_group_memberships", uniqueConstraints = @UniqueConstraint(columnNames = {"group_email", "member_email"}))
public class WorkspaceMembership {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @Column(name = "group_email", nullable = false) private String groupEmail;
    @Column(name = "member_email", nullable = false) private String memberEmail;
    @Column(nullable = false) private Instant syncedAt = Instant.now();
    protected WorkspaceMembership() {}
    public WorkspaceMembership(String groupEmail, String memberEmail) { this.groupEmail = groupEmail; this.memberEmail = memberEmail; }
    public String getGroupEmail() { return groupEmail; }
    public String getMemberEmail() { return memberEmail; }
}
