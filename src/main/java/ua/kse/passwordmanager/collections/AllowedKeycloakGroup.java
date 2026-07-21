package ua.kse.passwordmanager.collections;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/** Admin-curated allowlist; this application never creates or edits Keycloak groups. */
@Entity
@Table(name = "allowed_keycloak_groups")
public class AllowedKeycloakGroup {
    @Id
    private String groupName;
    private Instant createdAt;

    protected AllowedKeycloakGroup() { }

    public AllowedKeycloakGroup(String groupName) {
        this.groupName = groupName;
        this.createdAt = Instant.now();
    }

    public String getGroupName() { return groupName; }
    public Instant getCreatedAt() { return createdAt; }
}
