package ua.kse.passwordmanager.collections;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A team vault (Bitwarden-style organization collection). The collection has
 * its own AES-256 key, generated in the browser and stored only wrapped with
 * each member's RSA public key (see {@link CollectionMember}); item keys of
 * records in the collection are wrapped with the collection key. The server
 * never sees any of these keys unwrapped.
 */
@Entity
@Table(name = "collections")
public class Collection {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String ownerEmail;

    /** Optional Keycloak group used only to suggest explicit members. */
    @Column
    private String keycloakGroup;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    protected Collection() {
    }

    public Collection(String name, String ownerEmail, String keycloakGroup) {
        this.name = name;
        this.ownerEmail = ownerEmail;
        this.keycloakGroup = keycloakGroup;
    }

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public String getKeycloakGroup() {
        return keycloakGroup;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
