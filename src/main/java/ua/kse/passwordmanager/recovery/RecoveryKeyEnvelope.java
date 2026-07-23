package ua.kse.passwordmanager.recovery;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "recovery_key_envelopes", uniqueConstraints = @UniqueConstraint(columnNames = {"resourceType", "resourceId"}))
public class RecoveryKeyEnvelope {
    @Id private UUID id = UUID.randomUUID();
    @Enumerated(EnumType.STRING) @Column(nullable = false) private RecoveryResourceType resourceType;
    @Column(nullable = false) private UUID resourceId;
    @Column(nullable = false) private String ownerEmail;
    @Column(nullable = false, length = 1024) private String keyVersion;
    @Column(nullable = false, length = 8192) private String ciphertext;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;
    protected RecoveryKeyEnvelope() { }
    public RecoveryKeyEnvelope(RecoveryResourceType type, UUID resourceId, String ownerEmail, String keyVersion, String ciphertext) {
        this.resourceType = type; this.resourceId = resourceId; this.ownerEmail = ownerEmail;
        this.keyVersion = keyVersion; this.ciphertext = ciphertext;
    }
    @PrePersist void created() { createdAt = Instant.now(); updatedAt = createdAt; }
    @PreUpdate void updated() { updatedAt = Instant.now(); }
    public UUID getId() { return id; } public RecoveryResourceType getResourceType() { return resourceType; }
    public UUID getResourceId() { return resourceId; } public String getOwnerEmail() { return ownerEmail; }
    public String getKeyVersion() { return keyVersion; } public String getCiphertext() { return ciphertext; }
    public void replace(String keyVersion, String ciphertext) { this.keyVersion = keyVersion; this.ciphertext = ciphertext; }
    public void setOwnerEmail(String ownerEmail) { this.ownerEmail = ownerEmail; }
}
