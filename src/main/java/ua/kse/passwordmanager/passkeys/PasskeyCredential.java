package ua.kse.passwordmanager.passkeys;

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

/** Encrypted private WebAuthn material. The server stores no usable private
 * key: callers must unwrap the per-credential AES key client-side. */
@Entity
@Table(name = "passkey_credentials")
public class PasskeyCredential {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @Column(nullable = false) private UUID itemId;
    @Column(nullable = false, length = 255) private String ownerEmail;
    @Column(nullable = false, length = 253) private String relyingPartyId;
    @Column(nullable = false, length = 1024, unique = true) private String credentialId;
    @Column(nullable = false, length = 1024) private String userHandle;
    @Column(nullable = false, length = 32) private String algorithm;
    @Column(nullable = false, length = 4096) private String publicKey;
    @Column(nullable = false, length = 16384) private String encryptedPrivateMaterial;
    @Column(nullable = false, length = 255) private String privateMaterialIv;
    @Column(length = 1024) private String transports;
    @Column(nullable = false) private long signCounter;
    @Column(nullable = false) private Instant createdAt;
    @Column(nullable = false) private Instant updatedAt;
    protected PasskeyCredential() { }
    public PasskeyCredential(UUID itemId, String ownerEmail, String relyingPartyId, String credentialId,
                             String userHandle, String algorithm, String publicKey,
                             String encryptedPrivateMaterial, String privateMaterialIv, String transports) {
        this.itemId = itemId; this.ownerEmail = ownerEmail; this.relyingPartyId = relyingPartyId;
        this.credentialId = credentialId; this.userHandle = userHandle; this.algorithm = algorithm;
        this.publicKey = publicKey; this.encryptedPrivateMaterial = encryptedPrivateMaterial;
        this.privateMaterialIv = privateMaterialIv; this.transports = transports; this.signCounter = 0;
    }
    @PrePersist void onCreate() { createdAt = Instant.now(); updatedAt = createdAt; }
    @PreUpdate void onUpdate() { updatedAt = Instant.now(); }
    public UUID getId() { return id; } public UUID getItemId() { return itemId; }
    public String getOwnerEmail() { return ownerEmail; } public String getRelyingPartyId() { return relyingPartyId; }
    public String getCredentialId() { return credentialId; } public String getUserHandle() { return userHandle; }
    public String getAlgorithm() { return algorithm; } public String getPublicKey() { return publicKey; }
    public String getEncryptedPrivateMaterial() { return encryptedPrivateMaterial; }
    public String getPrivateMaterialIv() { return privateMaterialIv; } public String getTransports() { return transports; }
    public long getSignCounter() { return signCounter; }
    /** Recovery transfer changes only record ownership; encrypted credential
     * bytes remain untouched and their AES key is rewrapped separately. */
    public void setOwnerEmail(String ownerEmail) { this.ownerEmail = ownerEmail; }
}
