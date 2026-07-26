package ua.kse.passwordmanager.externalsharing;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import ua.kse.passwordmanager.vault.PasswordItem;

/** An opaque package for a recipient outside the vault permission model. */
@Entity
@Table(name = "external_shares")
public class ExternalShare {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "item_id", nullable = false)
    private PasswordItem item;

    @Column(nullable = false)
    private String ownerEmail;

    // Unbounded: the ciphertext is as long as the record is, and a width here
    // only ever expressed how big a varchar someone once guessed would do.
    // ExternalShareDtos.MAX_ENCRYPTED_PACKAGE_CHARS rejects absurd payloads at
    // the edge instead. See V23__external_share_package_text.sql.
    @Column(nullable = false, columnDefinition = "text")
    private String encryptedPackage;

    @Column(nullable = false)
    private String packageIv;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false)
    private boolean oneTime;

    @Column(nullable = false)
    private boolean expiredAudited;

    @Column(nullable = false)
    private Instant createdAt;

    protected ExternalShare() { }

    public ExternalShare(PasswordItem item, String ownerEmail, String encryptedPackage,
                         String packageIv, Instant expiresAt, boolean oneTime) {
        this.item = item;
        this.ownerEmail = ownerEmail;
        this.encryptedPackage = encryptedPackage;
        this.packageIv = packageIv;
        this.expiresAt = expiresAt;
        this.oneTime = oneTime;
    }

    @PrePersist
    void onCreate() { createdAt = Instant.now(); }

    public UUID getId() { return id; }
    public PasswordItem getItem() { return item; }
    public String getOwnerEmail() { return ownerEmail; }
    public String getEncryptedPackage() { return encryptedPackage; }
    public String getPackageIv() { return packageIv; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public boolean isOneTime() { return oneTime; }
    public boolean isExpiredAudited() { return expiredAudited; }
    public void setExpiredAudited(boolean expiredAudited) { this.expiredAudited = expiredAudited; }
}
