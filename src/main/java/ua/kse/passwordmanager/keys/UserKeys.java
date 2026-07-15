package ua.kse.passwordmanager.keys;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Per-user asymmetric keypair for E2E sharing. The keypair is generated in
 * the browser: the public key (SPKI, base64) is stored as-is; the private key
 * (PKCS8) is encrypted client-side with an AES-GCM key derived from the vault
 * passphrase ({@link #kdfAlgorithm} + kdfSalt) before upload — the server can
 * never use it.
 */
@Entity
@Table(name = "user_keys")
public class UserKeys {

    @Id
    private String email;

    @Column(nullable = false, length = 2048)
    private String publicKey;

    @Column(nullable = false, length = 8192)
    private String encryptedPrivateKey;

    @Column(nullable = false)
    private String privateKeyIv;

    @Column(nullable = false)
    private String kdfSalt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private KdfAlgorithm kdfAlgorithm;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    protected UserKeys() {
    }

    public UserKeys(String email) {
        this.email = email;
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

    public String getEmail() {
        return email;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getEncryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public void setEncryptedPrivateKey(String encryptedPrivateKey) {
        this.encryptedPrivateKey = encryptedPrivateKey;
    }

    public String getPrivateKeyIv() {
        return privateKeyIv;
    }

    public void setPrivateKeyIv(String privateKeyIv) {
        this.privateKeyIv = privateKeyIv;
    }

    public String getKdfSalt() {
        return kdfSalt;
    }

    public void setKdfSalt(String kdfSalt) {
        this.kdfSalt = kdfSalt;
    }

    public KdfAlgorithm getKdfAlgorithm() {
        return kdfAlgorithm;
    }

    public void setKdfAlgorithm(KdfAlgorithm kdfAlgorithm) {
        this.kdfAlgorithm = kdfAlgorithm;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
