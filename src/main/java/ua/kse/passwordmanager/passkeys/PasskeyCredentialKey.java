package ua.kse.passwordmanager.passkeys;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** Credential AES key encrypted to one vault public key. */
@Entity
@Table(name = "passkey_credential_keys")
public class PasskeyCredentialKey {
    @Id @GeneratedValue(strategy = GenerationType.UUID) private UUID id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "credential_id")
    private PasskeyCredential credential;
    @Column(nullable = false, length = 255) private String userEmail;
    @Column(nullable = false, length = 4096) private String wrappedKey;
    @Column(nullable = false) private Instant createdAt;
    protected PasskeyCredentialKey() { }
    public PasskeyCredentialKey(PasskeyCredential credential, String userEmail, String wrappedKey) {
        this.credential = credential; this.userEmail = userEmail; this.wrappedKey = wrappedKey; this.createdAt = Instant.now();
    }
    public UUID getId() { return id; } public PasskeyCredential getCredential() { return credential; }
    public String getUserEmail() { return userEmail; } public String getWrappedKey() { return wrappedKey; }
    public void setWrappedKey(String wrappedKey) { this.wrappedKey = wrappedKey; }
}
