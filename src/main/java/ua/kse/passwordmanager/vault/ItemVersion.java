package ua.kse.passwordmanager.vault;

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

/**
 * Snapshot of an item taken before each update. Ciphertext only — versions
 * are encrypted with the same item key as the live record, so anyone holding
 * the wrapped key can decrypt their history, and the server still can't.
 */
@Entity
@Table(name = "password_item_versions")
public class ItemVersion {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private PasswordItem item;

    @Column(nullable = false)
    private String name;

    @Column(length = 2048)
    private String url;

    private String username;

    @Column(nullable = false, length = 4096)
    private String encryptedPassword;

    @Column(nullable = false)
    private String passwordIv;

    @Column(length = 16384)
    private String encryptedNotes;

    private String notesIv;

    @Column(nullable = false)
    private String replacedBy;

    @Column(nullable = false)
    private Instant replacedAt;

    protected ItemVersion() {
    }

    public ItemVersion(PasswordItem item, String replacedBy) {
        this.item = item;
        this.name = item.getName();
        this.url = item.getUrl();
        this.username = item.getUsername();
        this.encryptedPassword = item.getEncryptedPassword();
        this.passwordIv = item.getPasswordIv();
        this.encryptedNotes = item.getEncryptedNotes();
        this.notesIv = item.getNotesIv();
        this.replacedBy = replacedBy;
        this.replacedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public PasswordItem getItem() {
        return item;
    }

    public String getName() {
        return name;
    }

    public String getUrl() {
        return url;
    }

    public String getUsername() {
        return username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public String getPasswordIv() {
        return passwordIv;
    }

    public String getEncryptedNotes() {
        return encryptedNotes;
    }

    public String getNotesIv() {
        return notesIv;
    }

    public String getReplacedBy() {
        return replacedBy;
    }

    public Instant getReplacedAt() {
        return replacedAt;
    }
}
