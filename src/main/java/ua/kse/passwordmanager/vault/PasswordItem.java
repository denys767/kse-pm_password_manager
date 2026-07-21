package ua.kse.passwordmanager.vault;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * A vault record. The password (and notes) are encrypted on the client with
 * AES-GCM before they reach the server — the server only ever stores the
 * ciphertext and IV, never the plaintext secret.
 */
@Entity
@Table(name = "password_items")
public class PasswordItem {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

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

    @Column(length = 1024)
    private String tags;

    @Column(nullable = false)
    private String ownerEmail;

    /** Non-secret template discriminator; secrets are in encrypted payload. */
    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false)
    private SecretType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ItemType itemType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SyncMode syncMode;

    /** Collection this item belongs to (nullable). The item key is additionally
     * wrapped AES-GCM with the collection key so every member can unwrap it. */
    @Column(name = "collection_id")
    private UUID collectionId;

    @Column(length = 4096)
    private String collectionWrappedKey;

    private String collectionWrappedKeyIv;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEncryptedPassword() {
        return encryptedPassword;
    }

    public void setEncryptedPassword(String encryptedPassword) {
        this.encryptedPassword = encryptedPassword;
    }

    public String getPasswordIv() {
        return passwordIv;
    }

    public void setPasswordIv(String passwordIv) {
        this.passwordIv = passwordIv;
    }

    public String getEncryptedNotes() {
        return encryptedNotes;
    }

    public void setEncryptedNotes(String encryptedNotes) {
        this.encryptedNotes = encryptedNotes;
    }

    public String getNotesIv() {
        return notesIv;
    }

    public void setNotesIv(String notesIv) {
        this.notesIv = notesIv;
    }

    public String getTags() {
        return tags;
    }

    public void setTags(String tags) {
        this.tags = tags;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public SecretType getType() {
        return type;
    }

    public void setType(SecretType type) {
        this.type = type;
    }

    public ItemType getItemType() {
        return itemType;
    }

    public void setItemType(ItemType itemType) {
        this.itemType = itemType;
    }

    public SyncMode getSyncMode() {
        return syncMode;
    }

    public void setSyncMode(SyncMode syncMode) {
        this.syncMode = syncMode;
    }

    public UUID getCollectionId() {
        return collectionId;
    }

    public void setCollectionId(UUID collectionId) {
        this.collectionId = collectionId;
    }

    public String getCollectionWrappedKey() {
        return collectionWrappedKey;
    }

    public void setCollectionWrappedKey(String collectionWrappedKey) {
        this.collectionWrappedKey = collectionWrappedKey;
    }

    public String getCollectionWrappedKeyIv() {
        return collectionWrappedKeyIv;
    }

    public void setCollectionWrappedKeyIv(String collectionWrappedKeyIv) {
        this.collectionWrappedKeyIv = collectionWrappedKeyIv;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }
}
