package ua.kse.passwordmanager.attachment;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import ua.kse.passwordmanager.vault.PasswordItem;

@Entity
@Table(name = "item_attachments")
public class ItemAttachment {
    @Id private UUID id = UUID.randomUUID();
    @OneToOne(fetch = FetchType.LAZY) @JoinColumn(name = "item_id", nullable = false, unique = true)
    private PasswordItem item;
    @Column(name = "drive_file_id", nullable = false) private String driveFileId;
    @Column(name = "encrypted_filename", nullable = false, length = 4096) private String encryptedFilename;
    @Column(name = "encrypted_filename_iv", nullable = false) private String encryptedFilenameIv;
    @Column(name = "mime_type", nullable = false) private String mimeType;
    @Column(name = "ciphertext_size", nullable = false) private long ciphertextSize;
    @Column(name = "ciphertext_sha256", nullable = false) private String ciphertextSha256;
    @Column(nullable = false) private String nonce;
    @Column(name = "wrapped_file_key", nullable = false, length = 4096) private String wrappedFileKey;
    @Column(name = "wrapped_file_key_iv", nullable = false) private String wrappedFileKeyIv;
    @Column(name = "created_at", nullable = false) private Instant createdAt;
    @Column(name = "updated_at", nullable = false) private Instant updatedAt;

    protected ItemAttachment() { }
    ItemAttachment(PasswordItem item, String driveFileId, AttachmentMetadataRequest request) {
        this.item = item; this.driveFileId = driveFileId; apply(request);
    }
    void apply(String newDriveFileId, AttachmentMetadataRequest request) { this.driveFileId = newDriveFileId; apply(request); }
    private void apply(AttachmentMetadataRequest request) {
        encryptedFilename = request.encryptedFilename(); encryptedFilenameIv = request.encryptedFilenameIv();
        mimeType = request.mimeType(); ciphertextSize = request.ciphertextSize();
        ciphertextSha256 = request.ciphertextSha256().toLowerCase(); nonce = request.nonce();
        wrappedFileKey = request.wrappedFileKey(); wrappedFileKeyIv = request.wrappedFileKeyIv();
    }
    @PrePersist void created() { createdAt = Instant.now(); updatedAt = createdAt; }
    @PreUpdate void updated() { updatedAt = Instant.now(); }
    public UUID getId() { return id; } public PasswordItem getItem() { return item; }
    public String getDriveFileId() { return driveFileId; } public String getEncryptedFilename() { return encryptedFilename; }
    public String getEncryptedFilenameIv() { return encryptedFilenameIv; } public String getMimeType() { return mimeType; }
    public long getCiphertextSize() { return ciphertextSize; } public String getCiphertextSha256() { return ciphertextSha256; }
    public String getNonce() { return nonce; } public String getWrappedFileKey() { return wrappedFileKey; }
    public String getWrappedFileKeyIv() { return wrappedFileKeyIv; }
    /** Used only by the audited recovery transfer after the opaque blob was
     * copied and hash-verified in the successor's appDataFolder. */
    public void setDriveFileId(String driveFileId) { this.driveFileId = driveFileId; }
}
