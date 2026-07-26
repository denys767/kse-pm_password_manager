package ua.kse.passwordmanager.attachment;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.UUID;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.HexFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.sharing.AccessRole;
import ua.kse.passwordmanager.sharing.SharingService;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;

@Service
public class AttachmentService {
    private final ItemAttachmentRepository attachments;
    private final PasswordItemRepository items;
    private final SharingService sharing;
    private final DriveAttachmentStore drive;
    private final AuditService audit;
    private final ObjectMapper json;
    /** Programmatic, not @Transactional: the Drive transfer between the read
     * and write halves of upload()/download() can run for minutes on a large
     * attachment, and holding a pooled DB connection for that long is the
     * failure mode to avoid. TransactionTemplate also sidesteps the
     * self-invocation trap @Transactional has elsewhere in this codebase —
     * these are plain method calls, not proxied ones, so there is nothing to
     * bypass. */
    private final TransactionTemplate readOnlyTx;
    private final TransactionTemplate writeTx;

    public AttachmentService(ItemAttachmentRepository attachments, PasswordItemRepository items,
            SharingService sharing, DriveAttachmentStore drive, AuditService audit, ObjectMapper json,
            PlatformTransactionManager transactionManager) {
        this.attachments = attachments; this.items = items; this.sharing = sharing; this.drive = drive; this.audit = audit; this.json = json;
        this.readOnlyTx = new TransactionTemplate(transactionManager);
        this.readOnlyTx.setReadOnly(true);
        this.writeTx = new TransactionTemplate(transactionManager);
    }

    private record PreparedUpload(String ownerEmail, String oldDriveFile) { }

    /** Metadata travels in a base64 header beside the opaque binary body so a
     * replacement is one transactional client operation, not a staged record.
     * The Drive transfer itself runs outside any transaction. */
    public AttachmentMetadataResponse upload(CurrentUser user, UUID itemId, String encodedMetadata, InputStream ciphertext) {
        AttachmentMetadataRequest request = decode(encodedMetadata);
        PreparedUpload prepared = readOnlyTx.execute(status -> {
            PasswordItem item = ownerItem(user, itemId);
            ItemAttachment prior = attachments.findByItemId(itemId).orElse(null);
            return new PreparedUpload(item.getOwnerEmail(), prior == null ? null : prior.getDriveFileId());
        });
        String newDriveFile = drive.upload(prepared.ownerEmail(), ciphertext, request.ciphertextSize(), request.ciphertextSha256());
        AttachmentMetadataResponse response = writeTx.execute(status -> {
            PasswordItem item = ownerItem(user, itemId);
            ItemAttachment prior = attachments.findByItemId(itemId).orElse(null);
            ItemAttachment attachment;
            if (prior == null) attachment = attachments.save(new ItemAttachment(item, newDriveFile, request));
            else { prior.apply(newDriveFile, request); attachment = attachments.save(prior); }
            audit.record(user.email(), AuditAction.ATTACHMENT_UPLOADED, itemId, item.getName(), attachment.getId().toString(),
                    "ciphertextSize=" + request.ciphertextSize());
            return AttachmentMetadataResponse.from(attachment);
        });
        // Keep the old ciphertext readable until its replacement has safely
        // completed in Drive and PostgreSQL.
        if (prepared.oldDriveFile() != null && !prepared.oldDriveFile().equals(newDriveFile)) {
            drive.delete(prepared.ownerEmail(), prepared.oldDriveFile());
        }
        return response;
    }

    public AttachmentMetadataResponse metadata(CurrentUser user, UUID itemId, boolean extensionClient) {
        return readOnlyTx.execute(status -> {
            readableItem(user, itemId, extensionClient);
            return AttachmentMetadataResponse.from(required(itemId));
        });
    }

    private record PreparedDownload(String ownerEmail, String driveFileId, String itemName, String attachmentId) { }

    /** Streams straight to {@code out}; the Drive transfer runs outside any
     * transaction, same reasoning as {@link #upload}. */
    public void download(CurrentUser user, UUID itemId, OutputStream out, boolean extensionClient) {
        PreparedDownload prepared = readOnlyTx.execute(status -> {
            PasswordItem item = readableItem(user, itemId, extensionClient);
            ItemAttachment attachment = required(itemId);
            return new PreparedDownload(item.getOwnerEmail(), attachment.getDriveFileId(), item.getName(), attachment.getId().toString());
        });
        drive.download(prepared.ownerEmail(), prepared.driveFileId(), out);
        writeTx.executeWithoutResult(status ->
                audit.record(user.email(), AuditAction.ATTACHMENT_DOWNLOADED, itemId, prepared.itemName(), prepared.attachmentId(), null));
    }

    /** Drive deletion happens before the DB row is removed, same invariant as
     * {@link #deleteForItem}: a Drive failure must not leave an untracked
     * opaque file with no record pointing at it. */
    public void delete(CurrentUser user, UUID itemId) {
        record Prepared(String ownerEmail, String driveFileId) { }
        Prepared prepared = readOnlyTx.execute(status -> {
            PasswordItem item = ownerItem(user, itemId);
            ItemAttachment attachment = required(itemId);
            return new Prepared(item.getOwnerEmail(), attachment.getDriveFileId());
        });
        drive.delete(prepared.ownerEmail(), prepared.driveFileId());
        writeTx.executeWithoutResult(status -> {
            PasswordItem item = ownerItem(user, itemId);
            ItemAttachment attachment = required(itemId);
            attachments.delete(attachment);
            audit.record(user.email(), AuditAction.ATTACHMENT_DELETED, itemId, item.getName(), attachment.getId().toString(), null);
        });
    }

    /** Called as part of item deletion; Drive failure prevents deleting the DB
     * record, avoiding an untracked opaque file. Kept as one transaction: item
     * deletion already holds its own, and unlike upload/download this is not
     * a large-payload transfer, only a delete call. */
    public void deleteForItem(PasswordItem item) {
        writeTx.executeWithoutResult(status -> attachments.findByItemId(item.getId()).ifPresent(attachment -> {
            drive.delete(item.getOwnerEmail(), attachment.getDriveFileId());
            attachments.delete(attachment);
        }));
    }

    /** Copy encrypted bytes between per-user appDataFolder stores before an
     * ownership change, via a temp file rather than a heap-resident byte[] —
     * the file is opaque, so no secret is exposed by spilling it to disk. */
    public void transferOwner(PasswordItem item, String oldOwner, String successor) {
        ItemAttachment attachment = attachments.findByItemId(item.getId()).orElse(null);
        if (attachment == null) return;
        Path temp;
        try { temp = Files.createTempFile("pm-attachment-transfer-", ".bin"); }
        catch (IOException e) { throw new IllegalStateException("Could not stage attachment for transfer", e); }
        try {
            MessageDigest digest = sha256Digest();
            try (OutputStream out = Files.newOutputStream(temp)) {
                drive.download(oldOwner, attachment.getDriveFileId(), out);
            }
            long size;
            try (DigestInputStream verify = new DigestInputStream(Files.newInputStream(temp), digest)) {
                size = verify.transferTo(OutputStream.nullOutputStream());
            }
            String actualSha256 = HexFormat.of().formatHex(digest.digest());
            if (size != attachment.getCiphertextSize() || !actualSha256.equalsIgnoreCase(attachment.getCiphertextSha256())) {
                throw new IllegalStateException("Cannot transfer attachment: ciphertext integrity check failed");
            }
            String replacement;
            try (InputStream in = Files.newInputStream(temp)) {
                replacement = drive.upload(successor, in, attachment.getCiphertextSize(), attachment.getCiphertextSha256());
            }
            String oldFile = attachment.getDriveFileId();
            writeTx.executeWithoutResult(status -> {
                attachment.setDriveFileId(replacement);
                attachments.save(attachment);
            });
            drive.delete(oldOwner, oldFile);
        } catch (IOException e) {
            throw new IllegalStateException("Attachment transfer failed", e);
        } finally {
            try { Files.deleteIfExists(temp); } catch (IOException ignored) { /* best effort cleanup */ }
        }
    }

    private static MessageDigest sha256Digest() {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException("SHA-256 unavailable", e); }
    }

    private PasswordItem ownerItem(CurrentUser user, UUID itemId) {
        PasswordItem item = items.findById(itemId).orElseThrow(() -> new NotFoundException("Item not found"));
        if (!item.getOwnerEmail().equalsIgnoreCase(user.email())) throw new ForbiddenException("Only the owner can manage attachments");
        return item;
    }
    private PasswordItem readableItem(CurrentUser user, UUID itemId, boolean extensionClient) {
        PasswordItem item = items.findById(itemId).orElseThrow(() -> new NotFoundException("Item not found"));
        AccessRole role = sharing.resolveAccess(item, user);
        if (!role.mayReceivePasswordMaterial(extensionClient)) throw new NotFoundException("Attachment not found");
        return item;
    }
    private ItemAttachment required(UUID itemId) { return attachments.findByItemId(itemId).orElseThrow(() -> new NotFoundException("Attachment not found")); }
    private AttachmentMetadataRequest decode(String encoded) {
        try {
            String decoded = new String(Base64.getUrlDecoder().decode(encoded), java.nio.charset.StandardCharsets.UTF_8);
            return json.readValue(decoded, AttachmentMetadataRequest.class);
        } catch (Exception e) { throw new IllegalArgumentException("Invalid encrypted attachment metadata", e); }
    }
}
