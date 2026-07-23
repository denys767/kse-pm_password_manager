package ua.kse.passwordmanager.attachment;

import java.util.Base64;
import java.util.UUID;
import java.security.MessageDigest;
import java.util.HexFormat;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
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

    public AttachmentService(ItemAttachmentRepository attachments, PasswordItemRepository items,
            SharingService sharing, DriveAttachmentStore drive, AuditService audit, ObjectMapper json) {
        this.attachments = attachments; this.items = items; this.sharing = sharing; this.drive = drive; this.audit = audit; this.json = json;
    }

    /** Metadata travels in a base64 header beside the opaque binary body so a
     * replacement is one transactional client operation, not a staged record. */
    @Transactional
    public AttachmentMetadataResponse upload(CurrentUser user, UUID itemId, String encodedMetadata, byte[] ciphertext) {
        PasswordItem item = ownerItem(user, itemId);
        AttachmentMetadataRequest request = decode(encodedMetadata);
        String newDriveFile = drive.upload(item.getOwnerEmail(), ciphertext, request.ciphertextSize(), request.ciphertextSha256());
        ItemAttachment prior = attachments.findByItemId(itemId).orElse(null);
        String oldDriveFile = prior == null ? null : prior.getDriveFileId();
        ItemAttachment attachment;
        if (prior == null) attachment = attachments.save(new ItemAttachment(item, newDriveFile, request));
        else { prior.apply(newDriveFile, request); attachment = attachments.save(prior); }
        // Keep the old ciphertext readable until its replacement has safely
        // completed in Drive and PostgreSQL.
        if (oldDriveFile != null && !oldDriveFile.equals(newDriveFile)) drive.delete(item.getOwnerEmail(), oldDriveFile);
        audit.record(user.email(), AuditAction.ATTACHMENT_UPLOADED, itemId, item.getName(), attachment.getId().toString(),
                "ciphertextSize=" + request.ciphertextSize());
        return AttachmentMetadataResponse.from(attachment);
    }

    @Transactional(readOnly = true)
    public AttachmentMetadataResponse metadata(CurrentUser user, UUID itemId, boolean extensionClient) {
        readableItem(user, itemId, extensionClient);
        return AttachmentMetadataResponse.from(required(itemId));
    }

    @Transactional(readOnly = true)
    public byte[] download(CurrentUser user, UUID itemId, boolean extensionClient) {
        PasswordItem item = readableItem(user, itemId, extensionClient);
        ItemAttachment attachment = required(itemId);
        byte[] ciphertext = drive.download(item.getOwnerEmail(), attachment.getDriveFileId());
        audit.record(user.email(), AuditAction.ATTACHMENT_DOWNLOADED, itemId, item.getName(), attachment.getId().toString(), null);
        return ciphertext;
    }

    @Transactional
    public void delete(CurrentUser user, UUID itemId) {
        PasswordItem item = ownerItem(user, itemId);
        ItemAttachment attachment = required(itemId);
        drive.delete(item.getOwnerEmail(), attachment.getDriveFileId());
        attachments.delete(attachment);
        audit.record(user.email(), AuditAction.ATTACHMENT_DELETED, itemId, item.getName(), attachment.getId().toString(), null);
    }

    /** Called as part of item deletion; Drive failure prevents deleting the DB
     * record, avoiding an untracked opaque file. */
    @Transactional
    public void deleteForItem(PasswordItem item) {
        attachments.findByItemId(item.getId()).ifPresent(attachment -> {
            drive.delete(item.getOwnerEmail(), attachment.getDriveFileId());
            attachments.delete(attachment);
        });
    }

    /** Copy encrypted bytes between per-user appDataFolder stores before an
     * ownership change. The file is opaque, so no secret is exposed here. */
    @Transactional
    public void transferOwner(PasswordItem item, String oldOwner, String successor) {
        attachments.findByItemId(item.getId()).ifPresent(attachment -> {
            byte[] bytes = drive.download(oldOwner, attachment.getDriveFileId());
            if (bytes.length != attachment.getCiphertextSize() || !sha256(bytes).equalsIgnoreCase(attachment.getCiphertextSha256())) {
                throw new IllegalStateException("Cannot transfer attachment: ciphertext integrity check failed");
            }
            String replacement = drive.upload(successor, bytes, attachment.getCiphertextSize(), attachment.getCiphertextSha256());
            String oldFile = attachment.getDriveFileId();
            attachment.setDriveFileId(replacement);
            attachments.save(attachment);
            drive.delete(oldOwner, oldFile);
        });
    }

    private static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 unavailable", e); }
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
