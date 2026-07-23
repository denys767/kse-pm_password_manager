package ua.kse.passwordmanager.attachment;

import java.util.UUID;

/** Never contains the Drive path: callers only receive opaque attachment metadata. */
public record AttachmentMetadataResponse(UUID id, String encryptedFilename, String encryptedFilenameIv,
        String mimeType, long ciphertextSize, String ciphertextSha256, String nonce,
        String wrappedFileKey, String wrappedFileKeyIv) {
    static AttachmentMetadataResponse from(ItemAttachment attachment) {
        return new AttachmentMetadataResponse(attachment.getId(), attachment.getEncryptedFilename(),
                attachment.getEncryptedFilenameIv(), attachment.getMimeType(), attachment.getCiphertextSize(),
                attachment.getCiphertextSha256(), attachment.getNonce(), attachment.getWrappedFileKey(),
                attachment.getWrappedFileKeyIv());
    }
}
