package ua.kse.passwordmanager.attachment;

/** Server-side Drive transport; all content is already encrypted by the browser. */
public interface DriveAttachmentStore {
    String upload(String ownerEmail, byte[] ciphertext, long expectedSize, String ciphertextSha256);
    byte[] download(String ownerEmail, String driveFileId);
    void delete(String ownerEmail, String driveFileId);
}
