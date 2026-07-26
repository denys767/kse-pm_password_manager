package ua.kse.passwordmanager.attachment;

import java.io.InputStream;
import java.io.OutputStream;

/** Server-side Drive transport; all content is already encrypted by the browser.
 * Streamed both ways so a large attachment costs bounded heap, not one full
 * copy per concurrent request. */
public interface DriveAttachmentStore {
    String upload(String ownerEmail, InputStream ciphertext, long expectedSize, String ciphertextSha256);
    void download(String ownerEmail, String driveFileId, OutputStream out);
    void delete(String ownerEmail, String driveFileId);
}
