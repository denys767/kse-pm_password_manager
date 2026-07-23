package ua.kse.passwordmanager.attachment;

import ua.kse.passwordmanager.common.BadGatewayException;

/** Fail closed until the service account and Drive API are configured. */
final class UnavailableDriveAttachmentStore implements DriveAttachmentStore {
    private static final String MESSAGE = "Google Drive attachments are unavailable: configure domain-wide delegation and the Drive API";
    @Override public String upload(String ownerEmail, byte[] ciphertext, long expectedSize, String hash) { throw new BadGatewayException(MESSAGE, null); }
    @Override public byte[] download(String ownerEmail, String driveFileId) { throw new BadGatewayException(MESSAGE, null); }
    @Override public void delete(String ownerEmail, String driveFileId) { throw new BadGatewayException(MESSAGE, null); }
}
