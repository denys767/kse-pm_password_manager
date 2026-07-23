package ua.kse.passwordmanager.vault;

/** Summary intentionally contains no secret fields or ciphertext. */
public record VaultImportPreview(int createCount, int updateCount, int deleteCount) {
}
