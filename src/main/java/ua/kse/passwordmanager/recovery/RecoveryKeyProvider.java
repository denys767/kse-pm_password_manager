package ua.kse.passwordmanager.recovery;

/** Thin boundary around KMS. Implementations return key bytes only to the
 * recovery service, never through an HTTP response or log statement. */
public interface RecoveryKeyProvider {
    String activeKeyVersion();
    String publicKeyPem();
    byte[] decrypt(String keyVersion, byte[] ciphertext);
}
