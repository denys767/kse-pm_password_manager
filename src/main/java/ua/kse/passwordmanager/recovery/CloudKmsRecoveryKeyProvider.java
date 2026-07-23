package ua.kse.passwordmanager.recovery;

import com.google.cloud.kms.v1.AsymmetricDecryptRequest;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32C;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Google asymmetric KMS implementation. The configured resource must be an
 * RSA_DECRYPT_OAEP_2048_SHA256 CryptoKeyVersion with decrypt IAM granted only
 * to the service identity. */
@Component
@ConditionalOnProperty(name = "pm.recovery.provider", havingValue = "cloud")
public class CloudKmsRecoveryKeyProvider implements RecoveryKeyProvider, AutoCloseable {
    private final KeyManagementServiceClient kms;
    private final String version;
    public CloudKmsRecoveryKeyProvider(@Value("${pm.recovery.active-key-version:}") String version) {
        if (version == null || version.isBlank()) throw new IllegalStateException("PM_KMS_ACTIVE_KEY_VERSION is required for Cloud KMS recovery");
        this.version = version;
        try { kms = KeyManagementServiceClient.create(); }
        catch (Exception e) { throw new IllegalStateException("Cannot initialize Google Cloud KMS", e); }
    }
    @Override public String activeKeyVersion() { return version; }
    @Override public String publicKeyPem() {
        var response = kms.getPublicKey(version);
        byte[] pem = response.getPem().getBytes(StandardCharsets.US_ASCII);
        if (crc32c(pem) != response.getPemCrc32C().getValue()) throw new IllegalStateException("Cloud KMS public-key CRC32C verification failed");
        return response.getPem();
    }
    @Override public byte[] decrypt(String keyVersion, byte[] ciphertext) {
        if (!version.equals(keyVersion)) throw new IllegalArgumentException("Recovery envelope references a non-active KMS version");
        long checksum = crc32c(ciphertext);
        var response = kms.asymmetricDecrypt(AsymmetricDecryptRequest.newBuilder().setName(keyVersion)
                .setCiphertext(ByteString.copyFrom(ciphertext)).setCiphertextCrc32C(com.google.protobuf.Int64Value.of(checksum)).build());
        byte[] plaintext = response.getPlaintext().toByteArray();
        if (!response.getVerifiedCiphertextCrc32C() || crc32c(plaintext) != response.getPlaintextCrc32C().getValue()) {
            throw new IllegalStateException("Cloud KMS CRC32C verification failed");
        }
        return plaintext;
    }
    private static long crc32c(byte[] value) { CRC32C crc = new CRC32C(); crc.update(value, 0, value.length); return crc.getValue(); }
    @Override public void close() { kms.close(); }
}
