package ua.kse.passwordmanager.recovery;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/** Development/test provider. It intentionally has process-local key material
 * and must never be selected in production. */
@Component
@ConditionalOnProperty(name = "pm.recovery.provider", havingValue = "local", matchIfMissing = true)
public class LocalRecoveryKeyProvider implements RecoveryKeyProvider {
    private final KeyPair pair;
    private final String version;
    public LocalRecoveryKeyProvider(@Value("${pm.recovery.active-key-version:local-dev-v1}") String version) {
        this.version = version;
        try { KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); pair = generator.generateKeyPair(); }
        catch (GeneralSecurityException e) { throw new IllegalStateException("Cannot initialize development recovery key", e); }
    }
    @Override public String activeKeyVersion() { return version; }
    @Override public String publicKeyPem() {
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----\n";
    }
    @Override public byte[] decrypt(String keyVersion, byte[] ciphertext) {
        if (!version.equals(keyVersion)) throw new IllegalArgumentException("Unknown local recovery key version");
        try { return cipher(Cipher.DECRYPT_MODE, pair.getPrivate()).doFinal(ciphertext); }
        catch (GeneralSecurityException e) { throw new IllegalArgumentException("Recovery envelope cannot be decrypted", e); }
    }
    static Cipher cipher(int mode, Key key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(mode, key, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        return cipher;
    }
}
