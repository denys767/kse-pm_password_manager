package ua.kse.passwordmanager.vault;

/**
 * The template of a vault item.  This is intentionally only a non-secret
 * discriminator: all template-specific values remain in the client-encrypted
 * payload and are opaque to the server.
 */
public enum SecretType {
    LOGIN,
    API_CREDENTIALS,
    SSH_KEY,
    CARD,
    SECURE_NOTE
}
