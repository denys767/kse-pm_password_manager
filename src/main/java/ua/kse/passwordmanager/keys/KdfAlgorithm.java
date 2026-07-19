package ua.kse.passwordmanager.keys;

/**
 * Passphrase-to-KEK derivation algorithm used to encrypt the private key.
 * ARGON2ID (memory-hard, OWASP-recommended) is used for every new keypair;
 * PBKDF2 is kept only so keypairs registered before this algorithm existed
 * keep unlocking — there is no forced migration, since re-deriving requires
 * the user's passphrase, which the server never has.
 */
public enum KdfAlgorithm {
    PBKDF2,
    ARGON2ID
}
